#!/usr/bin/env python3
"""Build and verify the playground golden AMI ("ubuntu2004-labs" profile).

  build   launch a temporary builder from the frozen Ubuntu 20.04 base AMI, bake the
          labs onto it (guest/bake.sh, over SSM), snapshot it into an AMI, tag it,
          optionally publish the AMI id to SSM Parameter Store, then delete the builder.
  verify  launch a clone of an AMI, run guest/verify.sh on it (nothing is created in AWS
          other than the clone itself), then delete the clone.

Every lab file the builder installs is downloaded from GitHub at ONE pinned commit, so the
commit must be pushed. The script refuses to run if the commit is not on a remote branch or
if the lab files in the working tree differ from it.

Everything the script creates is tagged Project=sisyfix and removed again, except the AMI
(and its snapshot) from `build`.

Examples (from the repo root, with the backend venv that has boto3):
  python infra/playground-ami/build_ami.py build \\
      --instance-profile vop-vuln-lab-env3-profile \\
      --publish-param /sisyfix/dev/playground/ami/ubuntu2004-labs/latest
  python infra/playground-ami/build_ami.py verify --ami ami-0123456789abcdef0 \\
      --instance-profile vop-vuln-lab-env3-profile \\
      --state-bucket sisyfix-terraform-state-486655355038 --lock-table sisyfix-terraform-locks
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import subprocess
import sys
import time
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, WaiterError

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
GUEST = HERE / "guest"

# Same frozen Ubuntu 20.04 AMI that env1/env2/env3 use (keeps the host package baseline identical).
DEFAULT_BASE_AMI = "ami-0dba2cb6798deb6d8"
PROFILE_NAME = "ubuntu2004-labs"
BASE_TAGS = {"Project": "sisyfix", "Component": "playground-ami"}


def log(msg: str) -> None:
    print(f"[{dt.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def git(*args: str) -> str:
    r = subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout.strip()


def tag_list(extra: dict[str, str]) -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in {**BASE_TAGS, **extra}.items()]


def preflight(commit_arg: str | None) -> str:
    """Return the commit to bake. It must be pushed and match the working tree."""
    commit = git("rev-parse", commit_arg or "HEAD")
    remotes = git("branch", "-r", "--contains", commit)
    if not remotes.strip():
        raise SystemExit(f"commit {commit[:10]} is not on any remote branch. Push it first: the builder downloads lab files from GitHub at that commit.")
    dirty = git("status", "--porcelain", "--", "infra/vuln-labs", "infra/playground-ami")
    if dirty:
        raise SystemExit("uncommitted changes under infra/vuln-labs or infra/playground-ami:\n" + dirty)
    if commit != git("rev-parse", "HEAD"):
        log("note: baking a commit other than HEAD; guest scripts come from your working tree")
    log(f"commit {commit[:10]} is on remote ({remotes.splitlines()[0].strip()}), tree clean")
    return commit


class Aws:
    def __init__(self, region: str) -> None:
        self.region = region
        self.ec2 = boto3.client("ec2", region_name=region)
        self.ssm = boto3.client("ssm", region_name=region)
        self.created_instances: list[str] = []
        self.created_sgs: list[str] = []

    # ---- network ----
    def default_subnet(self) -> tuple[str, str]:
        vpcs = self.ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"]
        if not vpcs:
            raise SystemExit("no default VPC in this region; pass --subnet-id/--vpc-id (not implemented)")
        vpc = vpcs[0]["VpcId"]
        subs = self.ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc]}, {"Name": "default-for-az", "Values": ["true"]}])["Subnets"]
        subs.sort(key=lambda s: s["AvailabilityZone"])
        return vpc, subs[0]["SubnetId"]

    def make_sg(self, vpc: str, purpose: str, tags: dict[str, str]) -> str:
        name = f"playground-{purpose}-{int(time.time())}"
        sg = self.ec2.create_security_group(
            GroupName=name, Description=f"Playground {purpose}: no ingress (SSM only)", VpcId=vpc,
            TagSpecifications=[{"ResourceType": "security-group", "Tags": tag_list({**tags, "Name": name})}],
        )["GroupId"]
        self.created_sgs.append(sg)
        return sg

    # ---- instances ----
    def launch(self, ami: str, itype: str, profile: str, sg: str, subnet: str, volume_gb: int | None, tags: dict[str, str],
               kms_key_id: str | None = None) -> str:
        kw: dict = {}
        if volume_gb or kms_key_id:
            img = self.ec2.describe_images(ImageIds=[ami])["Images"][0]
            ebs: dict = {"VolumeType": "gp3", "DeleteOnTermination": True}
            ebs["VolumeSize"] = volume_gb or img["BlockDeviceMappings"][0]["Ebs"]["VolumeSize"]
            if kms_key_id:
                # Encrypted with a customer-managed key, so the AMI can be shared to another account later.
                ebs.update({"Encrypted": True, "KmsKeyId": kms_key_id})
            kw["BlockDeviceMappings"] = [{"DeviceName": img["RootDeviceName"], "Ebs": ebs}]
        exp = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        t = tag_list({**tags, "ExpiresAt": exp})
        r = self.ec2.run_instances(
            ImageId=ami, InstanceType=itype, MinCount=1, MaxCount=1,
            IamInstanceProfile={"Name": profile},
            NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": subnet, "Groups": [sg], "AssociatePublicIpAddress": True}],
            MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
            TagSpecifications=[{"ResourceType": "instance", "Tags": t}, {"ResourceType": "volume", "Tags": t}],
            **kw,
        )
        iid = r["Instances"][0]["InstanceId"]
        self.created_instances.append(iid)
        return iid

    def wait_ssm_online(self, iid: str, timeout: int = 600) -> float:
        t0 = time.time()
        self.ec2.get_waiter("instance_running").wait(InstanceIds=[iid])
        while time.time() - t0 < timeout:
            info = self.ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [iid]}])["InstanceInformationList"]
            if info and info[0].get("PingStatus") == "Online":
                return time.time() - t0
            time.sleep(5)
        raise SystemExit(f"{iid} did not become SSM Online within {timeout}s (check the instance profile and egress)")

    def run_script(self, iid: str, script: str, timeout: int) -> tuple[str, str, str]:
        b64 = base64.b64encode(script.encode()).decode()
        cid = self.ssm.send_command(
            InstanceIds=[iid], DocumentName="AWS-RunShellScript", TimeoutSeconds=max(60, timeout),
            Parameters={"commands": [f"echo {b64} | base64 -d | bash"], "executionTimeout": [str(timeout)]},
        )["Command"]["CommandId"]
        t0 = time.time()
        time.sleep(2)
        while True:
            try:
                inv = self.ssm.get_command_invocation(CommandId=cid, InstanceId=iid)
            except ClientError as e:
                if e.response["Error"]["Code"] == "InvocationDoesNotExist":
                    time.sleep(2)
                    continue
                raise
            if inv["Status"] not in ("Pending", "InProgress", "Delayed"):
                return inv["Status"], inv.get("StandardOutputContent", ""), inv.get("StandardErrorContent", "")
            if time.time() - t0 > timeout + 120:
                return "LocalTimeout", "", ""
            time.sleep(5)

    def cleanup(self) -> None:
        if self.created_instances:
            log(f"terminating {self.created_instances}")
            try:
                self.ec2.terminate_instances(InstanceIds=self.created_instances)
                self.ec2.get_waiter("instance_terminated").wait(InstanceIds=self.created_instances)
            except Exception as e:  # noqa: BLE001
                log(f"WARNING: terminate problem: {e}")
        for sg in self.created_sgs:
            for _ in range(12):
                try:
                    self.ec2.delete_security_group(GroupId=sg)
                    log(f"deleted security group {sg}")
                    break
                except ClientError as e:
                    if e.response["Error"]["Code"] in ("DependencyViolation", "InvalidGroup.InUse"):
                        time.sleep(10)
                        continue
                    log(f"WARNING: could not delete {sg}: {e}")
                    break


def cmd_build(a: argparse.Namespace) -> int:
    commit = preflight(a.commit)
    aws = Aws(a.region)
    activate_b64 = base64.b64encode((GUEST / "activate.sh").read_bytes()).decode()
    bake = (GUEST / "bake.sh").read_text(encoding="utf-8")
    script = f"export COMMIT='{commit}'\nexport ACTIVATE_B64='{activate_b64}'\nexport MIN_FREE_GB='{a.min_free_gb}'\n{bake}"
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    tags = {"Name": f"playground-ami-builder-{stamp}", "Profile": PROFILE_NAME, "GitCommit": commit}
    ami_id = None
    try:
        vpc, subnet = aws.default_subnet()
        sg = aws.make_sg(vpc, "builder", tags)
        iid = aws.launch(a.base_ami, a.instance_type, a.instance_profile, sg, subnet, a.volume_gb, tags, a.kms_key_id)
        log(f"builder {iid} launched from {a.base_ami} ({a.volume_gb} GB root)")
        log(f"builder SSM Online after {aws.wait_ssm_online(iid):.0f}s")

        log("baking (apt, tools, scanners, labs, docker builds)...")
        t0 = time.time()
        status, out, err = aws.run_script(iid, script, timeout=a.bake_timeout)
        log(f"bake finished: status={status} in {time.time() - t0:.0f}s")
        print(out[:8000])
        if err.strip():
            print("--- stderr (head) ---\n" + err[:2500])
        # Do not trust truncated SSM output: ask the instance whether the bake completed.
        s2, o2, _ = aws.run_script(iid, "grep -c 'BAKE_OK' /var/log/playground-bake.log; test -f /opt/playground/MANIFEST.json && echo MANIFEST_PRESENT", timeout=60)
        baked = s2 == "Success" and "MANIFEST_PRESENT" in o2 and o2.split()[0] != "0"
        if status != "Success" or not baked:
            if a.keep_builder:
                log(f"BAKE FAILED. Builder {iid} and its security group were left in place (--keep-builder). Delete them when done.")
            else:
                log("BAKE FAILED. Builder is being deleted. Re-run with --keep-builder to inspect it over SSM.")
            return 1

        if a.keep_builder:
            log(f"--keep-builder: leaving {iid} and its security group in place. Delete them yourself.")
            aws.created_instances.clear()
            aws.created_sgs.clear()
            return 0

        name = f"sisyfix-playground-{PROFILE_NAME}-{commit[:8]}-{stamp}"
        ami_tags = {"Name": name, "Profile": PROFILE_NAME, "GitCommit": commit, "BaseAmi": a.base_ami, "BuiltBy": "build_ami.py"}
        log(f"creating AMI {name} (instance reboots for a consistent snapshot; this takes ~15-20 min)")
        ami_id = aws.ec2.create_image(
            InstanceId=iid, Name=name, Description=f"Playground golden image, profile {PROFILE_NAME}, commit {commit[:10]}",
            NoReboot=False,
            TagSpecifications=[{"ResourceType": "image", "Tags": tag_list(ami_tags)}, {"ResourceType": "snapshot", "Tags": tag_list(ami_tags)}],
        )["ImageId"]
        log(f"AMI id {ami_id} (pending)")
        try:
            aws.ec2.get_waiter("image_available").wait(ImageIds=[ami_id], WaiterConfig={"Delay": 15, "MaxAttempts": 200})
        except WaiterError as e:
            log(f"ERROR waiting for AMI: {e}")
            return 1
        log(f"AMI {ami_id} is available")

        if a.publish_param:
            aws.ssm.put_parameter(Name=a.publish_param, Value=ami_id, Type="String", DataType="aws:ec2:image", Overwrite=True,
                                  Description=f"Latest playground AMI ({PROFILE_NAME}), commit {commit[:10]}")
            log(f"published {ami_id} to SSM parameter {a.publish_param}")
        print(f"\nAMI_ID={ami_id}")
        return 0
    finally:
        if not a.keep_builder:
            aws.cleanup()


def cmd_verify(a: argparse.Namespace) -> int:
    aws = Aws(a.region)
    script = ""
    if a.state_bucket and a.lock_table:
        script += f"export STATE_BUCKET='{a.state_bucket}'\nexport LOCK_TABLE='{a.lock_table}'\nexport REGION='{a.region}'\n"
    script += (GUEST / "verify.sh").read_text(encoding="utf-8")
    tags = {"Name": f"playground-ami-verify-{int(time.time())}", "Purpose": "verify"}
    try:
        vpc, subnet = aws.default_subnet()
        sg = aws.make_sg(vpc, "verify", tags)
        t0 = time.time()
        iid = aws.launch(a.ami, a.instance_type, a.instance_profile, sg, subnet, None, tags)
        up = aws.wait_ssm_online(iid)
        log(f"clone {iid}: SSM Online {up:.0f}s after launch (total {time.time() - t0:.0f}s)")
        status, out, err = aws.run_script(iid, script, timeout=900)
        print(out[-9000:])
        if err.strip():
            print("--- stderr (tail) ---\n" + err[-2000:])
        passed = status == "Success" and "VERIFY_RESULT fails=0" in out
        log("VERIFY " + ("PASSED" if passed else f"FAILED (ssm status {status})"))
        return 0 if passed else 1
    finally:
        aws.cleanup()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--region", default="us-east-1")
        sp.add_argument("--instance-type", default="t3.small")
        sp.add_argument("--instance-profile", required=True, help="existing IAM instance profile that grants SSM access")

    b = sub.add_parser("build", help="bake and snapshot the golden AMI")
    common(b)
    b.add_argument("--commit", help="commit to bake (default: HEAD). Must be pushed.")
    b.add_argument("--base-ami", default=DEFAULT_BASE_AMI)
    b.add_argument("--volume-gb", type=int, default=20)
    b.add_argument("--min-free-gb", type=int, default=4, help="fail the bake if less than this is free afterwards")
    b.add_argument("--bake-timeout", type=int, default=3000)
    b.add_argument("--kms-key-id", help="customer-managed KMS key to encrypt the volume/AMI (default: unencrypted, as env1-3 are today)")
    b.add_argument("--publish-param", help="SSM parameter name to store the new AMI id in")
    b.add_argument("--keep-builder", action="store_true", help="skip AMI creation and cleanup; leave the baked builder for inspection")
    b.set_defaults(fn=cmd_build)

    v = sub.add_parser("verify", help="launch a clone and run the checks")
    common(v)
    v.add_argument("--ami", required=True)
    v.add_argument("--state-bucket")
    v.add_argument("--lock-table")
    v.set_defaults(fn=cmd_verify)

    args = p.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
