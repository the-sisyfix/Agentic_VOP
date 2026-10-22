"""Shared trivy scanning + finding classification for the hardening pipeline.

ONE full-scope scan is the source of truth for the policy-zero gate; its
findings are classified by trivy's `Class` field into OS-package vs
dependency/language findings so the orchestrator can decide what to run:

  - OS findings (Class == "os-pkgs")   → copa can patch in place.
  - dep findings (Class == "lang-pkgs")→ need the rebuild leg (if a Dockerfile
                                          is available) or are residual.

The GATE is full-scope: zero fixable critical/high across BOTH classes. This is
why a dependency-only image is NOT falsely passed by a copa-only (OS) scan.

Only fixable findings count (FixedVersion present) — matching the policy-zero
definition ("zero *fixable* critical/high at certification").

WHY WE COUNT ON THE BUILD BOX
-----------------------------
A full-scope trivy JSON report is large (often 1-2 MB). We run commands on the
build box via SSM RunCommand, whose `GetCommandInvocation` response caps
`StandardOutputContent` at ~24,000 characters. `cat`-ing a 1.5 MB report back
over stdout therefore returns a TRUNCATED, mid-JSON-chopped string — which
`json.loads` cannot parse. The historical parser then returned an all-zero
classification, which silently PASSED the policy-zero gate and published an
UNSCANNED (unpatched) image as "success".

Fix: do the counting ON THE BOX with a tiny python3 program that reads the
report file directly and prints a small, bounded JSON summary (a few dozen
bytes — never truncated). This module parses that compact summary, and treats
any parse/scan failure as a HARD FAILURE (never a silent zero) so an unscanned
image can never be certified.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

# trivy Result.Class values (verified from trivy's output schema).
_CLASS_OS = "os-pkgs"
_CLASS_LANG = "lang-pkgs"

_GATE_SEVERITIES = ("CRITICAL", "HIGH")


class ScanParseError(RuntimeError):
    """A trivy report could not be classified.

    Raised instead of returning an all-zero classification so an unscanned /
    unparseable report HARD-FAILS the gate rather than silently passing it.
    An image we could not scan is an image we cannot certify.
    """


@dataclass(frozen=True)
class ScanClassification:
    """Fixable critical/high counts, split by remediation class."""

    os_critical: int = 0
    os_high: int = 0
    dep_critical: int = 0
    dep_high: int = 0
    # Detected base-OS identity (from trivy Metadata.OS). Used by the
    # orchestrator for end-of-life fail-fast. Empty for non-OS images (e.g.
    # scratch/distroless) — which is fine, EOL check simply doesn't apply.
    os_family: str = ""
    os_name: str = ""

    @property
    def os_fixable(self) -> int:
        return self.os_critical + self.os_high

    @property
    def dep_fixable(self) -> int:
        return self.dep_critical + self.dep_high

    @property
    def total_fixable(self) -> int:
        return self.os_fixable + self.dep_fixable

    @property
    def gate_passes(self) -> bool:
        """Policy-zero gate: zero fixable critical/high across ALL classes."""
        return self.total_fixable == 0

    def summary(self) -> dict:
        return {
            "os_fixable_critical": self.os_critical,
            "os_fixable_high": self.os_high,
            "dep_fixable_critical": self.dep_critical,
            "dep_fixable_high": self.dep_high,
            "total_fixable": self.total_fixable,
            "gate_passes": self.gate_passes,
        }


# A sentinel marking the start of the compact counter JSON in box stdout, so we
# can isolate it even if trivy/other tooling prints banners or warnings first.
_SUMMARY_MARKER = "__HARDEN_SCAN_SUMMARY__"


def box_count_command(report_path: str) -> str:
    """Return a shell command that counts fixable crit/high ON THE BUILD BOX.

    Reads the (large) trivy JSON report FILE directly with python3 and prints a
    tiny, bounded JSON summary prefixed with a marker line. This avoids piping a
    multi-MB report through SSM stdout (which truncates at ~24 KB and corrupts
    the JSON). The printed summary is a few dozen bytes and never truncated.

    The box emits exactly one marker line:
        __HARDEN_SCAN_SUMMARY__ {"ok": true, "os_critical": N, ...}
    or, on any failure to read/parse the report ON the box:
        __HARDEN_SCAN_SUMMARY__ {"ok": false, "error": "..."}

    Classes are mapped exactly as the historical in-process parser did:
      - Class == "os-pkgs"  → OS counts
      - Class == "lang-pkgs"→ dep counts
      - unknown/missing     → counted as dep (conservative: never drop a
                              finding from the full-scope gate)
    Only CRITICAL/HIGH with a FixedVersion are counted (fixable only).
    """
    # Single-quoted heredoc so the box shell does not expand anything in the
    # python source. report_path AND the marker are passed as argv (argv[1],
    # argv[2]) so neither needs quoting/interpolation inside the source.
    py = (
        "import json,sys\n"
        "p=sys.argv[1]\n"
        "mk=sys.argv[2]\n"
        "try:\n"
        "    d=json.load(open(p))\n"
        "except Exception as e:\n"
        "    print(mk+' '+json.dumps({'ok':False,'error':'read/parse: '+str(e)[:200]}))\n"
        "    sys.exit(0)\n"
        "oc=oh=dc=dh=0\n"
        "for r in (d.get('Results') or []):\n"
        "    cls=(r.get('Class') or '').strip()\n"
        "    is_os=cls=='os-pkgs'\n"
        "    for v in (r.get('Vulnerabilities') or []):\n"
        "        sev=(v.get('Severity') or '').upper()\n"
        "        if sev not in ('CRITICAL','HIGH'): continue\n"
        "        if not v.get('FixedVersion'): continue\n"
        "        if sev=='CRITICAL':\n"
        "            oc+=1 if is_os else 0; dc+=0 if is_os else 1\n"
        "        else:\n"
        "            oh+=1 if is_os else 0; dh+=0 if is_os else 1\n"
        # Capture the detected OS (family + version) from trivy's Metadata so the
        # orchestrator can fail fast on an END-OF-LIFE base before any patching.
        "osm=((d.get('Metadata') or {}).get('OS') or {})\n"
        "ofam=osm.get('Family') or ''\n"
        "oname=osm.get('Name') or ''\n"
        "print(mk+' '+json.dumps({'ok':True,'os_critical':oc,'os_high':oh,"
        "'dep_critical':dc,'dep_high':dh,'os_family':ofam,'os_name':oname}))\n"
    )
    return (
        f"python3 - '{report_path}' '{_SUMMARY_MARKER}' "
        f"<<'__HARDEN_PY_EOF__'\n{py}__HARDEN_PY_EOF__"
    )


def parse_box_summary(stdout: str) -> ScanClassification:
    """Parse the compact summary emitted by `box_count_command`.

    HARD-FAILS (raises ScanParseError) if the summary is missing, malformed, or
    reports ok=false — so an unscanned/unparseable report can NEVER silently
    pass the gate.
    """
    if not stdout:
        raise ScanParseError("empty scan output from build box")
    line = None
    for ln in stdout.splitlines():
        if ln.startswith(_SUMMARY_MARKER):
            line = ln[len(_SUMMARY_MARKER) :].strip()
            break
    if line is None:
        raise ScanParseError(f"no scan summary marker in box output: {stdout[:200]!r}")
    try:
        obj = json.loads(line)
    except (ValueError, TypeError) as e:
        raise ScanParseError(f"scan summary not valid JSON: {e}: {line[:200]!r}") from e
    if not obj.get("ok"):
        raise ScanParseError(f"box could not scan/parse report: {obj.get('error')!r}")
    try:
        return ScanClassification(
            os_critical=int(obj["os_critical"]),
            os_high=int(obj["os_high"]),
            dep_critical=int(obj["dep_critical"]),
            dep_high=int(obj["dep_high"]),
            # OS fields are optional (older box output / non-OS images omit
            # them) — default to empty so this stays backward compatible.
            os_family=str(obj.get("os_family") or ""),
            os_name=str(obj.get("os_name") or ""),
        )
    except (KeyError, TypeError, ValueError) as e:
        raise ScanParseError(f"scan summary missing counts: {e}: {obj!r}") from e


# Marker for the compact RESIDUAL list the box prints (distinct from the count
# summary marker so the two can be parsed independently).
_RESIDUAL_MARKER = "__HARDEN_RESIDUAL__"


def box_residual_command(
    report_path: str,
    *,
    out_report_path: str,
    out_vex_path: str,
    image_ref: str,
    image_digest: str,
) -> str:
    """Build the residual REPORT + OpenVEX ON THE BOX, write them to FILES, and
    print only a tiny counts summary to stdout.

    "Residual" = findings with NO available fix (no FixedVersion): the CVEs that
    remain after copa patched everything fixable — the honest residual we report
    (and VEX) to the client, matching why their ECR console still shows CVEs on
    a correctly-hardened image.

    WHY FILES, NOT STDOUT: the residual list for a fat base (every unfixable CVE
    with packages + titles) easily exceeds SSM's ~24 KB stdout cap, which would
    truncate the JSON mid-stream (exactly the trap we hit with the raw report).
    So the box WRITES the full report + VEX JSON to disk (no size limit) — the
    orchestrator then `aws s3 cp`s those files, same as the SBOM. Only a small
    counts summary comes back via stdout:

        __HARDEN_RESIDUAL__ {"ok": true, "total": N, "critical": N, "high": N,
                             "medium": N, "low": N, "unknown": N}
    or on failure:
        __HARDEN_RESIDUAL__ {"ok": false, "error": "..."}

    Findings are deduplicated BY CVE ID (packages aggregated), matching the
    client's ECR/Inspector grouping rather than trivy's per-binary duplication.
    All severities are included (full transparency; the GATE stays crit/high).
    The report + VEX JSON written here mirror the shapes in residual.py so the
    on-box and in-process builders stay consistent.
    """
    # argv: [1]=trivy report path, [2]=marker, [3]=out report, [4]=out vex,
    #       [5]=image_ref, [6]=image_digest
    py = (
        "import json,sys,datetime\n"
        "p=sys.argv[1]; mk=sys.argv[2]; orp=sys.argv[3]; ovp=sys.argv[4]\n"
        "img=sys.argv[5]; dig=sys.argv[6]\n"
        "try:\n"
        "    d=json.load(open(p))\n"
        "except Exception as e:\n"
        "    print(mk+' '+json.dumps({'ok':False,'error':'read/parse: '+str(e)[:200]}))\n"
        "    sys.exit(0)\n"
        "agg={}\n"
        "for r in (d.get('Results') or []):\n"
        "    for v in (r.get('Vulnerabilities') or []):\n"
        "        if v.get('FixedVersion'): continue\n"
        "        vid=v.get('VulnerabilityID') or ''\n"
        "        if not vid: continue\n"
        "        e=agg.get(vid)\n"
        "        if e is None:\n"
        "            e={'id':vid,'severity':(v.get('Severity') or 'UNKNOWN').upper(),"
        "'status':v.get('Status') or '','pkgs':set(),"
        "'installed':v.get('InstalledVersion') or '',"
        "'title':(v.get('Title') or '')[:200]}\n"
        "            agg[vid]=e\n"
        "        pn=v.get('PkgName')\n"
        "        if pn: e['pkgs'].add(pn)\n"
        "order=['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN']\n"
        "findings=[]\n"
        "for e in agg.values():\n"
        "    e['packages']=sorted(e.pop('pkgs'))\n"
        "    e['installed_version']=e.pop('installed')\n"
        "    if e['severity'] not in order: e['severity']='UNKNOWN'\n"
        "    findings.append(e)\n"
        "findings.sort(key=lambda x:(order.index(x['severity']),x['id']))\n"
        "counts={s.lower():0 for s in order}\n"
        "for f in findings: counts[f['severity'].lower()]+=1\n"
        "counts['total']=len(findings)\n"
        "now=datetime.datetime.now(datetime.timezone.utc).isoformat()\n"
        "report={'schema':'sisyfix.image-hardening.residual/v1','generated_at':now,"
        "'image_ref':img,'image_digest':dig,"
        "'artifact_name':d.get('ArtifactName') or '',"
        "'definition':'Residual = CVEs with NO available fix at hardening time "
        "(unfixable). All fixable CRITICAL/HIGH were patched (policy-zero gate).',"
        "'counts':counts,'findings':findings}\n"
        "prod='pkg:oci/'+img.rsplit(':',1)[0].rsplit('/',1)[-1]+'@'+dig if dig else img\n"
        "stmts=[]\n"
        "for f in findings:\n"
        "    stmts.append({'vulnerability':{'name':f['id']},'products':[{'@id':prod}],"
        "'status':'affected','action_statement':'No upstream fix available at "
        "hardening time (vendor status: '+(f['status'] or 'no-fix-available')+'). "
        "All fixable findings were patched; cannot remediate by patching today.',"
        "'action_statement_timestamp':now})\n"
        "vex={'@context':'https://openvex.dev/ns/v0.2.0',"
        "'@id':'https://sisyfix/vex/'+(dig or 'unknown'),"
        "'author':'Sisyfix Image Hardening','timestamp':now,'version':1,'statements':stmts}\n"
        "open(orp,'w').write(json.dumps(report,indent=2))\n"
        "open(ovp,'w').write(json.dumps(vex,indent=2))\n"
        "print(mk+' '+json.dumps({'ok':True,**counts}))\n"
    )
    return (
        f"python3 - '{report_path}' '{_RESIDUAL_MARKER}' '{out_report_path}' "
        f"'{out_vex_path}' '{image_ref}' '{image_digest}' "
        f"<<'__HARDEN_RES_EOF__'\n{py}__HARDEN_RES_EOF__"
    )


def parse_box_residual_counts(stdout: str) -> dict:
    """Parse the tiny counts summary emitted by `box_residual_command`.

    Returns {"total","critical","high","medium","low","unknown"}. HARD-FAILS
    (ScanParseError) on missing/malformed output or ok=false — residual
    reporting must not silently misrepresent the image as cleaner than it is.
    The full report + VEX were written to FILES on the box (uploaded separately).
    """
    if not stdout:
        raise ScanParseError("empty residual output from build box")
    line = None
    for ln in stdout.splitlines():
        if ln.startswith(_RESIDUAL_MARKER):
            line = ln[len(_RESIDUAL_MARKER) :].strip()
            break
    if line is None:
        raise ScanParseError(f"no residual marker in box output: {stdout[:200]!r}")
    try:
        obj = json.loads(line)
    except (ValueError, TypeError) as e:
        raise ScanParseError(f"residual payload not valid JSON: {e}: {line[:200]!r}") from e
    if not obj.get("ok"):
        raise ScanParseError(f"box could not extract residual: {obj.get('error')!r}")
    return {
        "total": int(obj.get("total", 0)),
        "critical": int(obj.get("critical", 0)),
        "high": int(obj.get("high", 0)),
        "medium": int(obj.get("medium", 0)),
        "low": int(obj.get("low", 0)),
        "unknown": int(obj.get("unknown", 0)),
    }


# Marker for the compact lang-pkgs (dependency) findings the box prints for the
# dependency-bump leg.
_DEPS_MARKER = "__HARDEN_DEPS__"


def box_deps_report_command(report_path: str) -> str:
    """Return a shell command that extracts ONLY the lang-pkgs (dependency)
    findings from a trivy report ON THE BOX, as a compact `{"Results": [...]}`
    JSON printed after a marker.

    WHY: the dependency-bump leg feeds trivy findings to `compute_pip_bumps`,
    which reads Results[].Vulnerabilities[] (Class/Type/PkgName/FixedVersion/
    Severity/VulnerabilityID). The full report is multi-MB and `cat`-ing it over
    SSM stdout truncates at ~24 KB (the same trap fixed elsewhere). The lang-pkgs
    SUBSET — only the fields the bumper needs — is tiny, so we emit just that.
    The emitted JSON keeps the SAME SHAPE compute_pip_bumps expects, so that
    pure function needs no change.

    Emits:
        __HARDEN_DEPS__ {"ok": true, "report": {"Results": [ {Class, Type,
                         Vulnerabilities:[{PkgName, FixedVersion, Severity,
                         VulnerabilityID}, ...]}, ... ]}}
    or on failure:
        __HARDEN_DEPS__ {"ok": false, "error": "..."}
    """
    py = (
        "import json,sys\n"
        "p=sys.argv[1]; mk=sys.argv[2]\n"
        "try:\n"
        "    d=json.load(open(p))\n"
        "except Exception as e:\n"
        "    print(mk+' '+json.dumps({'ok':False,'error':'read/parse: '+str(e)[:200]}))\n"
        "    sys.exit(0)\n"
        "results=[]\n"
        "for r in (d.get('Results') or []):\n"
        "    if (r.get('Class') or '').strip()!='lang-pkgs': continue\n"
        "    vulns=[]\n"
        "    for v in (r.get('Vulnerabilities') or []):\n"
        "        vulns.append({'PkgName':v.get('PkgName'),"
        "'FixedVersion':v.get('FixedVersion'),'Severity':v.get('Severity'),"
        "'VulnerabilityID':v.get('VulnerabilityID')})\n"
        "    results.append({'Class':r.get('Class'),'Type':r.get('Type'),"
        "'Vulnerabilities':vulns})\n"
        "print(mk+' '+json.dumps({'ok':True,'report':{'Results':results}}))\n"
    )
    return f"python3 - '{report_path}' '{_DEPS_MARKER}' <<'__HARDEN_DEPS_EOF__'\n{py}__HARDEN_DEPS_EOF__"


def parse_box_deps_report(stdout: str) -> str:
    """Parse the compact lang-pkgs report emitted by `box_deps_report_command`.

    Returns the report as a JSON STRING (same shape compute_pip_bumps expects),
    so callers can pass it straight through. HARD-FAILS (ScanParseError) on
    missing/malformed output or ok=false — a silent empty report would make the
    bumper think there are no dependency fixes when there may be.
    """
    if not stdout:
        raise ScanParseError("empty deps output from build box")
    line = None
    for ln in stdout.splitlines():
        if ln.startswith(_DEPS_MARKER):
            line = ln[len(_DEPS_MARKER) :].strip()
            break
    if line is None:
        raise ScanParseError(f"no deps marker in box output: {stdout[:200]!r}")
    try:
        obj = json.loads(line)
    except (ValueError, TypeError) as e:
        raise ScanParseError(f"deps payload not valid JSON: {e}: {line[:200]!r}") from e
    if not obj.get("ok"):
        raise ScanParseError(f"box could not extract deps report: {obj.get('error')!r}")
    return json.dumps(obj.get("report") or {"Results": []})


def classify_trivy_report(report_json: str) -> ScanClassification:
    """Parse a full-scope trivy JSON report (as a STRING) into fixable crit/high.

    Full-scope report is produced with:
        trivy image --vuln-type os,library --ignore-unfixed -f json ...

    HARD-FAILS (raises ScanParseError) on malformed/empty input rather than
    returning an all-zero classification. Returning zeros on a parse failure
    silently PASSES the policy-zero gate on an unscanned image — the exact bug
    this guards against. Callers that scan large reports should prefer the
    box-side counter (`box_count_command` + `parse_box_summary`) to avoid SSM
    stdout truncation; this string parser remains for small reports and tests.
    """
    try:
        data = json.loads(report_json)
    except (ValueError, TypeError) as e:
        raise ScanParseError(f"trivy report not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise ScanParseError(f"trivy report is not a JSON object: {type(data).__name__}")

    os_c = os_h = dep_c = dep_h = 0
    for result in data.get("Results") or []:
        cls = (result.get("Class") or "").strip()
        for v in result.get("Vulnerabilities") or []:
            sev = (v.get("Severity") or "").upper()
            if sev not in _GATE_SEVERITIES:
                continue
            if not v.get("FixedVersion"):  # only fixable findings count
                continue
            is_os = cls == _CLASS_OS
            is_dep = cls == _CLASS_LANG
            # If Class is missing/unknown, be conservative and treat as dep
            # (dep is the "needs source" path — safer to over-report than to
            # silently drop a finding from the gate).
            if not is_os and not is_dep:
                is_dep = True
            if sev == "CRITICAL":
                if is_os:
                    os_c += 1
                else:
                    dep_c += 1
            elif sev == "HIGH":
                if is_os:
                    os_h += 1
                else:
                    dep_h += 1
    return ScanClassification(os_critical=os_c, os_high=os_h, dep_critical=dep_c, dep_high=dep_h)
