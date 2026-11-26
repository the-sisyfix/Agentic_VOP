#!/bin/bash
# =============================================================================
# Playground image verification. Runs on a CLONE of the golden image (as root,
# over SSM) and prints one PASS/FAIL line per check, then VERIFY_RESULT.
# It never applies Terraform: the activation test is init + plan only.
#
# Inputs (environment): STATE_BUCKET, LOCK_TABLE, REGION (optional)
# =============================================================================
set -uo pipefail
REGION="${REGION:-us-east-1}"
FAILS=0
ok()   { echo "PASS  $*"; }
bad()  { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }
check() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }

echo "== identity"
echo "host: $(hostname)  uptime: $(uptime -p)"
echo "manifest:"; cat /opt/playground/MANIFEST.json 2>/dev/null | head -40

echo "== files"
check "manifest present"               test -f /opt/playground/MANIFEST.json
check "activate.sh executable"         test -x /opt/playground/activate.sh
check "setup marker"                   test -f /opt/vuln-labs/SETUP_COMPLETE
check "appsec app.py"                  test -f /opt/vuln-labs/appsec-lab/app.py
check "appsec requirements.txt"        test -f /opt/vuln-labs/appsec-lab/requirements.txt
check "cspm template"                  test -f /opt/vuln-labs/cspm-lab/main.tf.template
check "cspm main.tf NOT pre-rendered"  test ! -f /opt/vuln-labs/cspm-lab/main.tf
check "semgrep-rules.yaml"             test -s /opt/vuln-labs/results/semgrep-rules.yaml
check "serverless-rules.yaml"          test -s /opt/vuln-labs/results/serverless-rules.yaml
check "serverless lab NOT present"     test ! -d /opt/vuln-labs/serverless-lab
check "no .bak files in labs"          bash -c '[ -z "$(find /opt/vuln-labs -name "*.bak-*" 2>/dev/null)" ]'

echo "== services and tools"
check "docker daemon active"           systemctl is-active docker
check "ssm agent active"               bash -c 'systemctl is-active snap.amazon-ssm-agent.amazon-ssm-agent.service || systemctl is-active amazon-ssm-agent'
check "unattended-upgrades disabled"   bash -c '! systemctl is-enabled unattended-upgrades 2>/dev/null | grep -q enabled'
for t in terraform trivy semgrep checkov aws docker; do check "tool: $t" command -v "$t"; done

echo "== images"
for img in vuln-lab-image vuln-java-image vuln-python-image vuln-php-image; do
  check "image $img:latest" docker image inspect "$img:latest"
done

echo "== disk"
df -h / | tail -1
FREE_GB="$(df --output=avail -B1G / | tail -1 | tr -d ' ')"
[ "$FREE_GB" -ge 4 ] && ok "free space ${FREE_GB}G >= 4G" || bad "free space ${FREE_GB}G < 4G"

echo "== quick scanner smoke tests"
check "semgrep parses extracted rules" semgrep --config /opt/vuln-labs/results/semgrep-rules.yaml --validate
check "trivy fs runs on appsec lab"    bash -c 'trivy fs /opt/vuln-labs/appsec-lab --scanners vuln --format json --quiet | python3 -c "import json,sys; json.load(sys.stdin)"'

echo "== activation (init + plan only, nothing is created)"
if [ -n "${STATE_BUCKET:-}" ] && [ -n "${LOCK_TABLE:-}" ]; then
  P="verify-$(date +%s)"
  ACT_OUT="$(/opt/playground/activate.sh --prefix "$P" --labs cspm --state-bucket "$STATE_BUCKET" --lock-table "$LOCK_TABLE" --region "$REGION" 2>&1)"
  ACT_RC=$?
  echo "$ACT_OUT" | tail -3
  [ "$ACT_RC" -eq 0 ] && ok "activate.sh ran (prefix $P)" || bad "activate.sh failed (rc=$ACT_RC)"
  check "main.tf rendered with prefix"   grep -q "cspm-lab-$P-bucket" /opt/vuln-labs/cspm-lab/main.tf
  check "main.tf.original saved"         cmp -s /opt/vuln-labs/cspm-lab/main.tf /opt/vuln-labs/cspm-lab/main.tf.original
  check "backend key unique to prefix"   grep -q "cspm-lab/$P/terraform.tfstate" /opt/vuln-labs/cspm-lab/backend.hcl
  ( cd /opt/vuln-labs/cspm-lab && terraform plan -lock=false -input=false -no-color -detailed-exitcode > /tmp/verify-plan.txt 2>&1; echo "plan_exit=$?" )
  grep -E "^Plan:" /tmp/verify-plan.txt || true
  check "plan creates 8 resources"       grep -q "Plan: 8 to add, 0 to change, 0 to destroy" /tmp/verify-plan.txt
  if /opt/playground/activate.sh --prefix "other-prefix-x" --labs cspm --state-bucket "$STATE_BUCKET" --lock-table "$LOCK_TABLE" >/dev/null 2>&1; then
    bad "activate.sh must refuse a different prefix"
  else
    ok "activate.sh refuses a different prefix"
  fi
else
  echo "SKIP  activation checks (STATE_BUCKET / LOCK_TABLE not provided)"
fi

echo "VERIFY_RESULT fails=${FAILS}"
exit $FAILS
