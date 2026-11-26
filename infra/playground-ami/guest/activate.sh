#!/bin/bash
# =============================================================================
# Playground activation: turns a freshly launched clone of the golden image
# into one lease's private playground.
#
# Installed at /opt/playground/activate.sh by bake.sh. Run as root over SSM.
#
#   activate.sh --prefix <lease-prefix> [--labs cspm] [--apply] \
#               [--state-bucket B --lock-table T] [--region us-east-1]
#
# What it does for the cspm lab:
#   1. Renders /opt/vuln-labs/cspm-lab/main.tf from main.tf.template using the
#      lease prefix, so every real AWS resource name is unique to this lease.
#   2. Saves the pristine render as main.tf.original (the reset baseline).
#   3. Writes backend.hcl with a state key unique to this lease.
#   4. terraform init. With --apply it also creates the lab resources.
#
# Safe to re-run with the same prefix. A different prefix is refused.
# The last line of output is ACTIVATE_RESULT {json}.
# =============================================================================
set -euo pipefail

PREFIX=""
LABS="cspm"
APPLY="no"
STATE_BUCKET=""
LOCK_TABLE=""
REGION="us-east-1"

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --labs) LABS="$2"; shift 2 ;;
    --apply) APPLY="yes"; shift ;;
    --state-bucket) STATE_BUCKET="$2"; shift 2 ;;
    --lock-table) LOCK_TABLE="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

fail() { echo "ACTIVATE_ERROR $*" >&2; exit 1; }

# S3 bucket names are "cspm-lab-<prefix>-bucket" (max 63 chars), so cap the prefix.
[[ "$PREFIX" =~ ^[a-z0-9][a-z0-9-]{2,38}[a-z0-9]$ ]] || fail "invalid --prefix '${PREFIX}' (lowercase letters, digits, '-', 4-40 chars)"

MARKER=/opt/playground/ACTIVATED.json
if [ -f "$MARKER" ]; then
  OLD="$(python3 -c "import json;print(json.load(open('$MARKER'))['prefix'])")"
  [ "$OLD" = "$PREFIX" ] || fail "already activated with prefix '${OLD}', refusing '${PREFIX}'"
fi

APPLIED="no"
if [[ ",${LABS}," == *",cspm,"* ]]; then
  [ -n "$STATE_BUCKET" ] && [ -n "$LOCK_TABLE" ] || fail "--state-bucket and --lock-table are required for the cspm lab"
  D=/opt/vuln-labs/cspm-lab
  [ -f "$D/main.tf.template" ] || fail "$D/main.tf.template missing (not a playground image?)"

  sed -e "s/NAME_PLACEHOLDER/${PREFIX}/g" -e "s/REGION_PLACEHOLDER/${REGION}/g" "$D/main.tf.template" > "$D/main.tf"
  if grep -q "PLACEHOLDER" "$D/main.tf"; then fail "unrendered placeholder left in main.tf"; fi
  cp "$D/main.tf" "$D/main.tf.original"

  cat > "$D/backend.hcl" <<EOF
bucket         = "${STATE_BUCKET}"
key            = "vuln-labs/cspm-lab/${PREFIX}/terraform.tfstate"
region         = "${REGION}"
encrypt        = true
dynamodb_table = "${LOCK_TABLE}"
EOF

  cd "$D"
  terraform init -reconfigure -backend-config=backend.hcl -input=false -no-color >/tmp/activate-init.log 2>&1 \
    || { tail -20 /tmp/activate-init.log >&2; fail "terraform init failed"; }
  if [ "$APPLY" = "yes" ]; then
    terraform apply -auto-approve -input=false -no-color >/tmp/activate-apply.log 2>&1 \
      || { tail -20 /tmp/activate-apply.log >&2; fail "terraform apply failed"; }
    APPLIED="yes"
  fi
  chown -R ubuntu:ubuntu "$D" 2>/dev/null || true
fi

python3 - <<PY
import datetime, json
rec = {"prefix": "${PREFIX}", "labs": "${LABS}", "applied": "${APPLIED}", "region": "${REGION}",
       "activated_at": datetime.datetime.utcnow().isoformat() + "Z"}
json.dump(rec, open("${MARKER}", "w"))
print("ACTIVATE_RESULT " + json.dumps(rec))
PY
