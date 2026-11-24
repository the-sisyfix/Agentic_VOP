"""Sub-Agent 4 safety module — command-level guardrails before SSM dispatch.

Every command the fixer would run through SSM RunCommand passes through
`validate_command()` first. Blocked patterns are non-negotiable — hitting
one halts the current step + triggers rollback + persists a safety_reason
on the step result.

Two layers of defense:
  1. Regex blocklist  — patterns for actions we NEVER want run on env2
  2. Path allowlist   — commands operating outside /opt/vuln-labs/* are
                        rejected even if they'd otherwise be innocuous

Design notes:
  - Patterns come from Nikhil's 2026-07-13 architecture doc. Same list as
    the verifier's DESTRUCTIVE_PATTERNS but the fixer BLOCKS at exec time,
    whereas the verifier just FLAGS in the package.
  - Patterns are family-agnostic — apply equally to Terraform, apt, pip,
    kubectl, etc. Adding new patterns doesn't require changes elsewhere.
  - `validate_command` is pure — no I/O, no state. Safe to call from
    strategies + the LLM tool wrapper alike.
"""

from __future__ import annotations

import re

from .models import SafetyResult


# =============================================================================
# Blocked command patterns (regex, case-insensitive)
#
# Each entry: (pattern_name, compiled_regex, human_readable_reason)
# =============================================================================
_BLOCKED_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "rm-rf-root-or-wildcard",
        re.compile(r"\brm\s+-rf\s+(/(\s|$)|/[a-zA-Z]|\$\w+|\*(\s|$)|~\/?)", re.IGNORECASE),
        "Recursive delete from root, wildcard, or unexpanded variable path. Irreversible; refuse.",
    ),
    (
        "mkfs-format",
        re.compile(r"\bmkfs\.", re.IGNORECASE),
        "Filesystem format command. Destroys all data on target device.",
    ),
    (
        "dd-raw-disk-write",
        re.compile(r"\bdd\s+.*(if=|of=/dev/)", re.IGNORECASE),
        "Raw disk write via dd — bypasses all filesystem protections.",
    ),
    (
        "shell-download-pipe",
        re.compile(r"\b(curl|wget|fetch)\b[^|]*\|\s*(bash|sh|zsh|python\d?|perl)\b", re.IGNORECASE),
        "Piping downloaded content into a shell. Arbitrary code from arbitrary URL.",
    ),
    (
        "imds-credential-fetch",
        re.compile(r"169\.254\.169\.254", re.IGNORECASE),
        "IMDS endpoint access — potential IAM role credential exfiltration.",
    ),
    (
        "iam-create-user",
        re.compile(r"\baws\s+iam\s+create-user\b", re.IGNORECASE),
        "IAM user creation is outside the fixer's blast radius.",
    ),
    (
        "iam-create-access-key",
        re.compile(r"\baws\s+iam\s+create-access-key\b", re.IGNORECASE),
        "Long-lived credential generation — never appropriate from an automated fix.",
    ),
    (
        "iam-attach-admin",
        re.compile(r"\baws\s+iam\s+(attach|put)-[a-z-]+.*Admin", re.IGNORECASE),
        "Attaching admin/wildcard policy — privilege escalation.",
    ),
    (
        "overwrite-system-auth-files",
        re.compile(
            r"\s*>\s*/etc/(passwd|shadow|sudoers|group|gshadow)\b",
            re.IGNORECASE,
        ),
        "Direct overwrite of system auth database — refuse.",
    ),
    (
        "chmod-recursive-root",
        re.compile(
            r"\bchmod\s+.*-R\s+.*\s+(/|/etc|/usr|/bin|/sbin)(\s|$)",
            re.IGNORECASE,
        ),
        "Recursive chmod near system directories — can render OS unbootable.",
    ),
    (
        "aws-account-close",
        re.compile(r"\baws\s+organizations\s+(close-account|leave-organization)\b", re.IGNORECASE),
        "Account closure / org leave — outside fixer scope.",
    ),
    (
        "terraform-destroy",
        re.compile(r"\bterraform\s+(destroy|apply\s+-destroy)\b", re.IGNORECASE),
        "Wholesale terraform destroy — never a fix. Rollback uses restore-and-apply, not destroy.",
    ),
    (
        "s3-rb-force",
        re.compile(r"\baws\s+s3\s+rb\s+.*--force\b", re.IGNORECASE),
        "Force-delete S3 bucket with contents — irrecoverable.",
    ),
    (
        "kubectl-delete-namespace",
        re.compile(r"\bkubectl\s+delete\s+(namespace|ns)\s+\S+", re.IGNORECASE),
        "Deletes entire namespace including all workloads + PVCs.",
    ),
    (
        "interactive-editor-or-pager",
        # SSM RunCommand runs non-interactively — invoking vim/nano/less
        # hangs the session waiting for TTY input until timeout. Fail fast
        # with a clear reason instead of burning the whole step timeout.
        # Matched at word boundaries so `vimdiff-plugin.tf` etc. don't trip.
        re.compile(
            r"(^|[\s;&|`])(vim|vi|nano|emacs|pico|less|more|top|htop|man)(\s|$)",
            re.IGNORECASE | re.MULTILINE,
        ),
        "Interactive tool (editor/pager) — SSM runs non-interactively and will hang until timeout. "
        "Use `cat >> file << 'EOF' ... EOF` for appends or `sed -i` for in-place edits instead.",
    ),
    # =========================================================================
    # Host-level dangerous commands — can sever the SSM connection, render the
    # instance unreachable, or destroy state that makes the sandbox unrecoverable.
    # These apply to ALL strategies (OS, image, IaC) generically.
    # =========================================================================
    (
        "reboot-or-shutdown",
        # Catches: reboot, sudo reboot, shutdown, sudo shutdown, init 6, init 0,
        # systemctl reboot, systemctl poweroff, halt, poweroff.
        # Does NOT match strings like "reboot_required" in grep output.
        re.compile(
            r"(^|[;&|]\s*)(sudo\s+)?(reboot|shutdown|halt|poweroff)\b"
            r"|"
            r"\b(init|telinit)\s+[06]\b"
            r"|"
            r"\bsystemctl\s+(reboot|poweroff|halt)\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        "Reboot/shutdown severs SSM connection and makes the instance unreachable. "
        "OS package fixes do NOT require a reboot unless the CVE is in kernel or glibc. "
        "Remove this step — the fix takes effect immediately for userspace packages.",
    ),
    (
        "stop-ssm-agent",
        # Stopping the SSM agent kills the communication channel — all
        # subsequent commands (including rollback) become impossible.
        re.compile(
            r"\b(systemctl|service)\s+(stop|disable|mask)\s+(amazon-ssm-agent|ssm-agent|sshd)\b",
            re.IGNORECASE,
        ),
        "Stopping SSM agent or SSHD severs remote access — instance becomes unreachable. "
        "Never stop the management agent during an automated fix.",
    ),
    (
        "kill-all-or-killall",
        # `killall` or `kill -9 -1` (kill all processes) would nuke the SSM
        # session along with everything else.
        re.compile(
            r"\bkillall\b|\bkill\s+-9\s+-1\b|\bpkill\s+-9\s+",
            re.IGNORECASE,
        ),
        "Mass process kill (killall / kill -9 -1 / pkill -9) would terminate the SSM session. "
        "Never appropriate in an automated remediation context.",
    ),
    (
        "network-interface-down",
        # Taking down the network interface severs connectivity.
        re.compile(
            r"\b(ifdown|ip\s+link\s+set\s+\S+\s+down|nmcli\s+.*\s+down)\b",
            re.IGNORECASE,
        ),
        "Taking a network interface down severs connectivity — instance becomes unreachable.",
    ),
    (
        "iptables-drop-all",
        # Flushing iptables to DROP or adding a blanket DROP rule kills connectivity.
        re.compile(
            r"\biptables\s+.*(-P\s+(INPUT|OUTPUT|FORWARD)\s+DROP|-A\s+INPUT\s+-j\s+DROP)",
            re.IGNORECASE,
        ),
        "Blanket iptables DROP policy severs all network connectivity including SSM.",
    ),
    (
        "package-manager-remove-critical",
        # Removing critical system packages (systemd, glibc, kernel, bash, coreutils)
        # can brick the instance. Upgrading is fine; removal is not.
        re.compile(
            r"\b(apt-get|apt|yum|dnf|rpm)\s+(remove|purge|erase)\s+.*(systemd|glibc|libc6|bash|coreutils|kernel|linux-image|openssh)\b",
            re.IGNORECASE,
        ),
        "Removing critical system packages (systemd, glibc, bash, kernel, openssh) can "
        "brick the instance. Use upgrade/update instead of remove/purge.",
    ),
    (
        "userdel-root-or-ec2-user",
        # Deleting the root user or the ec2-user / ssm-user locks out access.
        re.compile(
            r"\buserdel\s+.*(root|ec2-user|ssm-user|admin|ubuntu)\b",
            re.IGNORECASE,
        ),
        "Deleting root, ec2-user, ssm-user, or admin user locks out all access.",
    ),
]


# =============================================================================
# Path allowlist — commands may only cd/touch files inside these prefixes.
# =============================================================================
_ALLOWED_WORKING_DIRECTORIES: tuple[str, ...] = (
    "/opt/vuln-labs/",
    "/tmp/fixer-scratch/",  # noqa: S108 — intentional scratch dir for fixer strategies
    "/",  # OS strategy runs apt-get from root (no specific workdir)
    # Image Hardening (separate feature) reuses this validator as a library and
    # builds in its own clone dir on the dedicated build EC2. Additive entry —
    # does not change validation for any existing fixer strategy.
    "/opt/image-forge-src/",
)


# Patterns that reveal the command is trying to escape the working directory
# via path traversal. Any of these fires → reject regardless of blocklist.
_PATH_TRAVERSAL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\.\./\.\./"),  # up two dirs
    re.compile(r"\.\.\\/\.\.\\/"),  # windows-style just in case
    re.compile(r"~/\.\.[^/]"),  # ~/../
]


# Environment variable exfiltration patterns
_ENV_EXFIL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\benv\s*\|\s*(curl|wget|nc|netcat|base64)", re.IGNORECASE),
    re.compile(r"\bprintenv\s*\|\s*(curl|wget|nc|netcat|base64)", re.IGNORECASE),
    re.compile(r"\$AWS_(SECRET|SESSION)_[A-Z_]+", re.IGNORECASE),
]


# =============================================================================
# Public API
# =============================================================================
def validate_command(command: str, working_directory: str | None = None) -> SafetyResult:
    """Return SafetyResult(allowed, reason, matched_pattern).

    Checks in this order (any single failure → reject):
      1. Blocked-pattern regex list
      2. Path-traversal patterns
      3. Environment-variable exfiltration patterns
      4. Working directory (if provided) is within the allowlist

    `command` is treated as opaque untrusted text. `working_directory` is
    what the strategy claims it will `cd` into; enforced by the runner.
    """
    if not command or not command.strip():
        return SafetyResult(
            allowed=False,
            reason="Empty command not allowed",
        )

    # 1. Blocked patterns
    for name, pattern, reason in _BLOCKED_PATTERNS:
        if pattern.search(command):
            return SafetyResult(
                allowed=False,
                reason=reason,
                matched_pattern=name,
            )

    # 2. Path traversal
    for pat in _PATH_TRAVERSAL_PATTERNS:
        if pat.search(command):
            return SafetyResult(
                allowed=False,
                reason="Path traversal detected — command escapes working directory",
                matched_pattern="path-traversal",
            )

    # 3. Env exfiltration
    for pat in _ENV_EXFIL_PATTERNS:
        if pat.search(command):
            return SafetyResult(
                allowed=False,
                reason="Environment variable exfiltration pattern detected",
                matched_pattern="env-exfiltration",
            )

    # 4. Working directory allowlist
    if working_directory is not None:
        allowed = any(
            working_directory == p.rstrip("/") or working_directory.startswith(p)
            for p in _ALLOWED_WORKING_DIRECTORIES
        )
        if not allowed:
            return SafetyResult(
                allowed=False,
                reason=(
                    f"Working directory {working_directory!r} is not in the allowlist "
                    f"({', '.join(_ALLOWED_WORKING_DIRECTORIES)})"
                ),
                matched_pattern="dir-not-allowed",
            )

    return SafetyResult(allowed=True)


def list_blocked_patterns() -> list[dict[str, str]]:
    """Introspection helper — returns the blocklist for debugging/UI display.

    Format: [{"name": ..., "regex": pattern.pattern, "reason": ...}, ...]
    """
    return [
        {"name": name, "regex": pat.pattern, "reason": reason}
        for name, pat, reason in _BLOCKED_PATTERNS
    ]
