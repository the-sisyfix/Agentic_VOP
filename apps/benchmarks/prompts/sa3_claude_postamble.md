

<output_schema_example>
Below is a CONCRETE EXAMPLE of a valid LLMRemediationOutput for a Checkov
S3-encryption finding. Match this shape exactly. Replace the content with
values derived from THIS finding + your research — never emit this example
verbatim.

{
  "finding": "Checkov CKV_AWS_145: S3 bucket 'cspm-lab-audit-logs' lacks default encryption; aws_s3_bucket.audit_logs block in main.tf has no server_side_encryption_configuration.",
  "root_cause": "The bucket resource declares storage without opt-in to SSE. AWS does not apply default encryption at the account level in this environment, so new objects land unencrypted.",
  "impact": "Objects at rest are not encrypted; a bucket-policy misconfiguration or stolen access key could expose plaintext audit logs. Violates SOC2 CC6.7 and the organization's data-at-rest policy.",
  "pathways": [
    {
      "name": "Enable SSE-S3 via server_side_encryption_configuration block",
      "description": "Append an aws_s3_bucket_server_side_encryption_configuration resource bound to the existing bucket, using AES256. Zero extra IAM, zero new KMS keys, lowest blast radius.",
      "remediation_steps": [
        {
          "step": "Phase A — BACKUP: Snapshot main.tf before edit.\n\nCommand:\n    cp /workspace/main.tf /workspace/main.tf.bak-$(date +%Y%m%d-%H%M%S)\n\nWhy: Enables trivial rollback if terraform apply surfaces an unforeseen issue; takes <100ms.",
          "source": "Phase A — Backup pattern, SA3 IaC-first spec",
          "source_url": ""
        },
        {
          "step": "Phase B — EDIT main.tf: Append an SSE-S3 configuration block.\n\nCommand:\n    cat >> /workspace/main.tf << 'EOF'\n\n    resource \"aws_s3_bucket_server_side_encryption_configuration\" \"audit_logs_sse\" {\n      bucket = aws_s3_bucket.audit_logs.id\n      rule {\n        apply_server_side_encryption_by_default {\n          sse_algorithm = \"AES256\"\n        }\n      }\n    }\n    EOF\n\nWhy: SSE-S3 (AES256) satisfies CKV_AWS_145 without requiring KMS CreateKey permissions. The configuration binds to the existing bucket via its .id attribute.",
          "source": "CKV_AWS_145 Checkov policy doc",
          "source_url": "https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-general-policies/ensure-s3-bucket-has-server-side-encryption"
        },
        {
          "step": "Phase C — PLAN: terraform dry-run.\n\nCommand:\n    cd /workspace && terraform plan -detailed-exitcode\n\nWhy: Exit 2 = changes to apply (expected). Exit 0 = edit didn't register (abort). Exit 1 = error (abort).",
          "source": "SA3 Phase C spec",
          "source_url": ""
        },
        {
          "step": "Phase D — APPLY: Commit the fix.\n\nCommand:\n    cd /workspace && terraform apply -auto-approve\n\nWhy: Applies the new SSE configuration resource to the live bucket.",
          "source": "SA3 Phase D spec",
          "source_url": ""
        },
        {
          "step": "Phase E — VERIFY CLI: Confirm bucket now has SSE.\n\nCommand:\n    aws s3api get-bucket-encryption --bucket cspm-lab-audit-logs --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text\n\nWhy: Resource-level smoke check. Expected output: AES256.",
          "source": "AWS S3 API docs",
          "source_url": "https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-encryption.html"
        }
      ],
      "validation_tests": [
        {
          "name": "Re-scan with original Checkov check — authoritative proof",
          "method": "cli",
          "command": "checkov -d /workspace --check CKV_AWS_145 --output json --quiet",
          "expected": "PASSED (not FAILED) for aws_s3_bucket.audit_logs",
          "source": "Checkov CKV_AWS_145 original check"
        },
        {
          "name": "AWS CLI SSE verification",
          "method": "cli",
          "command": "aws s3api get-bucket-encryption --bucket cspm-lab-audit-logs",
          "expected": "AES256",
          "source": "AWS S3 encryption API"
        }
      ],
      "advantages": [
        "Zero new IAM permissions required",
        "No KMS key management overhead",
        "AWS-managed key rotation handled transparently"
      ],
      "considerations": [
        "SSE-S3 satisfies the Checkov check but may not meet stricter compliance frameworks that require customer-managed keys (e.g. PCI-DSS with SAQ-D) — if that's a factor, use SSE-KMS instead",
        "Rollback is cp of the .bak file + terraform apply"
      ]
    }
  ]
}
</output_schema_example>

<final_reminder>
Emit the final answer as a tool_use call to the structured output tool with the
LLMRemediationOutput shape above. No prose. No markdown fences. Lowercase enums.
Fill every required field with concrete values. Stay under 8 tool calls total.
</final_reminder>
