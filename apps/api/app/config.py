from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict

# Push .env values into os.environ so plain os.getenv() calls (used for
# local-only feature flags that aren't worth adding to the Settings schema)
# can see them. pydantic-settings itself reads .env for declared Settings
# fields but does NOT propagate unknown keys to os.environ.
load_dotenv()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    agentic_vop_supabase_url: str
    agentic_vop_supabase_service_key: str

    openai_api_key: str

    # Optional provider keys — required only when the corresponding model
    # provider is selected in prompt_db.parameters.provider for any agent.
    anthropic_api_key: str = ""
    google_api_key: str = ""

    # Tenable / Nessus (only required if any tool uses connector_type="tenable_api")
    tenable_access_key: str = ""
    tenable_secret_key: str = ""

    # GitHub Dependabot (only required if any tool uses connector_type="dependabot_api")
    # Token needs the 'security_events' scope for public repos, or 'repo' for private repos.
    github_token: str = ""
    github_org: str = (
        ""  # org name or username; can also be set in connection_registry.metadata.org
    )

    # NVD API key (optional; without it, calls are rate-limited to 5 per 30 sec.
    # Get one free from https://nvd.nist.gov/developers/request-an-api-key)
    nvd_api_key: str = ""

    # Tavily web-search API key. Required by the agentic Sub-Agent 3 (Phase-2)
    # for live remediation research. Free tier = 1000 searches/month, plenty
    # for dev. Get one at https://tavily.com. When empty, the agent skips
    # live search and falls back to hybrid pattern-based planner.
    tavily_api_key: str = ""

    # Per-package budget for the agentic Sub-Agent 3. Prevents runaway costs.
    # Both caps are enforced; whichever is hit first triggers fallback to the
    # hybrid pattern-based planner.
    #
    # Budget accommodates BOTH phases:
    #   Research phase — 8-10 calls (searches + fetches to build the draft)
    #   Verification phase — 3-4 calls (cross-source consensus checks on the
    #     most impactful commands from the draft; see verifier.py)
    # Bumped to 16 (was 12) so verification has real room to run.
    agent_max_tool_calls: int = 16
    agent_max_cost_usd: float = 1.50

    # Parallel LLM workers — Sub-Agent 1 + Sub-Agent 2 run this many threads
    # concurrently. 5 gives ~150K TPM peak — comfortably under OpenAI's default
    # 200K TPM limit for gpt-4o-mini. Bump to 10+ if you have a higher tier.
    llm_parallel_workers: int = 5

    # Emit per-call TOKEN_USAGE trace events to the Agents page trace stream.
    # Set false to suppress the chatty per-LLM-invocation events at scale.
    # Token totals in the final TOKEN_SUMMARY remain accurate either way
    # because the callback always accumulates counts in memory.
    trace_token_usage: bool = True

    # --- Sub-Agent 4 (Fixer) settings ---
    # env2 (Remediation Playground) EC2 instance id — the sandbox target for
    # every fix run. Set once per deployment. Empty = Sub-Agent 4 refuses to
    # start (fails fast rather than silently attempt fixes with no target).
    fixer_env2_instance_id: str = ""

    # Path prefix to prepend to raw-finding absolute paths so they resolve to
    # env2's real filesystem layout. Example:
    #   Raw finding says:  /main.tf         (relative to Checkov's scan root)
    #   env2 actually has: /opt/vuln-labs/cspm-lab/main.tf
    #   Set:               FIXER_ENV2_PATH_PREFIX=/opt/vuln-labs/cspm-lab
    #   Result:            file_path = /opt/vuln-labs/cspm-lab/main.tf
    #
    # Empty (default) = no translation, use raw path as-is. This works when
    # the scanner + fix target share the same filesystem view (e.g. running
    # SA4 locally against a Terraform module on your laptop).
    fixer_env2_path_prefix: str = ""

    # Toggle for auto-chaining Sub-Agent 4 after Sub-Agent 3 in the demo
    # pipeline. Set false to keep SA3 emitting packages without triggering
    # execution (useful when env2 isn't provisioned yet).
    fixer_auto_chain: bool = True

    # AWS region for env2 + SSM RunCommand calls.
    aws_region: str = "us-east-1"

    # --- Image Hardening (separate feature; see app/services/image_hardening) ---
    # Core runtime config for the hardening pipeline. These are permanent
    # production settings (not test-only) — only the VALUES change per
    # environment. The registry can also be overridden per-request via the
    # trigger's target_registry (orchestrator._with_defaults); the setting is
    # the fallback/default. The build-instance id is the MVP/fallback path and
    # coexists with the future ephemeral-box seam (resolve_build_instance).
    hardening_build_instance_id: str = ""  # dedicated build EC2 (SSM-managed)
    hardening_ecr_repository_url: str = ""  # ECR repo URL (push target, no tag)
    hardening_sbom_bucket: str = ""  # S3 bucket for SBOM artifacts

    # --- HITL v2 Git-native review (Phase B, side experiment) ------------
    # All optional. When any of these are empty, the git-review flow is
    # simply unavailable — existing HITL v1 + sandbox review + auto-demo
    # keep working unchanged.
    #
    # github_pat        — fine-grained PAT with contents+pull-requests write
    # github_repo       — 'owner/name' the agent opens PRs against
    # github_base_branch — target branch for the PR (usually 'main')
    github_pat: str = ""
    github_repo: str = ""
    github_base_branch: str = "main"

    # --- GitHub App auth for image-hardening auto-sign dispatch -----------
    # Preferred over github_pat for programmatically dispatching the signing
    # workflow (short-lived installation tokens, no long-lived PAT). All
    # optional: when any is empty, auto-dispatch falls back to github_pat, and
    # if that is also empty, signing is skipped gracefully (dispatch manually).
    #
    # github_app_id                      — the App's numeric id
    # github_app_installation_id         — the installation id on the target repo
    # github_app_private_key_secret_arn  — AWS Secrets Manager ARN/name holding
    #   the App private key (.pem). The KEY VALUE is never in env/config — only
    #   this reference; the backend fetches it from Secrets Manager at dispatch.
    github_app_id: str = ""
    github_app_installation_id: str = ""
    github_app_private_key_secret_arn: str = ""

    # --- Secrets encryption ---
    # Base64-encoded 32-byte key for AES-256-GCM encryption of sensitive
    # scanner metadata (headers, body, credentials). REQUIRED for production.
    # Generate with: python -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
    secrets_encryption_key: str = ""

    # Which secrets backend to use. Currently only "local" (AES-256-GCM) is
    # supported. Future: "aws_secrets_manager", "hashicorp_vault".
    secrets_backend: str = "local"

    # Comma-separated list of metadata keys treated as sensitive (encrypted at
    # rest, redacted in API responses). Extend for custom credential fields.
    sensitive_metadata_fields: str = "headers,body,credentials"

    # Block saving auth headers against non-HTTPS endpoints. Set to "false"
    # only for local development.
    enforce_https_endpoints: bool = True

    # --- Intelligence Layer (DynamoDB) ---
    # DynamoDB table name for vulnerability intelligence lookups.
    # Pattern: sisyfix-{env}-vulnerability-intelligence
    intelligence_table_name: str = ""

    # AWS region for the intelligence DynamoDB table.
    intelligence_aws_region: str = "us-east-1"

    # Feature flag for gradual rollout of DynamoDB-backed lookups.
    # When False, falls back to direct NVD API calls.
    intelligence_enabled: bool = False

    # Threshold for cache misses before emitting CacheMissesLookupFailed metric.
    max_sync_cache_misses: int = 10

    # --- Ticketing integration ---
    # When true, approving a remediation package auto-creates a ticket in the
    # configured default provider. Requires at least one enabled row in
    # ticketing_connections. When false, tickets are only created via explicit
    # POST /admin/tickets/create or the per-package endpoint.
    ticketing_auto_create_on_approve: bool = False

    # Default ticketing provider slug used for auto-creation. Must match a
    # provider value in ticketing_connections (e.g. "jira", "servicenow",
    # "webhook"). Ignored when ticketing_auto_create_on_approve is False.
    ticketing_default_provider: str = ""

    # --- Jira settings (used when provider = "jira") ---
    # These can alternatively live in ticketing_connections.config per-row,
    # but env vars are convenient for single-instance setups.
    jira_base_url: str = ""  # e.g. https://yourcompany.atlassian.net
    jira_user_email: str = ""  # API token owner email
    jira_api_token: str = ""  # Atlassian API token
    jira_project_key: str = ""  # e.g. "SEC" or "VULN"

    # --- ServiceNow OAuth2 credentials (password grant) ---
    servicenow_client_id: str = ""
    servicenow_client_secret: str = ""

    # --- ServiceNow settings (used when provider = "servicenow") ---
    servicenow_instance_url: str = ""  # e.g. https://yourcompany.service-now.com
    servicenow_username: str = ""
    servicenow_password: str = ""
    servicenow_assignment_group: str = ""

    # --- Generic webhook (used when provider = "webhook") ---
    # Sends a JSON POST with ticket payload to this URL. Use for custom
    # integrations (Slack, Teams, PagerDuty, n8n, Zapier, etc.)
    ticketing_webhook_url: str = ""
    ticketing_webhook_secret: str = ""  # Optional HMAC-SHA256 signing secret

    # --- Schema isolation for local development ---
    # Postgres schema that supabase_admin() targets. Defaults to "public"
    # (production behavior). Set to "dev" in your local .env to route all
    # reads/writes to the isolated dev schema — zero agent code changes needed.
    # The "demo" pipeline is unaffected (supabase_admin_demo() stays hardcoded).
    db_schema: str = "public"


settings = Settings()
