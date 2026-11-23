CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL,
  theme_preference TEXT NOT NULL DEFAULT 'classic_red',
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS projects (
  project_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  summary TEXT NOT NULL,
  env_tier TEXT NOT NULL,
  llm_profile TEXT NOT NULL,
  stage_label TEXT NOT NULL,
  classification TEXT NOT NULL,
  whitelist_cidrs_json TEXT NOT NULL DEFAULT '[]',
  forbidden_cidrs_json TEXT NOT NULL DEFAULT '["192.168.1.250/32"]',
  enabled_extensions_json TEXT NOT NULL DEFAULT '["GENERAL"]',
  max_concurrency INTEGER NOT NULL DEFAULT 2,
  nuclei_rate_limit INTEGER NOT NULL DEFAULT 50,
  status TEXT NOT NULL DEFAULT 'active',
  started_at TEXT,
  archived_at TEXT,
  updated_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
  asset_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  host TEXT NOT NULL,
  security_zone TEXT NOT NULL,
  os_type TEXT NOT NULL,
  object_type TEXT NOT NULL DEFAULT 'host_os',
  scan_mode TEXT NOT NULL,
  scanners_json TEXT NOT NULL,
  ssh_port INTEGER NOT NULL DEFAULT 22,
  ssh_user TEXT NOT NULL DEFAULT '',
  ssh_auth_mode TEXT NOT NULL DEFAULT 'env_ref',
  ssh_secret_env TEXT NOT NULL DEFAULT '',
  ssh_key_env TEXT NOT NULL DEFAULT '',
  ssh_secret_encrypted TEXT NOT NULL DEFAULT '',
  is_enabled INTEGER NOT NULL DEFAULT 1,
  notes TEXT NOT NULL DEFAULT '',
  updated_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_jobs (
  job_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  project_name TEXT NOT NULL,
  env_tier TEXT NOT NULL,
  llm_profile TEXT NOT NULL,
  status TEXT NOT NULL,
  progress_pct INTEGER NOT NULL DEFAULT 0,
  current_stage TEXT NOT NULL DEFAULT '',
  started_at TEXT NOT NULL,
  finished_at TEXT,
  error_msg TEXT
);

CREATE TABLE IF NOT EXISTS job_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id TEXT NOT NULL,
  stage TEXT NOT NULL,
  message TEXT NOT NULL,
  progress_pct INTEGER NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS normalized_evidences (
  evidence_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  source_tool TEXT NOT NULL,
  evidence_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  cve_or_cwe TEXT,
  title TEXT NOT NULL,
  sanitized_detail_json TEXT NOT NULL,
  detected_by_json TEXT NOT NULL,
  origin TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS clause_assessments (
  assessment_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  clause_id TEXT NOT NULL,
  auto_status TEXT NOT NULL,
  manual_status TEXT,
  final_status TEXT NOT NULL,
  risk_level TEXT NOT NULL,
  is_high_risk INTEGER NOT NULL,
  evidence_ids_json TEXT NOT NULL,
  ai_rationale TEXT NOT NULL,
  remediation_script TEXT NOT NULL,
  compensation_status TEXT NOT NULL DEFAULT 'none',
  compensation_note TEXT NOT NULL DEFAULT '',
  reviewer TEXT,
  reviewed_at TEXT
);

CREATE TABLE IF NOT EXISTS attack_paths (
  path_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  steps_json TEXT NOT NULL,
  mitigation_priority TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sanitization_vault (
  vault_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL UNIQUE,
  encrypted_mapping_blob TEXT NOT NULL,
  leak_check_passed INTEGER NOT NULL,
  preview_json TEXT NOT NULL,
  approved_by TEXT,
  approved_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS llm_audit_logs (
  log_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  stage TEXT NOT NULL,
  model_id TEXT NOT NULL,
  prompt_tokens INTEGER NOT NULL DEFAULT 0,
  completion_tokens INTEGER NOT NULL DEFAULT 0,
  cached_tokens INTEGER NOT NULL DEFAULT 0,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  error_detail TEXT
);

CREATE TABLE IF NOT EXISTS reports (
  report_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  variant TEXT NOT NULL,
  filename TEXT NOT NULL,
  content_path TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS llm_profiles (
  profile_key TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  provider TEXT NOT NULL,
  is_cross_border INTEGER NOT NULL DEFAULT 0,
  allowed_env_tiers_json TEXT NOT NULL,
  fast_mapper_model TEXT NOT NULL,
  deep_reasoner_model TEXT NOT NULL,
  api_base TEXT NOT NULL DEFAULT '',
  proxy_env TEXT NOT NULL DEFAULT '',
  auth_mode TEXT NOT NULL DEFAULT 'env_ref',
  api_key_env TEXT NOT NULL DEFAULT '',
  api_key_encrypted TEXT NOT NULL DEFAULT '',
  enable_context_caching INTEGER NOT NULL DEFAULT 0,
  inject_block_none_safety INTEGER NOT NULL DEFAULT 0,
  is_enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS manual_evidence (
  evidence_doc_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  clause_id TEXT NOT NULL,
  filename TEXT NOT NULL,
  note TEXT NOT NULL,
  reviewer TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS project_integrations (
  project_id TEXT PRIMARY KEY,
  dojo_product_id TEXT,
  dojo_product_name TEXT,
  dojo_engagement_id TEXT,
  dojo_url TEXT,
  ciso_folder_id TEXT,
  ciso_perimeter_id TEXT,
  ciso_framework_id TEXT,
  ciso_assessment_id TEXT,
  ciso_url TEXT,
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS sync_records (
  sync_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  job_id TEXT,
  target TEXT NOT NULL,
  status TEXT NOT NULL,
  summary TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS system_prompts (
  prompt_key TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL DEFAULT 'system',
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS report_narratives (
  job_id TEXT PRIMARY KEY,
  prompt_key TEXT NOT NULL,
  prompt_version INTEGER NOT NULL DEFAULT 1,
  model_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'fallback',
  sections_json TEXT NOT NULL,
  generated_at TEXT NOT NULL
);
