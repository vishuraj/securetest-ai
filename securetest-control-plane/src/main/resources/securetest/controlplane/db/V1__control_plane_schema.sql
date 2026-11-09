-- SecureTest AI control plane schema (SRS 12).
-- Portable SQL: runs on PostgreSQL 14+ (production) and H2 in PostgreSQL mode (tests).
-- Every tenant-owned row carries tenant_id; every query in the application filters on it.
-- JSON documents are stored as TEXT so the schema stays portable; ids are UUID strings.

CREATE TABLE tenant (
    id          VARCHAR(36)  PRIMARY KEY,
    slug        VARCHAR(64)  NOT NULL UNIQUE,
    name        VARCHAR(200) NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE organization (
    id          VARCHAR(36)  PRIMARY KEY,
    tenant_id   VARCHAR(36)  NOT NULL REFERENCES tenant(id),
    name        VARCHAR(200) NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_organization_name UNIQUE (tenant_id, name)
);

CREATE TABLE project (
    id              VARCHAR(36)  PRIMARY KEY,
    tenant_id       VARCHAR(36)  NOT NULL REFERENCES tenant(id),
    organization_id VARCHAR(36)  NOT NULL REFERENCES organization(id),
    name            VARCHAR(200) NOT NULL,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_project_name UNIQUE (organization_id, name)
);

CREATE TABLE application (
    id          VARCHAR(36)  PRIMARY KEY,
    tenant_id   VARCHAR(36)  NOT NULL REFERENCES tenant(id),
    project_id  VARCHAR(36)  NOT NULL REFERENCES project(id),
    service_id  VARCHAR(200) NOT NULL,
    name        VARCHAR(200) NOT NULL,
    criticality VARCHAR(20),
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_application_service UNIQUE (tenant_id, service_id)
);

CREATE TABLE environment (
    id             VARCHAR(36)  PRIMARY KEY,
    tenant_id      VARCHAR(36)  NOT NULL REFERENCES tenant(id),
    application_id VARCHAR(36)  NOT NULL REFERENCES application(id),
    name           VARCHAR(100) NOT NULL,
    production     BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_environment_name UNIQUE (application_id, name)
);

-- Opaque enrollment tokens used by embedded agents; only the SHA-256 hash is stored.
CREATE TABLE enrollment_token (
    id          VARCHAR(36)  PRIMARY KEY,
    tenant_id   VARCHAR(36)  NOT NULL REFERENCES tenant(id),
    token_hash  VARCHAR(64)  NOT NULL UNIQUE,
    description VARCHAR(200),
    created_by  VARCHAR(200),
    created_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked     BOOLEAN      NOT NULL DEFAULT FALSE
);

CREATE TABLE agent_registration (
    id                VARCHAR(36)  PRIMARY KEY,
    tenant_id         VARCHAR(36)  NOT NULL REFERENCES tenant(id),
    application_id    VARCHAR(36)  NOT NULL REFERENCES application(id),
    environment_id    VARCHAR(36)  NOT NULL REFERENCES environment(id),
    agent_version     VARCHAR(50),
    app_version       VARCHAR(100),
    runtime_json      TEXT,
    capabilities_json TEXT,
    remote_address    VARCHAR(100),
    first_seen        TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen         TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_agent_app_env UNIQUE (application_id, environment_id)
);

-- Remote workers (platform-operated fleet shared by all tenants).
CREATE TABLE worker (
    id            VARCHAR(100) PRIMARY KEY,
    name          VARCHAR(200),
    version       VARCHAR(50),
    sandbox       VARCHAR(50),
    scanners_json TEXT,
    first_seen    TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen     TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE scan_job (
    id                   VARCHAR(36)  PRIMARY KEY,
    tenant_id            VARCHAR(36)  NOT NULL REFERENCES tenant(id),
    application_id       VARCHAR(36)  NOT NULL REFERENCES application(id),
    environment_id       VARCHAR(36)  NOT NULL REFERENCES environment(id),
    scanner_id           VARCHAR(100) NOT NULL,
    module_id            VARCHAR(100),
    target_url           VARCHAR(2000),
    options_json         TEXT,
    status               VARCHAR(30)  NOT NULL,
    requested_by         VARCHAR(200),
    idempotency_key      VARCHAR(200),
    worker_id            VARCHAR(100),
    attempts             INTEGER      NOT NULL DEFAULT 0,
    max_attempts         INTEGER      NOT NULL DEFAULT 3,
    lease_until          TIMESTAMP WITH TIME ZONE,
    cancel_requested     BOOLEAN      NOT NULL DEFAULT FALSE,
    progress             INTEGER      NOT NULL DEFAULT 0,
    progress_message     VARCHAR(500),
    findings_count       INTEGER      NOT NULL DEFAULT 0,
    severity_counts_json TEXT,
    results_json         TEXT,
    log_text             TEXT,
    error                VARCHAR(2000),
    created_at           TIMESTAMP WITH TIME ZONE NOT NULL,
    started_at           TIMESTAMP WITH TIME ZONE,
    ended_at             TIMESTAMP WITH TIME ZONE,
    CONSTRAINT uq_scan_job_idempotency UNIQUE (tenant_id, idempotency_key)
);
CREATE INDEX ix_scan_job_queue ON scan_job (status, scanner_id, created_at);
CREATE INDEX ix_scan_job_tenant ON scan_job (tenant_id, created_at);

CREATE TABLE finding (
    id              VARCHAR(36)  PRIMARY KEY,
    tenant_id       VARCHAR(36)  NOT NULL REFERENCES tenant(id),
    application_id  VARCHAR(36)  NOT NULL REFERENCES application(id),
    environment_id  VARCHAR(36)  NOT NULL REFERENCES environment(id),
    fingerprint     VARCHAR(128) NOT NULL,
    module_id       VARCHAR(100),
    source          VARCHAR(100),
    rule_id         VARCHAR(200),
    category        VARCHAR(200),
    title           VARCHAR(1000) NOT NULL,
    source_severity VARCHAR(20)  NOT NULL,
    priority        VARCHAR(20)  NOT NULL,
    confidence      VARCHAR(20),
    status          VARCHAR(30)  NOT NULL,
    asset           VARCHAR(1000),
    file_path       VARCHAR(1000),
    line_start      INTEGER,
    first_detected  TIMESTAMP WITH TIME ZONE NOT NULL,
    last_detected   TIMESTAMP WITH TIME ZONE NOT NULL,
    last_scan_id    VARCHAR(36),
    occurrences     INTEGER      NOT NULL DEFAULT 1,
    payload_json    TEXT         NOT NULL,
    CONSTRAINT uq_finding_fingerprint UNIQUE (tenant_id, application_id, environment_id, fingerprint)
);
CREATE INDEX ix_finding_tenant ON finding (tenant_id, status, priority);

CREATE TABLE report (
    id             VARCHAR(36)  PRIMARY KEY,
    tenant_id      VARCHAR(36)  NOT NULL REFERENCES tenant(id),
    application_id VARCHAR(36)  REFERENCES application(id),
    format         VARCHAR(10)  NOT NULL,
    title          VARCHAR(300) NOT NULL,
    findings_count INTEGER      NOT NULL,
    sha256         VARCHAR(64)  NOT NULL,
    content        BYTEA        NOT NULL,
    created_by     VARCHAR(200),
    created_at     TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX ix_report_tenant ON report (tenant_id, created_at);

-- Append-only, hash-chained per tenant (SRS 9.5). tenant_id is NULL for platform-level events.
CREATE TABLE audit_event (
    seq         BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    id          VARCHAR(36)  NOT NULL UNIQUE,
    tenant_id   VARCHAR(36),
    occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
    actor       VARCHAR(200) NOT NULL,
    action      VARCHAR(100) NOT NULL,
    target      VARCHAR(500),
    detail      VARCHAR(2000),
    prev_hash   VARCHAR(64),
    hash        VARCHAR(64)  NOT NULL
);
CREATE INDEX ix_audit_tenant ON audit_event (tenant_id, seq);
