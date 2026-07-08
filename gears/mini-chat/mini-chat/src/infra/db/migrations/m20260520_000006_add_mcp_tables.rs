use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::ConnectionTrait;

/// Adds the MCP registry tables:
///
/// - `mcp_servers` — per-tenant or global (NULL tenant) MCP server registry.
///   Global rows are visible to all tenants; uniqueness is enforced with two
///   partial unique indexes because Postgres treats NULLs as distinct.
/// - `mcp_server_tools` — discovered tool metadata per server (read-through
///   cache backing store), cascade-deleted with the server.
/// - `role_mcp_servers` — per-tenant role → server attachments with optional
///   tool allow/deny and priority overrides.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        let conn = manager.get_connection();
        let sql = match backend {
            sea_orm::DatabaseBackend::Postgres => POSTGRES_UP,
            sea_orm::DatabaseBackend::Sqlite => SQLITE_UP,
            sea_orm::DatabaseBackend::MySql => {
                return Err(DbErr::Migration("MySQL not supported for mini-chat".into()));
            }
        };
        conn.execute_unprepared(sql).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared(DOWN).await?;
        Ok(())
    }
}

const DOWN: &str = r"
DROP TABLE IF EXISTS role_mcp_servers;
DROP TABLE IF EXISTS mcp_server_tools;
DROP TABLE IF EXISTS mcp_servers;
";

const POSTGRES_UP: &str = r"
-- 1. mcp_servers
CREATE TABLE IF NOT EXISTS mcp_servers (
    id                UUID PRIMARY KEY NOT NULL,
    tenant_id         UUID,
    source            VARCHAR(16) NOT NULL CHECK (source IN ('config', 'hub', 'api')),
    external_id       VARCHAR(255) NOT NULL,
    name              VARCHAR(255) NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    url               TEXT NOT NULL,
    enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    trust_level       VARCHAR(16) NOT NULL DEFAULT 'untrusted'
                          CHECK (trust_level IN ('trusted', 'restricted', 'untrusted')),
    auth_kind         VARCHAR(32) NOT NULL DEFAULT 'none'
                          CHECK (auth_kind IN ('none', 'bearer', 'api_key', 'oauth2', 'oauth2_auth_code')),
    auth_config       JSONB NOT NULL DEFAULT '{}',
    oagw_upstream_id  VARCHAR(64),
    priority          INT NOT NULL DEFAULT 100,
    allowed_tools     JSONB,
    denied_tools      JSONB,
    call_timeout_secs INT CHECK (call_timeout_secs IS NULL OR call_timeout_secs > 0),
    auto_attach       BOOLEAN NOT NULL DEFAULT FALSE,
    health_status     VARCHAR(16) NOT NULL DEFAULT 'unknown'
                          CHECK (health_status IN ('unknown', 'healthy', 'degraded', 'unhealthy')),
    last_refreshed_at TIMESTAMPTZ,
    last_error        TEXT,
    created_at        TIMESTAMPTZ NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL,
    deleted_at        TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_servers_tenant_ext
    ON mcp_servers (tenant_id, source, external_id)
    WHERE tenant_id IS NOT NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_servers_global_ext
    ON mcp_servers (source, external_id)
    WHERE tenant_id IS NULL AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_mcp_servers_tenant_enabled
    ON mcp_servers (tenant_id, enabled)
    WHERE deleted_at IS NULL;

-- 2. mcp_server_tools
CREATE TABLE IF NOT EXISTS mcp_server_tools (
    id            UUID PRIMARY KEY NOT NULL,
    server_id     UUID NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
    original_name VARCHAR(255) NOT NULL,
    exposed_name  VARCHAR(255) NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    input_schema  JSONB NOT NULL DEFAULT '{}',
    schema_hash   VARCHAR(64) NOT NULL,
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_server_tools_server_original
    ON mcp_server_tools (server_id, original_name);
CREATE INDEX IF NOT EXISTS idx_mcp_server_tools_server
    ON mcp_server_tools (server_id);

-- 3. role_mcp_servers
CREATE TABLE IF NOT EXISTS role_mcp_servers (
    id            UUID PRIMARY KEY NOT NULL,
    tenant_id     UUID NOT NULL,
    role          VARCHAR(255) NOT NULL,
    server_id     UUID NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    allowed_tools JSONB,
    denied_tools  JSONB,
    priority      INT,
    created_at    TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_role_mcp_servers_unique
    ON role_mcp_servers (tenant_id, role, server_id);
CREATE INDEX IF NOT EXISTS idx_role_mcp_servers_tenant_role
    ON role_mcp_servers (tenant_id, role)
    WHERE enabled = TRUE;
";

const SQLITE_UP: &str = r"
-- 1. mcp_servers
CREATE TABLE IF NOT EXISTS mcp_servers (
    id                TEXT PRIMARY KEY NOT NULL,
    tenant_id         TEXT,
    source            TEXT NOT NULL CHECK (source IN ('config', 'hub', 'api')),
    external_id       TEXT NOT NULL,
    name              TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    url               TEXT NOT NULL,
    enabled           INTEGER NOT NULL DEFAULT 1,
    trust_level       TEXT NOT NULL DEFAULT 'untrusted'
                          CHECK (trust_level IN ('trusted', 'restricted', 'untrusted')),
    auth_kind         TEXT NOT NULL DEFAULT 'none'
                          CHECK (auth_kind IN ('none', 'bearer', 'api_key', 'oauth2', 'oauth2_auth_code')),
    auth_config       TEXT NOT NULL DEFAULT '{}',
    oagw_upstream_id  TEXT,
    priority          INTEGER NOT NULL DEFAULT 100,
    allowed_tools     TEXT,
    denied_tools      TEXT,
    call_timeout_secs INTEGER CHECK (call_timeout_secs IS NULL OR call_timeout_secs > 0),
    auto_attach       INTEGER NOT NULL DEFAULT 0,
    health_status     TEXT NOT NULL DEFAULT 'unknown'
                          CHECK (health_status IN ('unknown', 'healthy', 'degraded', 'unhealthy')),
    last_refreshed_at TEXT,
    last_error        TEXT,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    deleted_at        TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_servers_tenant_ext
    ON mcp_servers (tenant_id, source, external_id)
    WHERE tenant_id IS NOT NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_servers_global_ext
    ON mcp_servers (source, external_id)
    WHERE tenant_id IS NULL AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_mcp_servers_tenant_enabled
    ON mcp_servers (tenant_id, enabled)
    WHERE deleted_at IS NULL;

-- 2. mcp_server_tools
CREATE TABLE IF NOT EXISTS mcp_server_tools (
    id            TEXT PRIMARY KEY NOT NULL,
    server_id     TEXT NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
    original_name TEXT NOT NULL,
    exposed_name  TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    input_schema  TEXT NOT NULL DEFAULT '{}',
    schema_hash   TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_server_tools_server_original
    ON mcp_server_tools (server_id, original_name);
CREATE INDEX IF NOT EXISTS idx_mcp_server_tools_server
    ON mcp_server_tools (server_id);

-- 3. role_mcp_servers
CREATE TABLE IF NOT EXISTS role_mcp_servers (
    id            TEXT PRIMARY KEY NOT NULL,
    tenant_id     TEXT NOT NULL,
    role          TEXT NOT NULL,
    server_id     TEXT NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
    enabled       INTEGER NOT NULL DEFAULT 1,
    allowed_tools TEXT,
    denied_tools  TEXT,
    priority      INTEGER,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_role_mcp_servers_unique
    ON role_mcp_servers (tenant_id, role, server_id);
CREATE INDEX IF NOT EXISTS idx_role_mcp_servers_tenant_role
    ON role_mcp_servers (tenant_id, role)
    WHERE enabled = 1;
";
