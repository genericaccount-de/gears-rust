use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::ConnectionTrait;

/// Widens the `mcp_servers.auth_kind` CHECK constraint to allow
/// `'oauth2_auth_code'` (interactive per-user OAuth authorization-code flow).
///
/// The original constraint shipped in `m20260520_000006_add_mcp_tables` only
/// permitted `('none', 'bearer', 'api_key', 'oauth2')`. That migration was
/// later edited in place to include `'oauth2_auth_code'`, but such an edit
/// only affects freshly created databases — any database that had already
/// applied `m20260520_000006` keeps the old constraint, so seeding a server
/// with `auth_kind = 'oauth2_auth_code'` fails with a CHECK violation. This
/// forward migration fixes already-provisioned databases.
///
/// Postgres can alter the constraint in place. `SQLite` cannot alter a CHECK
/// constraint, so the table is rebuilt via the standard
/// create-copy-drop-rename procedure and its indexes are recreated.
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
        let backend = manager.get_database_backend();
        let conn = manager.get_connection();
        let sql = match backend {
            sea_orm::DatabaseBackend::Postgres => POSTGRES_DOWN,
            sea_orm::DatabaseBackend::Sqlite => SQLITE_DOWN,
            sea_orm::DatabaseBackend::MySql => {
                return Err(DbErr::Migration("MySQL not supported for mini-chat".into()));
            }
        };
        conn.execute_unprepared(sql).await?;
        Ok(())
    }
}

const POSTGRES_UP: &str = r"
ALTER TABLE mcp_servers DROP CONSTRAINT IF EXISTS mcp_servers_auth_kind_check;
ALTER TABLE mcp_servers ADD CONSTRAINT mcp_servers_auth_kind_check
    CHECK (auth_kind IN ('none', 'bearer', 'api_key', 'oauth2', 'oauth2_auth_code'));
";

const POSTGRES_DOWN: &str = r"
ALTER TABLE mcp_servers DROP CONSTRAINT IF EXISTS mcp_servers_auth_kind_check;
ALTER TABLE mcp_servers ADD CONSTRAINT mcp_servers_auth_kind_check
    CHECK (auth_kind IN ('none', 'bearer', 'api_key', 'oauth2'));
";

// SQLite cannot ALTER a CHECK constraint, so the table is rebuilt in place.
// Foreign keys from `mcp_server_tools` / `role_mcp_servers` reference
// `mcp_servers` by name and continue to resolve to the recreated table.
const SQLITE_UP: &str = r"
CREATE TABLE mcp_servers_new (
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
INSERT INTO mcp_servers_new SELECT * FROM mcp_servers;
DROP TABLE mcp_servers;
ALTER TABLE mcp_servers_new RENAME TO mcp_servers;
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_servers_tenant_ext
    ON mcp_servers (tenant_id, source, external_id)
    WHERE tenant_id IS NOT NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_servers_global_ext
    ON mcp_servers (source, external_id)
    WHERE tenant_id IS NULL AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_mcp_servers_tenant_enabled
    ON mcp_servers (tenant_id, enabled)
    WHERE deleted_at IS NULL;
";

const SQLITE_DOWN: &str = r"
CREATE TABLE mcp_servers_new (
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
                          CHECK (auth_kind IN ('none', 'bearer', 'api_key', 'oauth2')),
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
INSERT INTO mcp_servers_new SELECT * FROM mcp_servers;
DROP TABLE mcp_servers;
ALTER TABLE mcp_servers_new RENAME TO mcp_servers;
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_servers_tenant_ext
    ON mcp_servers (tenant_id, source, external_id)
    WHERE tenant_id IS NOT NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_servers_global_ext
    ON mcp_servers (source, external_id)
    WHERE tenant_id IS NULL AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_mcp_servers_tenant_enabled
    ON mcp_servers (tenant_id, enabled)
    WHERE deleted_at IS NULL;
";
