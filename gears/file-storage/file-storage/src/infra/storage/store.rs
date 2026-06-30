//! Unit-of-work persistence facade — the single touch-point for `toolkit_db`.
//!
//! [`Store`] owns the `DBProvider`, the three tenant-scoped repositories, and
//! all connection-lifecycle / transaction logic. Nothing outside this module
//! needs to import `toolkit_db`, open a `conn()`, or call
//! `transaction_ref_mapped`.
//!
//! Intent-level methods mirror the operations the domain services need without
//! exposing `DBRunner`, `conn`, or `transaction_ref_mapped` to callers. The
//! bind and metadata-patch atomicity (DESIGN §3.7) are preserved verbatim —
//! the transaction code moved here unchanged from `service.rs`.
//!
//! ETag/If-Match semantics and the `AccessScope` decisions live here because
//! they are persistence concerns (which scope to use when querying each table),
//! not authorization decisions (those stay in `FileService`).

// Domain terms (ETag, If-Match) appear in the module docs.
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use time::OffsetDateTime;
use toolkit_db::{DBProvider, DbError};
use toolkit_security::AccessScope;
use uuid::Uuid;

use file_storage_sdk::{
    CustomMetadataEntry, CustomMetadataPatch, File, FileVersion, NewFile, OwnerFilter,
    VersionStatus,
};

use crate::domain::error::DomainError;
use crate::infra::content::hash;
use crate::infra::storage::db::db_err;
use crate::infra::storage::repo::{FileRepo, MetadataRepo, VersionRepo};

/// Persistence facade — the only type that holds `DBProvider` and drives
/// transactions. Cheap to clone (an `Arc` + three unit-struct repos).
#[allow(unknown_lints, de0309_must_have_domain_model)]
#[derive(Clone)]
pub struct Store {
    db: Arc<DBProvider<DbError>>,
    files: FileRepo,
    versions: VersionRepo,
    metadata: MetadataRepo,
}

impl Store {
    /// Construct a `Store` from the shared `DBProvider`.
    #[must_use]
    pub fn new(db: Arc<DBProvider<DbError>>) -> Self {
        Self {
            db,
            files: FileRepo::new(),
            versions: VersionRepo::new(),
            metadata: MetadataRepo::new(),
        }
    }

    // ── file queries ─────────────────────────────────────────────────────────

    /// Fetch a file by `(scope, file_id)`. Returns `None` when absent.
    pub async fn get_file(
        &self,
        scope: &AccessScope,
        file_id: Uuid,
    ) -> Result<Option<File>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.files.get(&conn, scope, file_id).await
    }

    /// Like [`get_file`] but errors with `FileNotFound` when absent.
    pub async fn require_file(
        &self,
        scope: &AccessScope,
        file_id: Uuid,
    ) -> Result<File, DomainError> {
        self.get_file(scope, file_id)
            .await?
            .ok_or_else(|| DomainError::file_not_found(file_id))
    }

    /// List files for an owner filter, newest-first, offset-paginated.
    pub async fn list_files(
        &self,
        scope: &AccessScope,
        owner: OwnerFilter,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<File>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.files.list(&conn, scope, owner, limit, offset).await
    }

    /// Delete a file row (FK cascade removes versions + custom metadata).
    /// Returns `true` if a row was removed.
    pub async fn delete_file(
        &self,
        scope: &AccessScope,
        file_id: Uuid,
    ) -> Result<bool, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.files.delete(&conn, scope, file_id).await
    }

    // ── create ───────────────────────────────────────────────────────────────

    /// Insert a new file row + a pending version row + any initial custom-
    /// metadata entries in ONE transaction, so a failure partway through cannot
    /// leave a visible file with no version (or partial metadata) behind.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_file_with_pending_version(
        &self,
        new: &NewFile,
        file_id: Uuid,
        version_id: Uuid,
        tenant_id: Uuid,
        backend_id: &str,
        backend_path: &str,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let file = File {
            file_id,
            tenant_id,
            owner_kind: new.owner_kind,
            owner_id: new.owner_id,
            name: new.name.clone(),
            gts_file_type: new.gts_file_type.clone(),
            content_id: None,
            meta_version: 0,
            created_at: now,
            last_modified_at: now,
        };
        let pending = pending_version(
            file_id,
            version_id,
            &new.mime_type,
            backend_id,
            backend_path,
            now,
        );
        // Own the initial metadata entries so the transaction closure can move them.
        let metadata_entries: Vec<(String, String)> = new
            .custom_metadata
            .iter()
            .map(|e| (e.key.clone(), e.value.clone()))
            .collect();

        let files = self.files.clone();
        let versions = self.versions.clone();
        let metadata = self.metadata.clone();
        self.db
            .db()
            .transaction_ref_mapped(move |tx| {
                Box::pin(async move {
                    files.create(tx, &AccessScope::allow_all(), &file).await?;
                    versions
                        .insert(tx, &AccessScope::allow_all(), &pending)
                        .await?;
                    for (key, value) in &metadata_entries {
                        metadata
                            .upsert(tx, &AccessScope::allow_all(), file_id, key, value, now)
                            .await?;
                    }
                    Ok::<(), DomainError>(())
                })
            })
            .await
    }

    // ── version management ───────────────────────────────────────────────────

    /// Insert a pending version row (for `presign_version`).
    pub async fn insert_pending_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        mime_type: &str,
        backend_id: &str,
        backend_path: &str,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        let pending = pending_version(
            file_id,
            version_id,
            mime_type,
            backend_id,
            backend_path,
            now,
        );
        self.versions
            .insert(&conn, &AccessScope::allow_all(), &pending)
            .await
    }

    /// Fetch a single version by `(file_id, version_id)`.
    pub async fn get_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
    ) -> Result<Option<FileVersion>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.versions
            .get(&conn, &AccessScope::allow_all(), file_id, version_id)
            .await
    }

    /// List all versions of a file, newest first.
    pub async fn list_versions(&self, file_id: Uuid) -> Result<Vec<FileVersion>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.versions
            .list_by_file(&conn, &AccessScope::allow_all(), file_id)
            .await
    }

    /// Return the MIME type of the file's current (bound) version, if any.
    /// `Ok(None)` means there is genuinely no bound content; a DB/connection
    /// failure is propagated as `Err` (never silently treated as "no mime").
    pub async fn current_version_mime(&self, file: &File) -> Result<Option<String>, DomainError> {
        let Some(content_id) = file.content_id else {
            return Ok(None);
        };
        Ok(self
            .get_version(file.file_id, content_id)
            .await?
            .map(|v| v.mime_type))
    }

    /// Record a version's size + hash and mark it `available`.
    /// Returns `true` if the version row existed and was updated.
    pub async fn finalize_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        size: i64,
        hash_value: Vec<u8>,
    ) -> Result<bool, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.versions
            .finalize(
                &conn,
                &AccessScope::allow_all(),
                file_id,
                version_id,
                size,
                hash_value,
            )
            .await
    }

    /// Delete a single version row.
    pub async fn delete_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
    ) -> Result<bool, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.versions
            .delete(&conn, &AccessScope::allow_all(), file_id, version_id)
            .await
    }

    // ── custom metadata ──────────────────────────────────────────────────────

    /// List all custom-metadata entries for a file, ordered by key.
    pub async fn list_metadata(
        &self,
        file_id: Uuid,
    ) -> Result<Vec<CustomMetadataEntry>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.metadata
            .list(&conn, &AccessScope::allow_all(), file_id)
            .await
    }

    // ── atomic multi-step operations ─────────────────────────────────────────

    /// Swap the content pointer + promote `version_id` as current, in a single
    /// transaction (the bind CAS — DESIGN §3.7).
    ///
    /// The `scope` used for the CAS update must be the authorized scope
    /// (returned by the authorizer); the `is_current` flip uses
    /// `allow_all()` because the version row has no tenant column and the
    /// parent file was already checked.
    ///
    /// Returns `true` on a successful swap, `false` on a concurrent CAS
    /// conflict (caller maps to 412 PreconditionFailed).
    pub async fn bind_atomic(
        &self,
        scope: &AccessScope,
        file_id: Uuid,
        expected_content_id: Option<Uuid>,
        version_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let files = self.files.clone();
        let versions = self.versions.clone();
        let bind_scope = scope.clone();
        self.db
            .db()
            .transaction_ref_mapped(move |tx| {
                Box::pin(async move {
                    let swapped = files
                        .bind_content_cas(
                            tx,
                            &bind_scope,
                            file_id,
                            expected_content_id,
                            version_id,
                            now,
                        )
                        .await?;
                    if !swapped {
                        return Ok(false);
                    }
                    // Promote the new version as current (unique-current index honoured).
                    versions
                        .clear_current(tx, &AccessScope::allow_all(), file_id)
                        .await?;
                    versions
                        .set_current(tx, &AccessScope::allow_all(), file_id, version_id)
                        .await?;
                    Ok::<bool, DomainError>(true)
                })
            })
            .await
    }

    /// Bump `meta_version` and apply a JSON-merge patch, in a single
    /// transaction (DESIGN §3.7 metadata CAS).
    ///
    /// Returns `false` when `expected_meta_version` does not match the current
    /// row (caller maps to 412 PreconditionFailed with "metadata revision
    /// changed concurrently").
    pub async fn patch_metadata_atomic(
        &self,
        scope: &AccessScope,
        file_id: Uuid,
        expected_meta_version: Option<i64>,
        patch: CustomMetadataPatch,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let files = self.files.clone();
        let metadata = self.metadata.clone();
        let patch_scope = scope.clone();
        self.db
            .db()
            .transaction_ref_mapped(move |tx| {
                Box::pin(async move {
                    let bumped = files
                        .touch_meta(tx, &patch_scope, file_id, expected_meta_version, now)
                        .await?;
                    if !bumped {
                        return Ok(false);
                    }
                    for (key, value) in &patch.entries {
                        match value {
                            Some(v) => {
                                metadata
                                    .upsert(tx, &AccessScope::allow_all(), file_id, key, v, now)
                                    .await?;
                            }
                            None => {
                                metadata
                                    .delete_key(tx, &AccessScope::allow_all(), file_id, key)
                                    .await?;
                            }
                        }
                    }
                    Ok::<bool, DomainError>(true)
                })
            })
            .await
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Build a `pending` version row with placeholder size/hash (filled at finalize).
fn pending_version(
    file_id: Uuid,
    version_id: Uuid,
    mime_type: &str,
    backend_id: &str,
    backend_path: &str,
    now: OffsetDateTime,
) -> FileVersion {
    FileVersion {
        file_id,
        version_id,
        mime_type: mime_type.to_owned(),
        size: 0,
        hash_algorithm: hash::ALGORITHM.to_owned(),
        // 32 zero bytes — satisfies the NOT NULL + length-32 CHECK until finalize.
        hash_value: vec![0u8; 32],
        status: VersionStatus::Pending,
        is_current: false,
        backend_id: backend_id.to_owned(),
        backend_path: backend_path.to_owned(),
        created_at: now,
    }
}
