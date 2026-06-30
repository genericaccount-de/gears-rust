//! REST DTOs for the control-plane API. These are the only types that carry
//! serde/utoipa; the contract types in the SDK stay transport-agnostic.

use std::collections::BTreeMap;

use time::OffsetDateTime;
use uuid::Uuid;

use file_storage_sdk::{CustomMetadataEntry, File, FileVersion, OwnerKind};

use crate::domain::etag;
use crate::infra::backend::BackendCapabilities;

/// One custom-metadata key/value pair.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(request, response)]
pub struct MetadataEntryDto {
    pub key: String,
    pub value: String,
}

/// File metadata response (`GET /files/{id}`, and the body of mutations).
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct FileDto {
    pub file_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_kind: String,
    pub owner_id: Uuid,
    pub name: String,
    pub gts_file_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_id: Option<Uuid>,
    pub meta_version: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified_at: OffsetDateTime,
    pub custom_metadata: Vec<MetadataEntryDto>,
}

impl FileDto {
    #[must_use]
    pub fn from_parts(file: File, meta: Vec<CustomMetadataEntry>) -> Self {
        let etag = etag::etag_for(&file);
        Self {
            file_id: file.file_id,
            tenant_id: file.tenant_id,
            owner_kind: file.owner_kind.as_str().to_owned(),
            owner_id: file.owner_id,
            name: file.name,
            gts_file_type: file.gts_file_type,
            content_id: file.content_id,
            meta_version: file.meta_version,
            etag,
            created_at: file.created_at,
            last_modified_at: file.last_modified_at,
            custom_metadata: meta
                .into_iter()
                .map(|e| MetadataEntryDto {
                    key: e.key,
                    value: e.value,
                })
                .collect(),
        }
    }
}

/// Request to create a file (`POST /files`).
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(request)]
pub struct CreateFileReq {
    /// `"user"` or `"app"`.
    pub owner_kind: String,
    pub owner_id: Uuid,
    pub name: String,
    pub gts_file_type: String,
    pub mime_type: String,
    #[serde(default)]
    pub custom_metadata: Vec<MetadataEntryDto>,
}

impl CreateFileReq {
    /// Parse the owner kind, rejecting unknown spellings.
    #[must_use]
    pub fn parse_owner_kind(&self) -> Option<OwnerKind> {
        OwnerKind::parse(&self.owner_kind)
    }
}

/// Result of create / presign: identity + the signed upload URL.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct UploadTicketDto {
    pub file_id: Uuid,
    pub version_id: Uuid,
    pub upload_url: String,
}

/// Result of `GET /files/{id}/download-url`.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct DownloadTicketDto {
    pub download_url: String,
    pub etag: String,
    pub version_id: Uuid,
}

/// Request body for `POST /files/{id}/bind`.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(request)]
pub struct BindReq {
    pub version_id: Uuid,
}

/// Request body for `PATCH /files/{id}` (JSON merge patch over custom metadata).
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(request)]
pub struct UpdateMetadataReq {
    /// Keys mapped to a value (upsert) or `null` (delete). Absent keys unchanged.
    #[serde(default)]
    pub custom_metadata: BTreeMap<String, Option<String>>,
}

/// One content version (`GET /files/{id}/versions`).
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct VersionDto {
    pub version_id: Uuid,
    pub mime_type: String,
    pub size: i64,
    pub hash_algorithm: String,
    pub hash: String,
    pub status: String,
    pub is_current: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl From<FileVersion> for VersionDto {
    fn from(v: FileVersion) -> Self {
        Self {
            version_id: v.version_id,
            mime_type: v.mime_type,
            size: v.size,
            hash_algorithm: v.hash_algorithm,
            hash: hex::encode(&v.hash_value),
            status: v.status.as_str().to_owned(),
            is_current: v.is_current,
            created_at: v.created_at,
        }
    }
}

/// Backend capabilities surface for `GET /storages`.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct CapabilitiesDto {
    pub multipart_native: bool,
    pub encryption_native: bool,
    pub range_native: bool,
}

impl From<BackendCapabilities> for CapabilitiesDto {
    fn from(c: BackendCapabilities) -> Self {
        Self {
            multipart_native: c.multipart_native,
            encryption_native: c.encryption_native,
            range_native: c.range_native,
        }
    }
}

/// A configured storage backend (`GET /storages`).
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct StorageDto {
    pub id: String,
    pub capabilities: CapabilitiesDto,
}

impl StorageDto {
    #[must_use]
    pub fn new(id: String, capabilities: BackendCapabilities) -> Self {
        Self {
            id,
            capabilities: capabilities.into(),
        }
    }
}
