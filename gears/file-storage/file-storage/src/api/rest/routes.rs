//! Control-plane route registration via `OperationBuilder`
//! (`cpt-cf-file-storage-fr-rest-api`). This surface is JSON-only and never
//! carries file content — bytes move over signed URLs against the sidecar.

use std::sync::Arc;

use axum::Router;
use http::StatusCode;
use toolkit::api::OpenApiRegistry;
use toolkit::api::operation_builder::{LicenseFeature, OperationBuilder};

use super::dto;
use super::handlers;
use crate::domain::service::FileService;

const API_TAG: &str = "File Storage";
const BASE: &str = "/api/file-storage/v1";

pub(crate) struct License;

impl AsRef<str> for License {
    fn as_ref(&self) -> &'static str {
        "gts.cf.core.lic.feat.v1~cf.core.global.base.v1"
    }
}

impl LicenseFeature for License {}

/// Register all file-storage control-plane routes and attach the service.
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
pub(crate) fn register_routes(
    mut router: Router,
    openapi: &dyn OpenApiRegistry,
    service: Arc<FileService>,
) -> Router {
    // POST /files — create + presign upload
    router = OperationBuilder::post(format!("{BASE}/files"))
        .operation_id("file_storage.create_file")
        .authenticated()
        .require_license_features::<License>([])
        .summary("Create a file and presign its first content upload")
        .tag(API_TAG)
        .json_request::<dto::CreateFileReq>(openapi, "File metadata")
        .handler(handlers::create_file)
        .json_response_with_schema::<dto::UploadTicketDto>(openapi, StatusCode::CREATED, "Created")
        .error_400(openapi)
        .error_401(openapi)
        .error_403(openapi)
        .error_500(openapi)
        .register(router, openapi);

    // POST /files/{id}/versions — presign a new version
    router = OperationBuilder::post(format!("{BASE}/files/{{id}}/versions"))
        .operation_id("file_storage.presign_version")
        .authenticated()
        .require_license_features::<License>([])
        .summary("Presign a new content version upload")
        .tag(API_TAG)
        .path_param("id", "File UUID")
        .handler(handlers::presign_version)
        .json_response_with_schema::<dto::UploadTicketDto>(openapi, StatusCode::OK, "Presigned")
        .error_401(openapi)
        .error_403(openapi)
        .error_404(openapi)
        .error_500(openapi)
        .register(router, openapi);

    // POST /files/{id}/bind — bind/rebind content pointer (If-Match)
    router = OperationBuilder::post(format!("{BASE}/files/{{id}}/bind"))
        .operation_id("file_storage.bind")
        .authenticated()
        .require_license_features::<License>([])
        .summary("Bind/rebind the content pointer under optimistic CAS")
        .description("If-Match carries the current content ETag; 412 on conflict.")
        .tag(API_TAG)
        .path_param("id", "File UUID")
        .json_request::<dto::BindReq>(openapi, "Version to bind")
        .handler(handlers::bind)
        .json_response_with_schema::<dto::FileDto>(openapi, StatusCode::OK, "Bound")
        .error_401(openapi)
        .error_403(openapi)
        .error_404(openapi)
        // 409: the target version's upload is not finalized yet.
        .error_409(openapi)
        // 412: the If-Match / CAS precondition failed (or is required and absent).
        .problem_response(
            openapi,
            StatusCode::PRECONDITION_FAILED,
            "Precondition Failed",
        )
        .error_500(openapi)
        .register(router, openapi);

    // GET /files/{id}/download-url — issue a signed download URL
    router = OperationBuilder::get(format!("{BASE}/files/{{id}}/download-url"))
        .operation_id("file_storage.download_url")
        .authenticated()
        .require_license_features::<License>([])
        .summary("Issue a signed download URL (pins current content or ?version_id)")
        .tag(API_TAG)
        .path_param("id", "File UUID")
        .query_param("version_id", false, "Pin a specific version")
        .handler(handlers::download_url)
        .json_response_with_schema::<dto::DownloadTicketDto>(openapi, StatusCode::OK, "Signed URL")
        .error_401(openapi)
        .error_403(openapi)
        .error_404(openapi)
        .error_500(openapi)
        .register(router, openapi);

    // GET /files/{id}/versions — list versions
    router = OperationBuilder::get(format!("{BASE}/files/{{id}}/versions"))
        .operation_id("file_storage.list_versions")
        .authenticated()
        .require_license_features::<License>([])
        .summary("List all versions of a file")
        .tag(API_TAG)
        .path_param("id", "File UUID")
        .handler(handlers::list_versions)
        .json_response_with_schema::<Vec<dto::VersionDto>>(openapi, StatusCode::OK, "Versions")
        .error_401(openapi)
        .error_403(openapi)
        .error_404(openapi)
        .error_500(openapi)
        .register(router, openapi);

    // DELETE /files/{id}/versions/{version_id} — delete a version
    router = OperationBuilder::delete(format!("{BASE}/files/{{id}}/versions/{{version_id}}"))
        .operation_id("file_storage.delete_version")
        .authenticated()
        .require_license_features::<License>([])
        .summary("Delete a single version")
        .tag(API_TAG)
        .path_param("id", "File UUID")
        .path_param("version_id", "Version UUID")
        .handler(handlers::delete_version)
        .json_response(StatusCode::NO_CONTENT, "Deleted")
        .error_401(openapi)
        .error_403(openapi)
        .error_404(openapi)
        .error_409(openapi)
        .error_500(openapi)
        .register(router, openapi);

    // GET /files/{id} — metadata (conditional)
    router = OperationBuilder::get(format!("{BASE}/files/{{id}}"))
        .operation_id("file_storage.get_file")
        .authenticated()
        .require_license_features::<License>([])
        .summary("Get file metadata (supports If-None-Match -> 304)")
        .tag(API_TAG)
        .path_param("id", "File UUID")
        .handler(handlers::get_file)
        .json_response_with_schema::<dto::FileDto>(openapi, StatusCode::OK, "File metadata")
        .error_401(openapi)
        .error_403(openapi)
        .error_404(openapi)
        .error_500(openapi)
        .register(router, openapi);

    // PATCH /files/{id} — update custom metadata (If-Match-Metadata)
    router = OperationBuilder::patch(format!("{BASE}/files/{{id}}"))
        .operation_id("file_storage.update_metadata")
        .authenticated()
        .require_license_features::<License>([])
        .summary("Update custom metadata (JSON merge patch)")
        .tag(API_TAG)
        .path_param("id", "File UUID")
        .json_request::<dto::UpdateMetadataReq>(openapi, "Metadata merge patch")
        .handler(handlers::update_metadata)
        .json_response_with_schema::<dto::FileDto>(openapi, StatusCode::OK, "Updated")
        .error_400(openapi)
        .error_401(openapi)
        .error_403(openapi)
        .error_404(openapi)
        .error_409(openapi)
        .error_500(openapi)
        .register(router, openapi);

    // DELETE /files/{id} — delete file + all versions (If-Match required)
    router = OperationBuilder::delete(format!("{BASE}/files/{{id}}"))
        .operation_id("file_storage.delete_file")
        .authenticated()
        .require_license_features::<License>([])
        .summary("Delete a file and all its versions")
        .description(
            "If-Match (content ETag or \"*\") is required; 412 on mismatch or when absent.",
        )
        .tag(API_TAG)
        .path_param("id", "File UUID")
        .handler(handlers::delete_file)
        .json_response(StatusCode::NO_CONTENT, "Deleted")
        .error_401(openapi)
        .error_403(openapi)
        .error_404(openapi)
        // 412: If-Match absent or does not match the current content ETag.
        .problem_response(
            openapi,
            StatusCode::PRECONDITION_FAILED,
            "Precondition Failed",
        )
        .error_500(openapi)
        .register(router, openapi);

    // GET /files — list (mandatory owner filter, offset pagination)
    router = OperationBuilder::get(format!("{BASE}/files"))
        .operation_id("file_storage.list_files")
        .authenticated()
        .require_license_features::<License>([])
        .summary("List files for an owner (owner_kind + owner_id required)")
        .tag(API_TAG)
        .query_param("owner_kind", true, "'user' or 'app'")
        .query_param("owner_id", true, "Owner UUID")
        .query_param_typed("limit", false, "Page size", "integer")
        .query_param_typed("offset", false, "Offset", "integer")
        .handler(handlers::list_files)
        .json_response_with_schema::<Vec<dto::FileDto>>(openapi, StatusCode::OK, "Files")
        .error_400(openapi)
        .error_401(openapi)
        .error_403(openapi)
        .error_500(openapi)
        .register(router, openapi);

    // GET /storages — backend discovery
    router = OperationBuilder::get(format!("{BASE}/storages"))
        .operation_id("file_storage.list_storages")
        .authenticated()
        .require_license_features::<License>([])
        .summary("List configured storage backends and capabilities")
        .tag(API_TAG)
        .handler(handlers::list_storages)
        .json_response_with_schema::<Vec<dto::StorageDto>>(openapi, StatusCode::OK, "Backends")
        .error_401(openapi)
        .error_403(openapi)
        .error_500(openapi)
        .register(router, openapi);

    // GET /storages/{id} — one backend
    router = OperationBuilder::get(format!("{BASE}/storages/{{id}}"))
        .operation_id("file_storage.get_storage")
        .authenticated()
        .require_license_features::<License>([])
        .summary("Get one storage backend")
        .tag(API_TAG)
        .path_param("id", "Backend id")
        .handler(handlers::get_storage)
        .json_response_with_schema::<dto::StorageDto>(openapi, StatusCode::OK, "Backend")
        .error_401(openapi)
        .error_403(openapi)
        .error_404(openapi)
        .error_500(openapi)
        .register(router, openapi);

    router.layer(axum::Extension(service))
}
