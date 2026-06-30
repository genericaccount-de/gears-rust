//! Tenant-scoped repositories (`SecureORM`) for the control-plane metadata.
//!
//! All access goes through the `toolkit_db::secure` extension API, which takes a
//! `DBRunner` connection and an `AccessScope`. Tenant isolation is enforced
//! on the `files` table (`cpt-cf-file-storage-fr-tenant-boundary`); version and
//! custom-metadata rows are reached only after the parent file is authorized, so
//! they use an unconstrained scope on their `file_id`-keyed queries.

mod file_repo;
mod metadata_repo;
mod version_repo;

pub use file_repo::FileRepo;
pub use metadata_repo::MetadataRepo;
pub use version_repo::VersionRepo;
