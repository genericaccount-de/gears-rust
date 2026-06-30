//! Database migration registry for the file-storage gear.

use sea_orm_migration::prelude::*;

mod m20260624_000001_p1_initial;

/// File-storage migrator. P1 ships a single initial migration creating the
/// control-plane metadata tables; P2/P3 tables are added as later migrations.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(m20260624_000001_p1_initial::Migration)]
    }
}
