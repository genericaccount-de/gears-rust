use toolkit::DatabaseCapability;

use super::*;

#[test]
fn gear_provides_exactly_one_p1_migration() {
    // The DatabaseCapability wiring must hand the runtime the P1 migration.
    // (init()/register_rest() need a live GearCtx — those seams are covered by
    // the E2E suite, not here.)
    let gear = FileStorageGear::default();
    assert_eq!(
        gear.migrations().len(),
        1,
        "M0 ships exactly one (P1 initial) migration"
    );
}
