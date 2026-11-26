//! The product write gate ([D-025] item 4, W323, W356, [D-029]).
//!
//! While the gate is closed, a product capture refuses with
//! `NOT_ADMITTED_FOR_EFFECT` right after the admin helper re-binds the
//! journaled projection digest, before any store check, secret read,
//! network use, dump or restic start. The worker's `backup` action checks
//! the same constant before it opens a session.
//!
//! D-029 option B opens the gate in every product build
//! (`--cfg rustiron_profile="product"`, as `packaging/stage-product.sh`
//! sets it). The lab build keeps it closed, so the lab profile cannot run
//! the product write path. The lab write-proof flag that opened the gate
//! for the D-025 proofs is retired: the product profile alone now decides.
//!
//! [D-025]: ../../../docs/decisions/D-025-product-capture-effects.md
//! [D-029]: ../../../docs/decisions/D-029-product-write-gate.md

/// Whether the product capture may write a snapshot.
pub const PRODUCT_WRITES_ENABLED: bool = cfg!(rustiron_profile = "product");

#[cfg(test)]
mod tests {
    use super::PRODUCT_WRITES_ENABLED;

    #[test]
    fn only_the_product_profile_opens_the_gate() {
        assert_eq!(
            std::hint::black_box(PRODUCT_WRITES_ENABLED),
            cfg!(rustiron_profile = "product"),
        );
    }

    #[cfg(not(rustiron_profile = "product"))]
    #[test]
    fn the_lab_profile_keeps_the_gate_closed() {
        assert!(!std::hint::black_box(PRODUCT_WRITES_ENABLED));
    }
}
