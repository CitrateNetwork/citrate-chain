// The node's start-up path: resolve the activation height for the CONFIGURED
// chain id (release pin, then env override, then config) and publish it
// process-wide. Its own test binary, because it sets process env and the
// process-wide height.

use citrate_consensus::hardening::{
    init_pba_hardening_for_chain, pba_hardening_height, pinned_activation,
    set_pba_hardening_height, ActivationSource, PBA_HARDENING_ENV,
};

#[test]
fn start_up_resolution_publishes_the_resolved_height() {
    // A chain with no release pin keeps the legacy order.
    let chain = 1_337;
    assert_eq!(pinned_activation(chain), None);

    std::env::remove_var(PBA_HARDENING_ENV);
    let r = init_pba_hardening_for_chain(chain, Some(42), false).expect("config value");
    assert_eq!((r.height, r.source), (Some(42), ActivationSource::Config));
    assert_eq!(pba_hardening_height(), Some(42));

    std::env::set_var(PBA_HARDENING_ENV, "7");
    let r = init_pba_hardening_for_chain(chain, Some(42), false).expect("env override");
    assert_eq!((r.height, r.source), (Some(7), ActivationSource::Env));
    assert_eq!(pba_hardening_height(), Some(7));

    // A bad override aborts and publishes nothing new.
    std::env::set_var(PBA_HARDENING_ENV, "soon");
    assert!(init_pba_hardening_for_chain(chain, Some(42), false).is_err());
    assert_eq!(pba_hardening_height(), Some(7));

    std::env::remove_var(PBA_HARDENING_ENV);
    let r = init_pba_hardening_for_chain(chain, None, false).expect("unset");
    assert_eq!((r.height, r.source), (None, ActivationSource::Unset));
    assert_eq!(pba_hardening_height(), None);

    // 40204 resolves through its release pin entry. Unset: the legacy order.
    // Pinned (the owner's release step): the pin wins and a conflicting
    // config value is refused.
    match pinned_activation(40204) {
        None => {
            let r = init_pba_hardening_for_chain(40204, Some(9), false).expect("40204");
            assert_eq!((r.height, r.source), (Some(9), ActivationSource::Config));
        }
        Some(p) => {
            let r = init_pba_hardening_for_chain(40204, None, false).expect("40204 pin");
            assert_eq!(
                (r.height, r.source),
                (Some(p), ActivationSource::ReleasePin)
            );
            let other = p.wrapping_add(1);
            assert!(init_pba_hardening_for_chain(40204, Some(other), false).is_err());
            // A dev profile on the same chain id keeps its own value.
            let r = init_pba_hardening_for_chain(40204, Some(0), true).expect("dev");
            assert_eq!(r.height, Some(0));
        }
    }
    set_pba_hardening_height(None);
}
