//! Print the r1007 genesis hash the compiled profile builds under the MPT state root rule
//! (the ceremony step of docs/consensus/STATE_ROOT_MPT.md §1, step 3), and what it still
//! waits for. Re-pin `citrate_consensus::hardening::R1007_GENESIS` from its output.
use citrate_economics::r1007;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let h = r1007::compute_genesis_hash_for_ceremony()?;
    println!("R1007_GENESIS=0x{}", hex::encode(h));
    println!(
        "pinned=0x{}",
        hex::encode(citrate_consensus::hardening::R1007_GENESIS)
    );
    let r = r1007::readiness()?;
    println!("release_ready={}", r.is_release_ready());
    for m in r.missing() {
        println!("missing: {m}");
    }
    Ok(())
}
