//! Print the r1006 genesis hash the compiled profile builds, and what it still waits for.
//! Used by scripts/genesis/r1006/fill_producers.py to pin R1006_GENESIS.
use citrate_economics::genesis::GenesisConfig;
use citrate_economics::r1006;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = GenesisConfig::r1006()?;
    let h = r1006::genesis_block_hash(&cfg)?;
    println!("R1006_GENESIS=0x{}", hex::encode(h));
    let r = r1006::readiness()?;
    println!("release_ready={}", r.is_release_ready());
    for m in r.missing() {
        println!("missing: {m}");
    }
    Ok(())
}
