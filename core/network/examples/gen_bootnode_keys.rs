//! gen_bootnode_keys — pre-generate Noise keypairs for bootnodes
//!
//! Generates N (default 3) NoiseKeypair instances, writes each to
//! `<OUT_DIR>/boot<i>.noise.key` (64 bytes, private || public), and prints
//! the derived peer IDs in a format suitable for pasting into a node config's
//! `bootstrap_nodes = [...]` list.
//!
//! Usage:
//!
//!     cargo run --release --example gen_bootnode_keys -p citrate-network -- \
//!         --count 3 --out-dir ./tools/bootnode-keys --host-template boot{i}.citrate.network --port 30303
//!
//! The keys are the EXACT same format the production code generates and reads
//! (`<data_dir>/noise.key`). Upload `boot<i>.noise.key` to droplet `i` as
//! `/home/citrate/.citrate/noise.key` BEFORE the first citrate-node start —
//! the node will load the pre-placed key instead of generating a fresh one,
//! and its peer ID will match what the partner-shipped config has baked in.

use citrate_network::NoiseKeypair;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

struct Args {
    count: usize,
    out_dir: PathBuf,
    host_template: String,
    port: u16,
}

fn parse_args() -> Result<Args, String> {
    let mut count: usize = 3;
    let mut out_dir = PathBuf::from("./tools/bootnode-keys");
    let mut host_template = String::from("boot{i}.citrate.network");
    let mut port: u16 = 30303;

    let mut it = env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--count" => {
                count = it
                    .next()
                    .ok_or("missing value for --count")?
                    .parse()
                    .map_err(|e| format!("--count: {e}"))?;
            }
            "--out-dir" => {
                out_dir = PathBuf::from(it.next().ok_or("missing value for --out-dir")?);
            }
            "--host-template" => {
                host_template = it.next().ok_or("missing value for --host-template")?;
            }
            "--port" => {
                port = it
                    .next()
                    .ok_or("missing value for --port")?
                    .parse()
                    .map_err(|e| format!("--port: {e}"))?;
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if count == 0 || count > 32 {
        return Err(format!("--count must be in 1..=32 (got {count})"));
    }
    Ok(Args {
        count,
        out_dir,
        host_template,
        port,
    })
}

fn print_usage() {
    eprintln!(
        "Usage: gen_bootnode_keys [--count N] [--out-dir PATH] [--host-template TPL] [--port P]\n\
         Defaults: --count 3 --out-dir ./tools/bootnode-keys --host-template boot{{i}}.citrate.network --port 30303\n\
         {{i}} in --host-template is replaced with 1..=N."
    );
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n");
            print_usage();
            return ExitCode::from(1);
        }
    };

    if let Err(e) = fs::create_dir_all(&args.out_dir) {
        eprintln!("error: create_dir_all {:?}: {e}", args.out_dir);
        return ExitCode::from(1);
    }

    println!("# Generated {} Noise keypairs", args.count);
    println!("# Out dir: {}", args.out_dir.display());
    println!();
    println!("# Paste into node config's bootstrap_nodes = [...]:");
    println!("bootstrap_nodes = [");

    for i in 1..=args.count {
        let kp = NoiseKeypair::generate();
        let peer_id = kp.derive_peer_id();
        let host = args.host_template.replace("{i}", &i.to_string());
        let key_path = args.out_dir.join(format!("boot{i}.noise.key"));

        if let Err(e) = fs::write(&key_path, kp.to_bytes()) {
            eprintln!("error: write {:?}: {e}", key_path);
            return ExitCode::from(1);
        }

        // Tighten permissions: 0600 (owner read/write only). Best-effort on unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = match fs::metadata(&key_path) {
                Ok(m) => m.permissions(),
                Err(e) => {
                    eprintln!("error: stat {:?}: {e}", key_path);
                    return ExitCode::from(1);
                }
            };
            perms.set_mode(0o600);
            if let Err(e) = fs::set_permissions(&key_path, perms) {
                eprintln!("error: chmod {:?}: {e}", key_path);
                return ExitCode::from(1);
            }
        }

        // PeerId Display ends up as "noise_<hex>"; embed directly in trusted form.
        println!("    \"{}@{}:{}\",", peer_id, host, args.port);
    }
    println!("]");

    println!();
    println!("# Per-droplet upload (Batch 4):");
    for i in 1..=args.count {
        println!(
            "#   scp {}/boot{i}.noise.key root@<DROPLET_{i}_IP>:/home/citrate/.citrate/noise.key",
            args.out_dir.display()
        );
    }
    println!("#   ssh root@<DROPLET_{{i}}_IP> 'chown citrate:citrate /home/citrate/.citrate/noise.key && chmod 600 /home/citrate/.citrate/noise.key'");

    ExitCode::SUCCESS
}
