//! `citrate-sealer` — the PIN-S6 sealing/proving sidecar.
//!
//! The pinning daemon (citrate-node-agent) holds NO halo2 prover — sealing and
//! PoSt proving are heavy and pull in the whole `halo2_proofs` stack, so the
//! daemon drives this binary OUT-OF-PROCESS over a line-delimited JSON protocol
//! on stdin/stdout (one request per line, one response per line; EOF exits).
//! This keeps the daemon light and lets the prover be a swappable component
//! (CPU now, GPU/real-size at PIN-P1 f.6).
//!
//! Proofs are produced against the SAME `ParamsKZG` the live `0x0108` verifier
//! uses (via `zkp::halo2::{prove_porep_reduced,prove_post_reduced}`), so a proof
//! emitted here verifies under the precompile by construction.
//!
//! **Reduced instance** (N=4, L=2, K=1): testnet-functional. The daemon's
//! `sealCommit` / `submitPoSt` calls carry these proofs and the on-chain v2/v3
//! reduced VKs accept them — proving the full daemon→sidecar→chain loop. Real-
//! size sealing (GB sectors) is PIN-P1 f.6; the protocol here is unchanged when
//! the circuit swaps.
//!
//! Build/run: `cargo run -p citrate-execution --features halo2-substrate
//! --bin citrate-sealer`.
//!
//! ## Protocol
//! Request (one JSON object per line):
//! ```json
//! {"op":"seal","pinner":"0x..32B..","cid":"0x..","sector":"0x..","epoch":"0x..","data":["0x..","0x..","0x..","0x.."]}
//! {"op":"prove_post","pinner":"0x..","cid":"0x..","sector":"0x..","epoch":"0x..","data":[...],"challenge_index":1}
//! ```
//! Response:
//! ```json
//! {"ok":true,"replica_id":"0x..","comm_d":"0x..","comm_r":"0x..","comm_c":"0x..","proof":"0x.."}   // seal
//! {"ok":true,"proof":"0x.."}                                                                        // prove_post
//! {"ok":false,"error":"..."}                                                                        // failure
//! ```
//! All field elements are 32-byte big-endian hex (`0x`-prefixed).

#[cfg(not(feature = "halo2-substrate"))]
fn main() {
    eprintln!(
        "citrate-sealer requires the `halo2-substrate` feature \
         (the reduced-circuit prover). Rebuild with --features halo2-substrate."
    );
    std::process::exit(2);
}

#[cfg(feature = "halo2-substrate")]
fn main() {
    use std::io::{BufRead, Write};

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                let _ = writeln!(out, "{}", imp::err_response(&format!("stdin read: {e}")));
                let _ = out.flush();
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let resp = imp::handle_line(&line);
        if writeln!(out, "{resp}").is_err() {
            break;
        }
        let _ = out.flush();
    }
}

#[cfg(feature = "halo2-substrate")]
mod imp {
    use citrate_execution::zkp::halo2::porep::{seal_reduced, SealedReplica, N};
    use citrate_execution::zkp::halo2::{prove_porep_reduced, prove_post_reduced};
    use halo2curves::bn256::Fr as Halo2Fr;
    use halo2curves::ff::PrimeField as _;
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Deserialize)]
    struct Request {
        op: String,
        pinner: String,
        cid: String,
        sector: String,
        epoch: String,
        data: Vec<String>,
        #[serde(default)]
        challenge_index: usize,
    }

    pub fn err_response(msg: &str) -> String {
        json!({"ok": false, "error": msg}).to_string()
    }

    /// Parse a `0x`-prefixed 32-byte big-endian hex string into an Fr.
    fn fr_from_be_hex(s: &str) -> Result<Halo2Fr, String> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| format!("bad hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("expected 32 bytes, got {}", bytes.len()));
        }
        let mut le = [0u8; 32];
        for (i, b) in bytes.iter().enumerate() {
            le[31 - i] = *b; // BE -> LE
        }
        Option::<Halo2Fr>::from(Halo2Fr::from_repr(le.into()))
            .ok_or_else(|| "field element not canonical".to_string())
    }

    /// Serialize an Fr as `0x`-prefixed 32-byte big-endian hex.
    fn fr_to_be_hex(x: &Halo2Fr) -> String {
        let le = x.to_repr();
        let le_slice: &[u8] = le.as_ref();
        let mut be = [0u8; 32];
        for (i, b) in le_slice.iter().enumerate() {
            be[31 - i] = *b;
        }
        format!("0x{}", hex::encode(be))
    }

    fn parse_data(data: &[String]) -> Result<[Halo2Fr; N], String> {
        if data.len() != N {
            return Err(format!("expected {N} data elements, got {}", data.len()));
        }
        let mut arr = [Halo2Fr::from(0u64); N];
        for (i, d) in data.iter().enumerate() {
            arr[i] = fr_from_be_hex(d)?;
        }
        Ok(arr)
    }

    /// Re-seal deterministically from the request (seal is a pure function of
    /// its inputs, so PoSt proving reconstructs the same witness without any
    /// cross-call state).
    fn seal_from(req: &Request) -> Result<(Halo2Fr, SealedReplica), String> {
        let pinner = fr_from_be_hex(&req.pinner)?;
        let cid = fr_from_be_hex(&req.cid)?;
        let sector = fr_from_be_hex(&req.sector)?;
        let epoch = fr_from_be_hex(&req.epoch)?;
        let data = parse_data(&req.data)?;
        Ok((pinner, seal_reduced(pinner, cid, sector, epoch, data)))
    }

    pub fn handle_line(line: &str) -> String {
        let req: Request = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => return err_response(&format!("bad request json: {e}")),
        };
        match req.op.as_str() {
            "seal" => match do_seal(&req) {
                Ok(s) => s,
                Err(e) => err_response(&e),
            },
            "prove_post" => match do_prove_post(&req) {
                Ok(s) => s,
                Err(e) => err_response(&e),
            },
            other => err_response(&format!("unknown op: {other}")),
        }
    }

    fn do_seal(req: &Request) -> Result<String, String> {
        let (pinner, sealed) = seal_from(req)?;
        // PoRep proof at EXACTLY `challenge_index`. The contract's sealCommit
        // builds its 0x0108 wire with challengeNonce=0, so the daemon requests
        // index 0 at seal time; the reduced circuit handles v=0 (the seed slot
        // bound to replicaID). Do NOT remap the index — the proof's public
        // challengeNonce must equal what the contract passes.
        let idx = req.challenge_index;
        let proof = prove_porep_reduced(&sealed, pinner, idx).map_err(|e| e.to_string())?;
        Ok(json!({
            "ok": true,
            "replica_id": fr_to_be_hex(&sealed.replica_id),
            "comm_d": fr_to_be_hex(&sealed.comm_d),
            "comm_r": fr_to_be_hex(&sealed.comm_r),
            "comm_c": fr_to_be_hex(&sealed.comm_c),
            "proof": format!("0x{}", hex::encode(proof)),
        })
        .to_string())
    }

    fn do_prove_post(req: &Request) -> Result<String, String> {
        let (pinner, sealed) = seal_from(req)?;
        // Prove at EXACTLY the requested index — the daemon passes the on-chain
        // committed nonce (which the reduced deployment pins to CHALLENGE_N == N
        // so it indexes a real node), and the proof's public challengeNonce must
        // equal it for submitPoSt to accept.
        let idx = req.challenge_index;
        let proof = prove_post_reduced(&sealed, pinner, idx).map_err(|e| e.to_string())?;
        Ok(json!({
            "ok": true,
            "proof": format!("0x{}", hex::encode(proof)),
        })
        .to_string())
    }
}
