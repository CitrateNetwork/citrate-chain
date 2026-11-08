//! `citrate contract verify` against the explorer's Etherscan-compatible API.
//!
//! The HTTP server here is a test-only recorder (Rule 1 allows test fakes). The request
//! shapes it checks come from real tools: `tests/fixtures/verify/*/…-requests.jsonl` are the
//! requests forge 1.5.1 and hardhat-verify 2.1.3 sent to a recording server (see the README
//! there), and the build-info files were written by those tools' compilers.

use citrate_cli::commands::contract::{self, ContractCommands};
use citrate_cli::commands::verify::{
    load_compilation_input, normalize_compiler_version, normalize_constructor_args,
    parse_compilation_input, parse_library, prepare_standard_json, BuildArtifactKind,
    ExplorerClient, PollConfig, SourceSubmission, VerifyError, VerifyRequest, VerifyStatus,
    DEFAULT_EXPLORER_URL,
};
use citrate_cli::config::Config;
use clap::Parser;
use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const FORGE_ADDR: &str = "0x5fbdb2315678afecb367f032d99f2f9fc9a2f74b";
const HARDHAT_ADDR: &str = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/verify")
}

fn forge_build_info() -> PathBuf {
    fixtures().join("forge/build-info/970692f6b0ae96cc.json")
}

fn hardhat_build_info() -> PathBuf {
    fixtures().join("hardhat/artifacts/build-info/dd99b6a8e0696988f72849c906423ccc.json")
}

fn hardhat_artifact() -> PathBuf {
    fixtures().join("hardhat/artifacts/contracts/Greeter.sol/Greeter.json")
}

fn read_json(p: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(p).expect("read fixture"))
        .expect("fixture is JSON")
}

/// Decode an `application/x-www-form-urlencoded` body (or a query string).
fn decode_form(s: &str) -> Vec<(String, String)> {
    let url = reqwest::Url::parse(&format!("http://x/?{s}")).expect("form body parses as a query");
    url.query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// One recorded tool request: (method, path-with-query, decoded body fields).
type RecordedRequest = (String, String, Vec<(String, String)>);

fn recorded(file: &str) -> Vec<RecordedRequest> {
    std::fs::read_to_string(fixtures().join(file))
        .expect("read recorded requests")
        .lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l).expect("recorded line is JSON");
            (
                v["method"].as_str().expect("method").to_owned(),
                v["path"].as_str().expect("path").to_owned(),
                decode_form(v["body"].as_str().expect("body")),
            )
        })
        .collect()
}

/// Compare form fields as a map, with `sourceCode` compared as JSON when it is JSON.
fn normalized(fields: &[(String, String)]) -> BTreeMap<String, Value> {
    fields
        .iter()
        .map(|(k, v)| {
            let val = if k == "sourceCode" {
                serde_json::from_str(v).unwrap_or(Value::String(v.clone()))
            } else {
                Value::String(v.clone())
            };
            (k.clone(), val)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// test-only HTTP recorder
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    target: String,
    content_type: Option<String>,
    body: String,
}

impl Seen {
    fn query(&self) -> Vec<(String, String)> {
        match self.target.split_once('?') {
            Some((_, q)) => decode_form(q),
            None => vec![],
        }
    }
}

struct Recorder {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

/// Serve scripted (status, body) answers in order; the last one repeats.
async fn recorder(script: Vec<(u16, &str)>) -> Recorder {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind recorder");
    let addr = listener.local_addr().expect("recorder addr");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let queue: Arc<Mutex<VecDeque<(u16, String)>>> = Arc::new(Mutex::new(
        script.into_iter().map(|(s, b)| (s, b.to_owned())).collect(),
    ));
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            let (head_end, content_len) = loop {
                let n = sock.read(&mut chunk).await.expect("read request");
                if n == 0 {
                    break (None, 0);
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..pos]).to_string();
                    let len = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.eq_ignore_ascii_case("content-length")
                                .then(|| v.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    break (Some(pos + 4), len);
                }
            };
            let Some(head_end) = head_end else { continue };
            while buf.len() < head_end + content_len {
                let n = sock.read(&mut chunk).await.expect("read request");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            let mut first = head.lines().next().unwrap_or("").split_whitespace();
            let method = first.next().unwrap_or("").to_owned();
            let target = first.next().unwrap_or("").to_owned();
            let content_type = head.lines().find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case("content-type")
                    .then(|| v.trim().to_owned())
            });
            let body = String::from_utf8_lossy(&buf[head_end..]).to_string();
            seen2.lock().expect("recorder mutex").push(Seen {
                method,
                target,
                content_type,
                body,
            });
            let (status, answer) = {
                let mut q = queue.lock().expect("recorder mutex");
                if q.len() > 1 {
                    q.pop_front().expect("scripted answer")
                } else {
                    q.front().cloned().unwrap_or((200, "{}".to_owned()))
                }
            };
            let resp = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{answer}",
                answer.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });
    Recorder {
        url: format!("http://{addr}/api"),
        seen,
    }
}

impl Recorder {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("recorder mutex").clone()
    }
}

fn fast() -> PollConfig {
    PollConfig {
        interval: Duration::from_millis(10),
        timeout: Duration::from_secs(5),
        rate_limit_retries: 2,
        rate_limit_backoff: Duration::from_millis(10),
    }
}

const OK_GUID: &str =
    r#"{"status":"1","message":"OK","result":"5d1d6cbe-5f4d-4bd4-a1c9-2c1a1c5b1e01"}"#;
const PENDING: &str = r#"{"status":"0","message":"NOTOK","result":"Pending in queue"}"#;
const PASS: &str = r#"{"status":"1","message":"OK","result":"Pass - Verified"}"#;
const FAIL: &str = r#"{"status":"0","message":"NOTOK","result":"Fail - Unable to verify"}"#;

fn forge_request(args: Option<&str>) -> VerifyRequest {
    let ci = load_compilation_input(&forge_build_info()).expect("load forge build-info");
    let s = prepare_standard_json(&ci, Some("src/Greeter.sol:Greeter"), None)
        .expect("prepare standard JSON");
    VerifyRequest {
        address: FORGE_ADDR.to_owned(),
        source: SourceSubmission::StandardJson(s),
        constructor_args: args.map(str::to_owned),
        creation_tx_hash: None,
        chain_id: None,
    }
}

// ---------------------------------------------------------------------------
// build-info parsing
// ---------------------------------------------------------------------------

#[test]
fn forge_build_info_yields_forges_own_standard_json() {
    let ci = load_compilation_input(&forge_build_info()).expect("load forge build-info");
    assert_eq!(ci.kind, BuildArtifactKind::ForgeBuildInfo);
    let s = prepare_standard_json(&ci, Some("src/Greeter.sol:Greeter"), None)
        .expect("prepare standard JSON");
    assert_eq!(s.contract_name, "src/Greeter.sol:Greeter");
    // forge's build-info says solcLongVersion "0.8.26"; the commit comes from the metadata.
    assert_eq!(s.compiler_version, "v0.8.26+commit.8a97fa7a");
    let expected = read_json(&fixtures().join("forge/standard-json-input.json"));
    assert_eq!(s.standard_json, expected);
    // Only the dependency closure: Unrelated.sol is dropped, and forge's extras are gone.
    let srcs = s.standard_json["sources"]
        .as_object()
        .expect("sources object");
    assert!(!srcs.contains_key("src/Unrelated.sol"));
    for extra in ["version", "allowPaths", "basePath", "includePaths"] {
        assert!(s.standard_json.get(extra).is_none(), "{extra} leaked");
    }
}

#[test]
fn bare_contract_name_resolves_when_unique() {
    let ci = load_compilation_input(&forge_build_info()).expect("load forge build-info");
    let s = prepare_standard_json(&ci, Some("Greeter"), None).expect("prepare standard JSON");
    assert_eq!(s.contract_name, "src/Greeter.sol:Greeter");
}

#[test]
fn missing_contract_choice_lists_candidates() {
    let ci = load_compilation_input(&forge_build_info()).expect("load forge build-info");
    let err = prepare_standard_json(&ci, None, None)
        .expect_err("expected an error")
        .to_string();
    assert!(err.contains("src/Greeter.sol:Greeter"), "{err}");
    assert!(err.contains("src/Counter.sol:Counter"), "{err}");
    let err = prepare_standard_json(&ci, Some("Nope"), None)
        .expect_err("expected an error")
        .to_string();
    assert!(err.contains("not in this build-info"), "{err}");
}

#[test]
fn forge_minimal_build_info_asks_for_build_info_flag() {
    let err = load_compilation_input(&fixtures().join("forge/minimal-build-info.json"))
        .expect_err("expected an error")
        .to_string();
    assert!(err.contains("forge build --build-info"), "{err}");
}

#[test]
fn hardhat_artifact_resolves_build_info_and_contract() {
    let ci = load_compilation_input(&hardhat_artifact()).expect("load hardhat artifact");
    assert_eq!(ci.kind, BuildArtifactKind::HardhatArtifact);
    let s = prepare_standard_json(&ci, None, None).expect("prepare standard JSON");
    assert_eq!(s.contract_name, "contracts/Greeter.sol:Greeter");
    assert_eq!(s.compiler_version, "v0.8.26+commit.8a97fa7a");
    // Byte-for-byte what hardhat-verify 2.1.3 submitted for this contract.
    let hh = recorded("hardhat/hardhat-verify-2.1.3-requests.jsonl");
    let submit = hh
        .iter()
        .find(|(m, _, _)| m == "POST")
        .expect("recorded POST");
    let sent = normalized(&submit.2);
    assert_eq!(sent["sourceCode"], s.standard_json);
}

#[test]
fn hardhat_build_info_with_bare_name() {
    let ci = load_compilation_input(&hardhat_build_info()).expect("load hardhat build-info");
    assert_eq!(ci.kind, BuildArtifactKind::HardhatBuildInfo);
    let s = prepare_standard_json(&ci, Some("Greeter"), None).expect("prepare standard JSON");
    assert_eq!(s.contract_name, "contracts/Greeter.sol:Greeter");
    assert!(!s.standard_json["sources"]
        .as_object()
        .expect("sources object")
        .contains_key("contracts/Unrelated.sol"));
}

#[test]
fn bare_standard_json_needs_qualified_name_and_compiler() {
    let std = read_json(&fixtures().join("forge/standard-json-input.json"));
    let ci = parse_compilation_input(std.clone()).expect("standard JSON input");
    assert_eq!(ci.kind, BuildArtifactKind::StandardJsonInput);
    assert!(prepare_standard_json(&ci, Some("Greeter"), Some("v0.8.26+commit.8a97fa7a")).is_err());
    assert!(prepare_standard_json(&ci, Some("src/Greeter.sol:Greeter"), None).is_err());
    let s = prepare_standard_json(
        &ci,
        Some("src/Greeter.sol:Greeter"),
        Some("0.8.26+commit.8a97fa7a"),
    )
    .expect("prepare standard JSON");
    assert_eq!(s.compiler_version, "v0.8.26+commit.8a97fa7a");
    assert_eq!(s.standard_json, std);
}

#[test]
fn url_only_sources_are_refused() {
    let mut std = read_json(&fixtures().join("forge/standard-json-input.json"));
    std["sources"]["src/Counter.sol"] = serde_json::json!({"urls": ["ipfs://x"]});
    let ci = parse_compilation_input(std).expect("standard JSON input");
    let err = prepare_standard_json(
        &ci,
        Some("src/Greeter.sol:Greeter"),
        Some("v0.8.26+commit.8a97fa7a"),
    )
    .expect_err("expected an error")
    .to_string();
    assert!(err.contains("inline content"), "{err}");
}

#[test]
fn compiler_version_needs_commit() {
    assert_eq!(
        normalize_compiler_version("0.8.26+commit.8a97fa7a").expect("long version"),
        "v0.8.26+commit.8a97fa7a"
    );
    assert!(normalize_compiler_version("0.8.26").is_err());
}

// ---------------------------------------------------------------------------
// request shape
// ---------------------------------------------------------------------------

#[test]
fn standard_json_request_matches_what_forge_sends() {
    let args = "0x0000000000000000000000000000000000000000000000000000000000000007";
    let ours = forge_request(Some(args))
        .form_fields()
        .expect("form fields");
    let forge = recorded("forge/forge-1.5.1-custom-verifier-requests.jsonl");
    let (method, path, fields) = &forge[0];
    assert_eq!((method.as_str(), path.as_str()), ("POST", "/api"));
    assert_eq!(normalized(&ours), normalized(fields));
}

#[test]
fn constructor_args_use_etherscan_spelling_without_0x() {
    let f = forge_request(Some("0xABCD"))
        .form_fields()
        .expect("form fields");
    let get = |k: &str| f.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    assert_eq!(get("constructorArguements").as_deref(), Some("abcd"));
    assert_eq!(get("constructorArguments").as_deref(), Some("abcd"));
    assert!(normalize_constructor_args("0xabc").is_err());
    assert!(normalize_constructor_args("zz").is_err());
    // No args given: neither field is sent (the explorer reads the creation tx).
    let f = forge_request(None).form_fields().expect("form fields");
    assert!(!f.iter().any(|(k, _)| k.starts_with("constructorArgu")));
}

#[test]
fn single_file_request_fields() {
    let req = VerifyRequest {
        address: FORGE_ADDR.to_owned(),
        source: SourceSubmission::SingleFile {
            source: "contract A {}".to_owned(),
            contract_name: "A".to_owned(),
            compiler_version: "0.8.26+commit.8a97fa7a".to_owned(),
            optimization_used: true,
            runs: 200,
            evm_version: Some("cancun".to_owned()),
            libraries: vec![
                parse_library("MyLib:0x00000000000000000000000000000000000000aa")
                    .expect("library spec"),
            ],
        },
        constructor_args: None,
        creation_tx_hash: Some("0x".to_owned() + &"11".repeat(32)),
        chain_id: Some(40204),
    };
    let f: BTreeMap<String, String> = req
        .form_fields()
        .expect("form fields")
        .into_iter()
        .collect();
    assert_eq!(f["module"], "contract");
    assert_eq!(f["action"], "verifysourcecode");
    assert_eq!(f["codeformat"], "solidity-single-file");
    assert_eq!(f["sourceCode"], "contract A {}");
    assert_eq!(f["contractname"], "A");
    assert_eq!(f["compilerversion"], "v0.8.26+commit.8a97fa7a");
    assert_eq!(f["optimizationUsed"], "1");
    assert_eq!(f["runs"], "200");
    assert_eq!(f["evmversion"], "cancun");
    assert_eq!(f["libraryname1"], "MyLib");
    assert_eq!(
        f["libraryaddress1"],
        "0x00000000000000000000000000000000000000aa"
    );
    assert_eq!(f["chainid"], "40204");
    assert_eq!(f["creationtxhash"], "0x".to_owned() + &"11".repeat(32));
}

#[test]
fn bad_address_is_refused_before_sending() {
    let mut r = forge_request(None);
    r.address = "0x1234".to_owned();
    assert!(r.form_fields().is_err());
}

// ---------------------------------------------------------------------------
// submission and polling against a recorder
// ---------------------------------------------------------------------------

#[tokio::test]
async fn submit_then_poll_to_pass() {
    let srv = recorder(vec![
        (200, OK_GUID),
        (200, PENDING),
        (200, PENDING),
        (200, PASS),
    ])
    .await;
    let client = ExplorerClient::new(&srv.url, Some("citrate".to_owned())).expect("client");
    let guid = client
        .submit(&forge_request(None), &fast())
        .await
        .expect("submit");
    assert_eq!(guid, "5d1d6cbe-5f4d-4bd4-a1c9-2c1a1c5b1e01");
    let status = client.wait(&guid, &fast()).await.expect("wait");
    assert_eq!(status, VerifyStatus::Verified("Pass - Verified".to_owned()));

    let seen = srv.seen();
    assert_eq!(seen.len(), 4);
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].target, "/api");
    assert_eq!(
        seen[0].content_type.as_deref(),
        Some("application/x-www-form-urlencoded")
    );
    let body: BTreeMap<_, _> = decode_form(&seen[0].body).into_iter().collect();
    assert_eq!(body["apikey"], "citrate");
    assert_eq!(body["action"], "verifysourcecode");
    for s in &seen[1..] {
        assert_eq!(s.method, "GET");
        let q: BTreeMap<_, _> = s.query().into_iter().collect();
        assert_eq!(q["module"], "contract");
        assert_eq!(q["action"], "checkverifystatus");
        assert_eq!(q["guid"], guid);
        assert_eq!(q["apikey"], "citrate");
    }
}

#[tokio::test]
async fn hardhat_submission_matches_hardhat_verify_exactly() {
    let srv = recorder(vec![(200, OK_GUID)]).await;
    let client = ExplorerClient::new(&srv.url, Some("citrate".to_owned())).expect("client");
    let ci = load_compilation_input(&hardhat_artifact()).expect("load hardhat artifact");
    let hh = recorded("hardhat/hardhat-verify-2.1.3-requests.jsonl");
    let hh_fields = &hh
        .iter()
        .find(|(m, _, _)| m == "POST")
        .expect("recorded POST")
        .2;
    let hh_map: BTreeMap<_, _> = hh_fields.iter().cloned().collect();
    let req = VerifyRequest {
        address: HARDHAT_ADDR.to_owned(),
        source: SourceSubmission::StandardJson(
            prepare_standard_json(&ci, None, None).expect("prepare standard JSON"),
        ),
        constructor_args: Some(hh_map["constructorArguements"].clone()),
        creation_tx_hash: None,
        chain_id: None,
    };
    client.submit(&req, &fast()).await.expect("submit");
    let ours = decode_form(&srv.seen()[0].body);
    let mut ours_n = normalized(&ours);
    // hardhat-verify sends only the misspelled field; we also send the corrected one.
    assert_eq!(
        ours_n.remove("constructorArguments"),
        Some(Value::String(hh_map["constructorArguements"].clone()))
    );
    assert_eq!(ours_n, normalized(hh_fields));
}

#[tokio::test]
async fn failed_verdict_is_terminal() {
    let srv = recorder(vec![(200, PENDING), (200, FAIL)]).await;
    let client = ExplorerClient::new(&srv.url, None).expect("client");
    let status = client.wait("g", &fast()).await.expect("wait");
    assert_eq!(
        status,
        VerifyStatus::Failed("Fail - Unable to verify".to_owned())
    );
    assert_eq!(srv.seen().len(), 2);
    // No api key configured: none is sent.
    assert!(!srv.seen()[0].query().iter().any(|(k, _)| k == "apikey"));
}

#[tokio::test]
async fn poll_times_out_with_last_status() {
    let srv = recorder(vec![(200, PENDING)]).await;
    let client = ExplorerClient::new(&srv.url, None).expect("client");
    let cfg = PollConfig {
        timeout: Duration::from_millis(80),
        ..fast()
    };
    match client.wait("g", &cfg).await {
        Err(VerifyError::Timeout { guid, last }) => {
            assert_eq!(guid, "g");
            assert_eq!(last, "Pending in queue");
        }
        other => panic!("expected timeout, got {other:?}"),
    }
}

#[tokio::test]
async fn submission_refusals_are_typed() {
    let already =
        r#"{"status":"0","message":"NOTOK","result":"Contract source code already verified"}"#;
    let srv = recorder(vec![(200, already)]).await;
    let c = ExplorerClient::new(&srv.url, None).expect("client");
    assert!(matches!(
        c.submit(&forge_request(None), &fast()).await,
        Err(VerifyError::AlreadyVerified(_))
    ));

    let missing = r#"{"status":"0","message":"NOTOK","result":"Unable to locate ContractCode at 0x5fbdb2315678afecb367f032d99f2f9fc9a2f74b"}"#;
    let srv = recorder(vec![(200, missing)]).await;
    let c = ExplorerClient::new(&srv.url, None).expect("client");
    match c.submit(&forge_request(None), &fast()).await {
        Err(VerifyError::Rejected(m)) => assert!(m.starts_with("Unable to locate ContractCode")),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn rate_limited_submission_is_retried() {
    let limited = r#"{"status":"0","message":"NOTOK","result":"Max rate limit reached"}"#;
    let srv = recorder(vec![(429, limited), (200, OK_GUID)]).await;
    let c = ExplorerClient::new(&srv.url, None).expect("client");
    assert!(c.submit(&forge_request(None), &fast()).await.is_ok());
    assert_eq!(srv.seen().len(), 2);

    let srv = recorder(vec![(429, limited)]).await;
    let c = ExplorerClient::new(&srv.url, None).expect("client");
    assert!(matches!(
        c.submit(&forge_request(None), &fast()).await,
        Err(VerifyError::RateLimited(_))
    ));
    // one try plus two retries
    assert_eq!(srv.seen().len(), 3);
}

#[tokio::test]
async fn non_envelope_answers_are_errors() {
    let srv = recorder(vec![(502, "bad gateway")]).await;
    let c = ExplorerClient::new(&srv.url, None).expect("client");
    assert!(matches!(
        c.check_status("g").await,
        Err(VerifyError::Http { status: 502, .. })
    ));
    let srv = recorder(vec![(200, r#"{"verified":true}"#)]).await;
    let c = ExplorerClient::new(&srv.url, None).expect("client");
    assert!(matches!(
        c.check_status("g").await,
        Err(VerifyError::Protocol(_))
    ));
}

#[tokio::test]
async fn get_source_code_reads_first_entry() {
    let body = r#"{"status":"1","message":"OK","result":[{"SourceCode":"{{}}","ContractName":"Greeter","CompilerVersion":"v0.8.26+commit.8a97fa7a"}]}"#;
    let srv = recorder(vec![(200, body)]).await;
    let c = ExplorerClient::new(&srv.url, None).expect("client");
    let entry = c.get_source_code(FORGE_ADDR).await.expect("getsourcecode");
    assert_eq!(entry["ContractName"], "Greeter");
    let q: BTreeMap<_, _> = srv.seen()[0].query().into_iter().collect();
    assert_eq!(q["action"], "getsourcecode");
    assert_eq!(q["address"], FORGE_ADDR);
}

// ---------------------------------------------------------------------------
// the CLI command
// ---------------------------------------------------------------------------

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    cmd: ContractCommands,
}

#[test]
fn verify_flags_and_default_explorer_url() {
    let cli = Cli::try_parse_from([
        "citrate",
        "verify",
        FORGE_ADDR,
        "--build-info",
        "out/build-info/x.json",
        "--contract",
        "src/Greeter.sol:Greeter",
        "--api-key",
        "k",
        "--constructor-args",
        "0x07",
        "--watch",
    ]);
    assert!(cli.is_ok(), "{:?}", cli.err());
    assert_eq!(DEFAULT_EXPLORER_URL, "https://explorer.citrate.ai/api");
    let help = Cli::try_parse_from(["citrate", "verify", "--help"])
        .err()
        .expect("--help exits with the help text")
        .to_string();
    for flag in [
        "--explorer-url",
        "--api-key",
        "--constructor-args",
        "--watch",
        "--build-info",
    ] {
        assert!(help.contains(flag), "{flag} missing from help");
    }
    assert!(help.contains("https://explorer.citrate.ai/api"));
}

#[tokio::test]
async fn contract_verify_uses_the_explorer_not_the_node() {
    let explorer = recorder(vec![(200, OK_GUID), (200, PENDING), (200, PASS)]).await;
    let node = recorder(vec![(
        200,
        r#"{"jsonrpc":"2.0","id":1,"result":{"verified":true}}"#,
    )])
    .await;
    let config = Config {
        rpc_endpoint: node.url.clone(),
        ..Config::default()
    };
    let bi = forge_build_info();
    let cli = Cli::try_parse_from([
        "citrate",
        "verify",
        FORGE_ADDR,
        "--build-info",
        bi.to_str().expect("utf-8 path"),
        "--contract",
        "src/Greeter.sol:Greeter",
        "--explorer-url",
        &explorer.url,
        "--watch",
        "--poll-interval-ms",
        "10",
    ])
    .expect("parse CLI args");
    contract::execute(cli.cmd, &config)
        .await
        .expect("contract verify");

    assert!(
        node.seen().is_empty(),
        "the CLI must not call the node's operator-only verify method: {:?}",
        node.seen()
    );
    let seen = explorer.seen();
    assert_eq!(seen.len(), 3);
    let body: BTreeMap<_, _> = decode_form(&seen[0].body).into_iter().collect();
    assert_eq!(body["action"], "verifysourcecode");
    assert_eq!(body["contractname"], "src/Greeter.sol:Greeter");
}

#[tokio::test]
async fn contract_verify_reports_failure_as_error() {
    let explorer = recorder(vec![(200, OK_GUID), (200, FAIL)]).await;
    let bi = forge_build_info();
    let cli = Cli::try_parse_from([
        "citrate",
        "verify",
        FORGE_ADDR,
        "--build-info",
        bi.to_str().expect("utf-8 path"),
        "--contract",
        "Greeter",
        "--explorer-url",
        &explorer.url,
        "--watch",
        "--poll-interval-ms",
        "10",
    ])
    .expect("parse CLI args");
    let err = contract::execute(cli.cmd, &Config::default())
        .await
        .expect_err("expected an error")
        .to_string();
    assert!(err.contains("Fail - Unable to verify"), "{err}");
}

#[tokio::test]
async fn contract_verify_status_subcommand_polls_guid() {
    let explorer = recorder(vec![(200, PASS)]).await;
    let cli = Cli::try_parse_from([
        "citrate",
        "verify-status",
        "abc",
        "--explorer-url",
        &explorer.url,
    ])
    .expect("parse CLI args");
    contract::execute(cli.cmd, &Config::default())
        .await
        .expect("verify-status");
    let q: BTreeMap<_, _> = explorer.seen()[0].query().into_iter().collect();
    assert_eq!(q["guid"], "abc");
}
