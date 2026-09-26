// Native transactions signed with the chain-bound (V2) digest are relayed only
// to peers whose handshake advertised a protocol version that verifies them.
//
// A node from before V2 verification checks a gossiped native transaction
// against the V1 digest only. Each failure costs the sending peer 10 points,
// each valid message earns 1, and at -100 the peer is banned for an hour. An
// upgraded node that relayed V2 transactions to it would be banned after about
// ten of them. So upgraded nodes withhold V2 native transactions from such
// peers; every other transaction, and every block, is relayed as before.

use citrate_consensus::crypto::Ed25519SigningKey;
use citrate_consensus::native_sig::{sign_native, signed_version, NativeSigVersion};
use citrate_consensus::tx_auth::native_tx_id;
use citrate_consensus::types::{Block, BlockBuilder, Hash, PublicKey, Transaction};
use citrate_network::peer::{Direction, Peer, PeerInfo};
use citrate_network::protocol::{NetworkMessage, ProtocolVersion};
use citrate_network::{PeerId, PeerManager, PeerManagerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

const OLD: ProtocolVersion = ProtocolVersion {
    major: 1,
    minor: 0,
    patch: 0,
};

fn native(seed: u8, nonce: u64, version: NativeSigVersion) -> Transaction {
    let sk = Ed25519SigningKey::from_bytes(&[seed; 32]);
    let mut tx = Transaction {
        nonce,
        to: Some(PublicKey::new([9u8; 32])),
        value: 1,
        gas_limit: 21_000,
        gas_price: 1_000_000_000,
        chain_id: Some(40204),
        ..Default::default()
    };
    sign_native(&mut tx, &sk, version).unwrap();
    tx.hash = native_tx_id(&tx);
    tx
}

/// Register a peer that advertised `version` (None: no handshake version
/// recorded) and return the queue its messages are written to.
async fn peer(
    pm: &PeerManager,
    n: u8,
    version: Option<ProtocolVersion>,
) -> mpsc::Receiver<NetworkMessage> {
    let addr: SocketAddr = format!("10.0.0.{n}:30303").parse().unwrap();
    let mut info = PeerInfo::new(PeerId(format!("peer-{n}")), addr, Direction::Outbound);
    info.version = version;
    let (to_wire, from_node) = mpsc::channel(64);
    let (_unused, inbound) = mpsc::channel(1);
    pm.add_peer(Arc::new(Peer::new(info, to_wire, inbound)))
        .await
        .expect("peer added");
    from_node
}

fn drain(rx: &mut mpsc::Receiver<NetworkMessage>) -> Vec<NetworkMessage> {
    let mut out = Vec::new();
    while let Ok(m) = rx.try_recv() {
        out.push(m);
    }
    out
}

/// The native transactions a peer received, by digest version.
fn received_native(msgs: &[NetworkMessage]) -> Vec<(Hash, Option<NativeSigVersion>)> {
    let mut out = Vec::new();
    for m in msgs {
        match m {
            NetworkMessage::NewTransaction { transaction } => {
                out.push((transaction.hash, signed_version(transaction)))
            }
            NetworkMessage::Transactions { transactions } => {
                for t in transactions {
                    out.push((t.hash, signed_version(t)))
                }
            }
            _ => {}
        }
    }
    out
}

/// The old node's gossip rule for transactions: V1-only verification, -10 per
/// failure, +1 per valid message; banned at -100.
fn old_node_score(msgs: &[NetworkMessage]) -> i32 {
    let mut score = 0i32;
    for m in msgs {
        let txs: Vec<&Transaction> = match m {
            NetworkMessage::NewTransaction { transaction } => vec![transaction],
            NetworkMessage::Transactions { transactions } => transactions.iter().collect(),
            NetworkMessage::NewBlock { .. } => {
                score += 1;
                continue;
            }
            _ => continue,
        };
        for t in txs {
            score += if signed_version(t) == Some(NativeSigVersion::V1) {
                1
            } else {
                -10
            };
        }
    }
    score
}

fn block_with(txs: Vec<Transaction>) -> Block {
    BlockBuilder::new()
        .height(5)
        .transactions(txs)
        .build_unhashed()
}

#[tokio::test]
async fn old_peers_never_receive_v2_native_txs_upgraded_peers_do() {
    let pm = PeerManager::new(PeerManagerConfig::default());
    let mut old = peer(&pm, 1, Some(OLD)).await;
    let mut unknown = peer(&pm, 2, None).await;
    let mut new = peer(&pm, 3, Some(ProtocolVersion::CURRENT)).await;

    let v1 = native(1, 0, NativeSigVersion::V1);
    let v2s: Vec<Transaction> = (0..20)
        .map(|n| native(2, n, NativeSigVersion::V2))
        .collect();
    let block = block_with(vec![v2s[0].clone(), v1.clone()]);

    // The API server's and gossip's per-tx broadcast.
    pm.broadcast(&NetworkMessage::NewTransaction {
        transaction: v1.clone(),
    })
    .await
    .unwrap();
    for t in &v2s[..15] {
        pm.broadcast(&NetworkMessage::NewTransaction {
            transaction: t.clone(),
        })
        .await
        .unwrap();
    }
    // A GetTransactions reply to specific peers.
    let batch = NetworkMessage::Transactions {
        transactions: vec![v1.clone(), v2s[15].clone(), v2s[16].clone()],
    };
    pm.send_to_peers(
        &[
            PeerId("peer-1".into()),
            PeerId("peer-2".into()),
            PeerId("peer-3".into()),
        ],
        &batch,
    )
    .await
    .unwrap();
    // Blocks relay unchanged, V2 txs inside included.
    pm.broadcast(&NetworkMessage::NewBlock {
        block: block.clone(),
    })
    .await
    .unwrap();

    for (name, rx) in [("old", &mut old), ("unknown", &mut unknown)] {
        let msgs = drain(rx);
        let got = received_native(&msgs);
        assert!(
            got.iter().all(|(_, v)| *v == Some(NativeSigVersion::V1)),
            "{name} peer received a V2 native tx: {got:?}"
        );
        assert_eq!(got.len(), 2, "{name}: the V1 tx, once per message");
        assert!(
            msgs.iter().any(
                |m| matches!(m, NetworkMessage::NewBlock { block: b } if b.transactions.len() == 2)
            ),
            "{name}: the block is relayed whole"
        );
        let score = old_node_score(&msgs);
        assert!(score > -100, "{name}: the old node would ban us ({score})");
        assert!(score >= 0, "{name}: nothing invalid was relayed ({score})");
    }

    let msgs = drain(&mut new);
    let got = received_native(&msgs);
    assert_eq!(got.len(), 1 + 15 + 3, "upgraded peer receives everything");
    assert_eq!(
        got.iter()
            .filter(|(_, v)| *v == Some(NativeSigVersion::V2))
            .count(),
        17
    );
    assert!(msgs
        .iter()
        .any(|m| matches!(m, NetworkMessage::NewBlock { .. })));
}

/// A batch that holds only V2 native txs is not sent to an old peer at all.
#[tokio::test]
async fn all_v2_batch_is_not_sent_to_old_peers() {
    let pm = PeerManager::new(PeerManagerConfig::default());
    let mut old = peer(&pm, 4, Some(OLD)).await;
    pm.broadcast(&NetworkMessage::Transactions {
        transactions: vec![native(5, 0, NativeSigVersion::V2)],
    })
    .await
    .unwrap();
    assert!(drain(&mut old).is_empty());
}

/// The version this release advertises is still compatible with old nodes
/// (they accept its handshake), and is the one that marks V2 relay.
#[test]
fn advertised_version_is_backward_compatible_and_gates_v2() {
    assert!(OLD.is_compatible(&ProtocolVersion::CURRENT));
    assert!(ProtocolVersion::CURRENT.is_compatible(&OLD));
    assert!(ProtocolVersion::CURRENT.verifies_native_v2());
    assert!(!OLD.verifies_native_v2());
    let later = ProtocolVersion {
        major: 1,
        minor: 7,
        patch: 3,
    };
    assert!(later.verifies_native_v2());
}

/// Tripwire: both production handshakes record the peer's advertised version.
#[test]
fn transport_records_the_peer_version() {
    let src = include_str!("../src/transport.rs");
    assert_eq!(
        src.matches("info.version = Some(version);").count(),
        2,
        "inbound and outbound handshakes must record the remote version"
    );
}
