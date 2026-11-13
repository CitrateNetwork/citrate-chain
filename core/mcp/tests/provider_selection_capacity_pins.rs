// Provider selection must not reward a self-reported capacity of zero.
//
// `select_provider` ranks candidates by a score in which free memory and free
// compute each count as `available / total`. A provider reporting a total of
// zero has no capacity at all, so that share must count as zero, whatever it
// reports as "available". Otherwise `x / 0 = inf`, clamped to a full share,
// lets it outrank an honest provider with real spare capacity.
//
// In-process only: no network, no files.

use citrate_execution::Address;
use citrate_mcp::provider::ProviderRegistry;
use citrate_mcp::types::{
    ComputeCapacity, ComputeRequirements, HardwareType, ModelId, ProviderInfo,
};

const GIB: u64 = 1024 * 1024 * 1024;

fn provider(id: u8, capacity: ComputeCapacity) -> ProviderInfo {
    let mut addr = [0u8; 20];
    addr[0] = id;
    ProviderInfo {
        address: Address(addr),
        name: format!("provider-{id}"),
        endpoint: format!("http://provider{id}.invalid"),
        capacity,
        reputation: 100,
        total_executions: 0,
    }
}

/// An honest provider with a quarter of its memory and compute free.
fn honest() -> ProviderInfo {
    provider(
        1,
        ComputeCapacity {
            total_memory: 16 * GIB,
            available_memory: 4 * GIB,
            total_compute: 100,
            available_compute: 25,
            hardware: vec![HardwareType::CPU],
        },
    )
}

fn no_requirements() -> ComputeRequirements {
    ComputeRequirements {
        min_memory: 0,
        min_compute: 0,
        gpu_required: false,
        supported_hardware: vec![],
    }
}

async fn winner(candidates: Vec<ProviderInfo>) -> Address {
    let registry = ProviderRegistry::new();
    let model = ModelId([0x42; 32]);
    for p in candidates {
        let addr = p.address;
        registry.register_provider(p).await.expect("register");
        registry
            .register_model_provider(addr, model)
            .await
            .expect("attach");
    }
    registry
        .select_provider(&model, &no_requirements())
        .await
        .expect("a provider is selected")
}

#[tokio::test]
async fn a_zero_total_memory_claim_does_not_outrank_real_spare_capacity() {
    let claimant = provider(
        2,
        ComputeCapacity {
            total_memory: 0,
            available_memory: u64::MAX,
            total_compute: 100,
            available_compute: 0,
            hardware: vec![HardwareType::CPU],
        },
    );
    assert_eq!(
        winner(vec![claimant, honest()]).await,
        honest().address,
        "a provider reporting zero total memory must get no memory share"
    );
}

#[tokio::test]
async fn a_zero_total_compute_claim_does_not_outrank_real_spare_capacity() {
    let claimant = provider(
        3,
        ComputeCapacity {
            total_memory: 16 * GIB,
            available_memory: 0,
            total_compute: 0,
            available_compute: u64::MAX,
            hardware: vec![HardwareType::CPU],
        },
    );
    assert_eq!(
        winner(vec![claimant, honest()]).await,
        honest().address,
        "a provider reporting zero total compute must get no compute share"
    );
}

#[tokio::test]
async fn real_spare_capacity_still_wins_on_merit() {
    // Control: a provider with more real spare capacity beats the honest one,
    // so the tests above are not passing because the first candidate always
    // loses.
    let roomier = provider(
        4,
        ComputeCapacity {
            total_memory: 16 * GIB,
            available_memory: 12 * GIB,
            total_compute: 100,
            available_compute: 75,
            hardware: vec![HardwareType::CPU],
        },
    );
    let addr = roomier.address;
    assert_eq!(winner(vec![honest(), roomier]).await, addr);
}
