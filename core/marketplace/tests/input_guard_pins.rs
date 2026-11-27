//! Input guards on the marketplace's public entry points: review ratings must
//! be finite and in range, and an IPFS CID is validated before it is put into
//! a gateway URL. No network: the metadata cache is built with no gateways.

use chrono::Utc;
use citrate_marketplace::metadata::MetadataCache;
use citrate_marketplace::rating_system::{RatingConfig, RatingSystem};
use citrate_marketplace::types::UserReview;

fn review(rating: f32, reviewer: u8) -> UserReview {
    UserReview {
        model_id: [9u8; 32],
        reviewer: [reviewer; 20],
        rating,
        title: "t".into(),
        content: "c".into(),
        pros: vec![],
        cons: vec![],
        recommended: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[tokio::test]
async fn non_finite_or_out_of_range_ratings_are_rejected() {
    let rs = RatingSystem::new(RatingConfig::default());
    for (i, bad) in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, 0.5, 5.5, -1.0]
        .into_iter()
        .enumerate()
    {
        assert!(
            rs.submit_review(review(bad, i as u8 + 1), false)
                .await
                .is_err(),
            "rating {bad} must be rejected"
        );
    }
    assert!(
        rs.get_model_rating(&[9u8; 32]).await.is_none(),
        "rejected reviews leave no rating behind"
    );
    rs.submit_review(review(4.0, 100), false)
        .await
        .expect("an in-range rating is accepted");
    assert!(rs.get_model_rating(&[9u8; 32]).await.is_some());
}

#[tokio::test]
async fn cid_with_url_metacharacters_is_refused_before_any_fetch() {
    let cache = MetadataCache::new().with_gateways(vec![]);
    for bad in [
        "",
        "Qm/../evil",
        "Qmabc?x=1",
        "Qmabc#f",
        "https://evil.example/x",
        "Qm abc",
    ] {
        let err = cache
            .get_metadata(bad)
            .await
            .expect_err("invalid CID must be an error");
        assert!(
            err.to_string().contains("invalid CID"),
            "{bad:?} must fail CID validation, got: {err}"
        );
    }
}
