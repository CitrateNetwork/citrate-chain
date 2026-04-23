//! SALT denomination and display helpers.
//!
//! # Terminology
//!
//! Citrate uses two names for the native-token unit depending on layer:
//!
//! | Layer                      | Name   | Scale                   |
//! |----------------------------|--------|-------------------------|
//! | Chain / RPC / transactions | `wei`  | 1 SALT = 10^18 wei       |
//! | UI / chat / docs           | `grain`| 1 SALT = 10^18 grains    |
//!
//! `wei` and `grain` are the **same value** — one `u128` smallest unit.
//! We keep `wei` in every RPC, transaction, contract call, and eth_* method
//! for EVM-compat (MetaMask, ethers, cast all assume "wei"). We use `grain`
//! when writing for humans so it matches the SALT metaphor.
//!
//! # The rule
//!
//! **Never display raw grains to a user.** Any surface that touches a
//! balance or value — a Slint widget, a chat system prompt, a toast, a
//! tool-call response — must run the number through [`grains_to_salt`]
//! (a.k.a. [`wei_to_salt`]) first. Leaving the raw 18-trailing-zeros
//! integer in a user message was a recurring bug; the naming here exists
//! to make the unit discipline visible.
//!
//! If you find yourself writing `format!("{} SALT", raw_u128_or_string)`,
//! stop — use [`format_salt_display`] instead.

/// SALT has 18 decimals (same as ETH). This is fixed at the consensus
/// layer (`citrate_economics::token::DECIMALS`) — do not redefine elsewhere.
pub const SALT_DECIMALS: u32 = 18;

/// Number of smallest units (grains / wei) per whole SALT.
pub const GRAINS_PER_SALT: u128 = 10u128.pow(SALT_DECIMALS);

/// Back-compat alias — same value as `GRAINS_PER_SALT`, kept for code that
/// predates the grain terminology.
pub const WEI_PER_SALT: u128 = GRAINS_PER_SALT;

/// The display unit name.
pub const UNIT_NAME: &str = "SALT";

/// The smallest-unit name as shown to humans.
pub const SUBUNIT_NAME: &str = "grain";

/// Format a grain (wei) amount as a human-readable SALT string.
///
/// Examples:
///   0 → "0"
///   1_000_000_000_000_000_000 → "1"
///   1_500_000_000_000_000_000 → "1.5"
///   500_000_000_000_000 → "0.0005"
///   123_456_789_012_345_678 → "0.123456789012345678"
pub fn grains_to_salt(grains: u128) -> String {
    wei_to_salt(grains)
}

/// Format a grain (wei) amount provided as a decimal or `0x`-prefixed hex
/// string. Designed for the boundary between RPC (wire format: hex wei)
/// and UI (human SALT). Returns the input unchanged if it doesn't parse —
/// callers should decide whether to treat that as an error.
pub fn grains_str_to_salt(grains: &str) -> String {
    let trimmed = grains.trim();
    let parsed: Option<u128> = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u128::from_str_radix(hex, 16).ok()
    } else {
        trimmed.parse::<u128>().ok()
    };
    match parsed {
        Some(g) => grains_to_salt(g),
        None => trimmed.to_string(),
    }
}

/// Format a grain (wei) amount as `"X SALT"` with comma separators for
/// the whole part. This is the canonical display format for the chat
/// system prompt, toasts, and anywhere else the value is shown to a user
/// along with a unit suffix.
pub fn grains_str_to_salt_display(grains: &str) -> String {
    let salt = grains_str_to_salt(grains);
    let parts: Vec<&str> = salt.split('.').collect();
    let whole = parts[0];
    let whole_with_commas = if whole.len() <= 3 {
        whole.to_string()
    } else {
        let chars: Vec<char> = whole.chars().rev().collect();
        chars
            .chunks(3)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(",")
            .chars()
            .rev()
            .collect()
    };
    if parts.len() > 1 {
        format!("{}.{} {}", whole_with_commas, parts[1], UNIT_NAME)
    } else {
        format!("{} {}", whole_with_commas, UNIT_NAME)
    }
}

/// Back-compat alias for code that predates the `grain` terminology.
/// Prefer [`grains_to_salt`] in new code.
pub fn wei_to_salt(wei: u128) -> String {
    if wei == 0 {
        return "0".to_string();
    }

    let whole = wei / WEI_PER_SALT;
    let frac = wei % WEI_PER_SALT;

    if frac == 0 {
        return whole.to_string();
    }

    // Format fraction with leading zeros, then trim trailing zeros
    let frac_str = format!("{:018}", frac);
    let trimmed = frac_str.trim_end_matches('0');

    format!("{}.{}", whole, trimmed)
}

/// Format wei as SALT with fixed decimal places.
pub fn wei_to_salt_fixed(wei: u128, decimals: usize) -> String {
    if wei == 0 {
        return format!("0.{}", "0".repeat(decimals));
    }

    let whole = wei / WEI_PER_SALT;
    let frac = wei % WEI_PER_SALT;
    let frac_str = format!("{:018}", frac);

    if decimals == 0 {
        return whole.to_string();
    }

    let truncated = &frac_str[..decimals.min(18)];
    format!("{}.{}", whole, truncated)
}

/// Parse a SALT amount string to wei.
/// Handles: "1", "1.5", "0.001", "1000"
pub fn salt_to_wei(salt: &str) -> Result<u128, String> {
    let salt = salt.trim();
    if salt.is_empty() {
        return Err("Empty amount".to_string());
    }

    let parts: Vec<&str> = salt.split('.').collect();
    match parts.len() {
        1 => {
            // Whole number only
            let whole: u128 = parts[0].parse()
                .map_err(|_| format!("Invalid number: {}", parts[0]))?;
            Ok(whole * WEI_PER_SALT)
        }
        2 => {
            // Has decimal part
            let whole: u128 = if parts[0].is_empty() { 0 } else {
                parts[0].parse()
                    .map_err(|_| format!("Invalid whole part: {}", parts[0]))?
            };

            let frac_str = parts[1];
            if frac_str.len() > 18 {
                return Err("Too many decimal places (max 18)".to_string());
            }

            // Pad to 18 digits
            let padded = format!("{:0<18}", frac_str);
            let frac: u128 = padded.parse()
                .map_err(|_| format!("Invalid decimal part: {}", frac_str))?;

            Ok(whole * WEI_PER_SALT + frac)
        }
        _ => Err("Invalid amount format".to_string()),
    }
}

/// Format a wei amount as a compact display string with unit.
/// "0 SALT", "1.5 SALT", "1,000 SALT"
pub fn format_salt_display(wei: u128) -> String {
    let salt = wei_to_salt(wei);
    // Add comma separators for large numbers
    let parts: Vec<&str> = salt.split('.').collect();
    let whole = parts[0];

    if whole.len() <= 3 {
        format!("{} SALT", salt)
    } else {
        // Add commas
        let chars: Vec<char> = whole.chars().rev().collect();
        let with_commas: String = chars.chunks(3)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(",")
            .chars()
            .rev()
            .collect();

        if parts.len() > 1 {
            format!("{}.{} SALT", with_commas, parts[1])
        } else {
            format!("{} SALT", with_commas)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero() {
        assert_eq!(wei_to_salt(0), "0");
    }

    #[test]
    fn test_one_salt() {
        assert_eq!(wei_to_salt(WEI_PER_SALT), "1");
    }

    #[test]
    fn test_fractional() {
        assert_eq!(wei_to_salt(WEI_PER_SALT / 2), "0.5");
    }

    #[test]
    fn test_large_amount() {
        assert_eq!(wei_to_salt(1_000_000 * WEI_PER_SALT), "1000000");
    }

    #[test]
    fn test_small_fraction() {
        assert_eq!(wei_to_salt(1_000_000_000_000), "0.000001");
    }

    #[test]
    fn test_mixed() {
        assert_eq!(wei_to_salt(WEI_PER_SALT + WEI_PER_SALT / 4), "1.25");
    }

    #[test]
    fn test_fixed_decimals() {
        assert_eq!(wei_to_salt_fixed(WEI_PER_SALT, 4), "1.0000");
        assert_eq!(wei_to_salt_fixed(WEI_PER_SALT + WEI_PER_SALT / 3, 4), "1.3333");
    }

    #[test]
    fn test_salt_to_wei_whole() {
        assert_eq!(salt_to_wei("1").expect("parse"), WEI_PER_SALT);
        assert_eq!(salt_to_wei("100").expect("parse"), 100 * WEI_PER_SALT);
    }

    #[test]
    fn test_salt_to_wei_fractional() {
        assert_eq!(salt_to_wei("0.5").expect("parse"), WEI_PER_SALT / 2);
        assert_eq!(salt_to_wei("1.5").expect("parse"), WEI_PER_SALT + WEI_PER_SALT / 2);
    }

    #[test]
    fn test_salt_to_wei_small() {
        assert_eq!(salt_to_wei("0.000001").expect("parse"), 1_000_000_000_000);
    }

    #[test]
    fn test_salt_to_wei_invalid() {
        assert!(salt_to_wei("").is_err());
        assert!(salt_to_wei("abc").is_err());
        assert!(salt_to_wei("1.2.3").is_err());
    }

    #[test]
    fn test_salt_to_wei_too_many_decimals() {
        assert!(salt_to_wei("0.1234567890123456789").is_err()); // 19 decimals
    }

    #[test]
    fn test_roundtrip() {
        let amounts = vec![0, 1, WEI_PER_SALT, WEI_PER_SALT / 3, 42 * WEI_PER_SALT + 123];
        for wei in amounts {
            let salt = wei_to_salt(wei);
            let back = salt_to_wei(&salt).expect("roundtrip");
            assert_eq!(back, wei, "Failed roundtrip for wei={}: salt='{}', back={}", wei, salt, back);
        }
    }

    #[test]
    fn test_display_format() {
        assert_eq!(format_salt_display(0), "0 SALT");
        assert_eq!(format_salt_display(WEI_PER_SALT), "1 SALT");
        assert_eq!(format_salt_display(1_000_000 * WEI_PER_SALT), "1,000,000 SALT");
    }

    #[test]
    fn test_display_with_fraction() {
        assert_eq!(format_salt_display(WEI_PER_SALT + WEI_PER_SALT / 2), "1.5 SALT");
    }

    #[test]
    fn grains_str_decimal_million_salt() {
        // The canonical "user has 1,000,000 SALT" case the chat used to
        // leak as the raw 25-digit integer.
        let grains_million = (1_000_000u128 * WEI_PER_SALT).to_string();
        assert_eq!(grains_str_to_salt(&grains_million), "1000000");
        assert_eq!(
            grains_str_to_salt_display(&grains_million),
            "1,000,000 SALT"
        );
    }

    #[test]
    fn grains_str_hex_parses() {
        // eth_getBalance returns hex wei. The grain formatter accepts it.
        let hex_one_salt = format!("0x{:x}", WEI_PER_SALT);
        assert_eq!(grains_str_to_salt(&hex_one_salt), "1");
    }

    #[test]
    fn grains_str_invalid_preserves_input() {
        // Non-parseable input is returned as-is. Callers decide whether
        // to treat that as an error; the formatter never panics.
        assert_eq!(grains_str_to_salt("not-a-number"), "not-a-number");
    }

    #[test]
    fn grains_to_salt_matches_wei_to_salt() {
        // grain ≡ wei — the two helpers must always agree.
        for g in [0u128, 1, WEI_PER_SALT, 42 * WEI_PER_SALT + 123, u128::MAX / 2] {
            assert_eq!(grains_to_salt(g), wei_to_salt(g));
        }
    }
}
