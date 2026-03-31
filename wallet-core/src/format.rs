//! SALT/wei formatting utilities.
//!
//! SALT has 18 decimals (same as ETH).
//! 1 SALT = 1_000_000_000_000_000_000 wei (10^18)

const SALT_DECIMALS: u32 = 18;
const WEI_PER_SALT: u128 = 10u128.pow(SALT_DECIMALS);

/// Format wei amount as human-readable SALT string.
/// Examples:
///   0 → "0"
///   1_000_000_000_000_000_000 → "1"
///   1_500_000_000_000_000_000 → "1.5"
///   500_000_000_000_000 → "0.0005"
///   123_456_789_012_345_678 → "0.123456789012345678"
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
}
