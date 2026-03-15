// citrate/core/economics/src/token.rs

use citrate_execution::types::Address;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Number of decimals for the native token
pub const DECIMALS: u32 = 18;

/// Token configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConfig {
    pub name: String,
    pub symbol: String,
    pub decimals: u32,
    pub total_supply: U256,
    pub initial_distribution: HashMap<Address, U256>,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            name: "Citrate".to_string(),
            symbol: "SALT".to_string(),
            decimals: DECIMALS,
            total_supply: U256::from(1_000_000_000) * U256::from(10).pow(U256::from(DECIMALS)),
            initial_distribution: HashMap::new(),
        }
    }
}

/// Native token representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub config: TokenConfig,
    pub balances: HashMap<Address, U256>,
    pub total_minted: U256,
    pub total_burned: U256,
}

impl Token {
    /// Create a new token with the given configuration
    pub fn new(config: TokenConfig) -> Self {
        let mut balances = HashMap::new();
        let mut total_minted = U256::zero();

        // Distribute initial tokens
        for (address, amount) in &config.initial_distribution {
            balances.insert(*address, *amount);
            total_minted += *amount;
        }

        Self {
            config,
            balances,
            total_minted,
            total_burned: U256::zero(),
        }
    }

    /// Get balance of an address
    pub fn balance_of(&self, address: &Address) -> U256 {
        self.balances.get(address).copied().unwrap_or(U256::zero())
    }

    /// Transfer tokens between addresses
    pub fn transfer(
        &mut self,
        from: &Address,
        to: &Address,
        amount: U256,
    ) -> Result<(), TokenError> {
        let from_balance = self.balance_of(from);

        if from_balance < amount {
            return Err(TokenError::InsufficientBalance);
        }

        // Update balances
        self.balances.insert(*from, from_balance - amount);
        let to_balance = self.balance_of(to);
        self.balances.insert(*to, to_balance + amount);

        Ok(())
    }

    /// Mint new tokens (for block rewards)
    pub fn mint(&mut self, to: &Address, amount: U256) -> Result<(), TokenError> {
        let new_total = self.total_minted + amount;

        // Check if minting would exceed total supply
        if new_total > self.config.total_supply {
            return Err(TokenError::ExceedsSupply);
        }

        let balance = self.balance_of(to);
        self.balances.insert(*to, balance + amount);
        self.total_minted = new_total;

        Ok(())
    }

    /// Burn tokens
    pub fn burn(&mut self, from: &Address, amount: U256) -> Result<(), TokenError> {
        let balance = self.balance_of(from);

        if balance < amount {
            return Err(TokenError::InsufficientBalance);
        }

        self.balances.insert(*from, balance - amount);
        self.total_burned += amount;

        Ok(())
    }

    /// Get circulating supply (minted - burned)
    pub fn circulating_supply(&self) -> U256 {
        self.total_minted - self.total_burned
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("Insufficient balance")]
    InsufficientBalance,

    #[error("Minting would exceed total supply")]
    ExceedsSupply,

    #[error("Invalid amount")]
    InvalidAmount,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_creation() {
        let config = TokenConfig::default();
        let token = Token::new(config);

        assert_eq!(token.total_minted, U256::zero());
        assert_eq!(token.total_burned, U256::zero());
    }

    #[test]
    fn test_mint_and_transfer() {
        let config = TokenConfig::default();
        let mut token = Token::new(config);

        let alice = Address([1; 20]);
        let bob = Address([2; 20]);
        let amount = U256::from(100) * U256::from(10).pow(U256::from(DECIMALS));

        // Mint to Alice
        token.mint(&alice, amount).unwrap();
        assert_eq!(token.balance_of(&alice), amount);

        // Transfer from Alice to Bob
        let transfer_amount = amount / 2;
        token.transfer(&alice, &bob, transfer_amount).unwrap();

        assert_eq!(token.balance_of(&alice), amount - transfer_amount);
        assert_eq!(token.balance_of(&bob), transfer_amount);
    }

    // --- Overflow tests ---

    #[test]
    fn test_mint_exceeding_total_supply_rejected() {
        let config = TokenConfig::default();
        let mut token = Token::new(config.clone());
        let alice = Address([1; 20]);

        // Mint exactly total supply — should succeed
        token.mint(&alice, config.total_supply).unwrap();

        // Mint 1 more wei — should fail
        let result = token.mint(&alice, U256::from(1));
        assert!(matches!(result, Err(TokenError::ExceedsSupply)));
    }

    #[test]
    fn test_mint_u128_max_rejected() {
        let config = TokenConfig::default();
        let mut token = Token::new(config);
        let alice = Address([1; 20]);

        // u128::MAX is far above 1B SALT total supply
        let huge = U256::from(u128::MAX);
        let result = token.mint(&alice, huge);
        assert!(matches!(result, Err(TokenError::ExceedsSupply)));
    }

    #[test]
    fn test_transfer_more_than_balance_rejected() {
        let config = TokenConfig::default();
        let mut token = Token::new(config);
        let alice = Address([1; 20]);
        let bob = Address([2; 20]);

        let amount = U256::from(1000);
        token.mint(&alice, amount).unwrap();

        // Try to transfer more than balance
        let result = token.transfer(&alice, &bob, amount + U256::from(1));
        assert!(matches!(result, Err(TokenError::InsufficientBalance)));
    }

    // --- Underflow tests ---

    #[test]
    fn test_transfer_from_zero_balance_rejected() {
        let config = TokenConfig::default();
        let mut token = Token::new(config);
        let alice = Address([1; 20]);
        let bob = Address([2; 20]);

        // Alice has zero balance, transfer should fail
        let result = token.transfer(&alice, &bob, U256::from(1));
        assert!(matches!(result, Err(TokenError::InsufficientBalance)));
    }

    #[test]
    fn test_burn_from_zero_balance_rejected() {
        let config = TokenConfig::default();
        let mut token = Token::new(config);
        let alice = Address([1; 20]);

        let result = token.burn(&alice, U256::from(1));
        assert!(matches!(result, Err(TokenError::InsufficientBalance)));
    }

    #[test]
    fn test_burn_more_than_balance_rejected() {
        let config = TokenConfig::default();
        let mut token = Token::new(config);
        let alice = Address([1; 20]);

        token.mint(&alice, U256::from(100)).unwrap();
        let result = token.burn(&alice, U256::from(101));
        assert!(matches!(result, Err(TokenError::InsufficientBalance)));
    }

    #[test]
    fn test_transfer_zero_succeeds() {
        let config = TokenConfig::default();
        let mut token = Token::new(config);
        let alice = Address([1; 20]);
        let bob = Address([2; 20]);

        // Transfer zero from unfunded account — should succeed (0 >= 0)
        token.transfer(&alice, &bob, U256::zero()).unwrap();
        assert_eq!(token.balance_of(&alice), U256::zero());
        assert_eq!(token.balance_of(&bob), U256::zero());
    }

    #[test]
    fn test_circulating_supply_after_burn() {
        let config = TokenConfig::default();
        let mut token = Token::new(config);
        let alice = Address([1; 20]);

        let amount = U256::from(1000);
        token.mint(&alice, amount).unwrap();
        token.burn(&alice, U256::from(400)).unwrap();

        assert_eq!(token.circulating_supply(), U256::from(600));
    }

    // --- Conservation of value (property-based) ---

    #[test]
    fn test_transfer_conserves_total_value() {
        let config = TokenConfig::default();
        let mut token = Token::new(config);
        let alice = Address([1; 20]);
        let bob = Address([2; 20]);

        let amount = U256::from(10_000);
        token.mint(&alice, amount).unwrap();

        let supply_before = token.circulating_supply();
        token.transfer(&alice, &bob, U256::from(3_000)).unwrap();
        let supply_after = token.circulating_supply();

        assert_eq!(supply_before, supply_after, "Transfer must conserve circulating supply");
        assert_eq!(
            token.balance_of(&alice) + token.balance_of(&bob),
            amount,
            "Sum of balances must equal minted amount"
        );
    }

    #[test]
    fn test_mint_burn_conservation() {
        let config = TokenConfig::default();
        let mut token = Token::new(config);
        let alice = Address([1; 20]);

        let mint_amount = U256::from(5_000);
        let burn_amount = U256::from(2_000);

        token.mint(&alice, mint_amount).unwrap();
        token.burn(&alice, burn_amount).unwrap();

        assert_eq!(token.circulating_supply(), mint_amount - burn_amount);
        assert_eq!(token.balance_of(&alice), mint_amount - burn_amount);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Strategy to generate a valid mint amount (1..=total_supply_in_units)
    fn mint_amount_strategy() -> impl Strategy<Value = u64> {
        // Keep amounts in a manageable u64 range (in wei-less units) to avoid slowness
        1u64..=1_000_000_000u64
    }

    fn address_strategy() -> impl Strategy<Value = Address> {
        prop::array::uniform20(1u8..=255u8).prop_map(Address)
    }

    proptest! {
        /// Transfer conserves the sum of sender + receiver balances
        #[test]
        fn prop_transfer_conserves_value(
            initial in 1u64..=1_000_000_000u64,
            transfer_pct in 0u64..=100u64,
        ) {
            let config = TokenConfig::default();
            let mut token = Token::new(config);
            let alice = Address([1; 20]);
            let bob = Address([2; 20]);

            let mint_amount = U256::from(initial);
            token.mint(&alice, mint_amount).unwrap();

            let transfer_amount = mint_amount * U256::from(transfer_pct) / U256::from(100);
            token.transfer(&alice, &bob, transfer_amount).unwrap();

            let sum = token.balance_of(&alice) + token.balance_of(&bob);
            prop_assert_eq!(sum, mint_amount, "Transfer must conserve total value");
        }

        /// Circulating supply == total_minted - total_burned after arbitrary mint+burn sequence
        #[test]
        fn prop_circulating_supply_invariant(
            mint_val in 1000u64..=1_000_000_000u64,
            burn_pct in 0u64..=100u64,
        ) {
            let config = TokenConfig::default();
            let mut token = Token::new(config);
            let alice = Address([1; 20]);

            let mint_amount = U256::from(mint_val);
            token.mint(&alice, mint_amount).unwrap();

            let burn_amount = mint_amount * U256::from(burn_pct) / U256::from(100);
            token.burn(&alice, burn_amount).unwrap();

            let expected_circulating = mint_amount - burn_amount;
            prop_assert_eq!(token.circulating_supply(), expected_circulating);
            prop_assert_eq!(token.balance_of(&alice), expected_circulating);
        }

        /// Multi-party transfers conserve total supply across N accounts
        #[test]
        fn prop_multi_transfer_conservation(
            initial in 10_000u64..=1_000_000u64,
            split1_pct in 0u64..=50u64,
            split2_pct in 0u64..=50u64,
        ) {
            let config = TokenConfig::default();
            let mut token = Token::new(config);
            let alice = Address([1; 20]);
            let bob = Address([2; 20]);
            let carol = Address([3; 20]);

            let mint_amount = U256::from(initial);
            token.mint(&alice, mint_amount).unwrap();

            let to_bob = mint_amount * U256::from(split1_pct) / U256::from(100);
            let to_carol = mint_amount * U256::from(split2_pct) / U256::from(100);

            token.transfer(&alice, &bob, to_bob).unwrap();
            token.transfer(&alice, &carol, to_carol).unwrap();

            let total = token.balance_of(&alice) + token.balance_of(&bob) + token.balance_of(&carol);
            prop_assert_eq!(total, mint_amount, "Multi-transfer must conserve total value");
            prop_assert_eq!(token.circulating_supply(), mint_amount);
        }
    }
}
