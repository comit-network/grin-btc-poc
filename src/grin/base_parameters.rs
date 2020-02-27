use crate::{PublicKey, SecretKey};

#[derive(Debug, Clone)]
pub struct BaseParameters {
    pub asset: u64,
    pub fee: u64, // for simplicity we don't model separate fee values for different transactions
    pub expiry: u64, // block height
    pub fund_input_key: PublicKey,
    pub redeem_output_key: PublicKey,
    pub refund_output_key: PublicKey,
    pub bulletproof_common_nonce: SecretKey,
}

impl BaseParameters {
    pub fn fund_input_amount(&self) -> u64 {
        self.asset + (2 * self.fee)
    }

    pub fn fund_output_amount(&self) -> u64 {
        self.asset + self.fee
    }

    pub fn redeem_output_amount(&self) -> u64 {
        self.asset
    }

    pub fn refund_output_amount(&self) -> u64 {
        self.asset
    }
}
