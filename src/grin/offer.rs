#[derive(Debug, Clone)]
pub struct Offer {
    pub asset: u64,
    pub fee: u64, // for simplicity we don't model separate fee values for different transactions
    pub expiry: u64, // block height
}

impl Offer {
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
