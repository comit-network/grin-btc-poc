#[derive(Debug, Clone)]
pub struct Offer {
    pub asset: u64,
    pub fee: u64,
    pub expiry: u32, // absolute timestamp
}

impl Offer {
    // funder pays for fee of redeem/refund tx
    pub fn fund_output_amount(&self) -> u64 {
        self.asset + self.fee
    }

    pub fn change_output_amount(&self, input: u64) -> anyhow::Result<u64> {
        input
            .checked_sub(self.asset + (2 * self.fee))
            .ok_or_else(|| {
                anyhow::anyhow!("Bitcoin input amount does not cover fund output amount plus fees")
            })
    }

    pub fn redeem_output_amount(&self) -> u64 {
        self.asset
    }

    pub fn refund_output_amount(&self) -> u64 {
        self.asset
    }
}
