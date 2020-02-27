use crate::bitcoin::wallet;

#[derive(Debug, Clone)]
pub struct BaseParameters {
    pub asset: u64,
    pub fee: u64,
    pub expiry: u32, // absolute timestamp
    pub input: wallet::Output,
    pub change: (bitcoin::Address, u64),
    pub refund_address: bitcoin::Address,
    pub redeem_address: bitcoin::Address,
}

impl BaseParameters {
    pub fn new(
        asset: u64,
        fee: u64,
        expiry: u32,
        input: wallet::Output,
        change_address: bitcoin::Address,
        refund_address: bitcoin::Address,
        redeem_address: bitcoin::Address,
    ) -> Result<Self, ()> {
        let total_input_amount = input.txout.value;
        // TODO: use check_operation everywhere
        let change_amount = total_input_amount
            .checked_sub(asset + (2 * fee))
            .ok_or(())?;

        Ok(Self {
            asset,
            fee,
            expiry,
            input,
            change: (change_address, change_amount),
            refund_address,
            redeem_address,
        })
    }

    pub fn fund_output_amount(&self) -> u64 {
        self.asset + self.fee
    }

    pub fn redeem_output_amount(&self) -> u64 {
        self.asset
    }
}
