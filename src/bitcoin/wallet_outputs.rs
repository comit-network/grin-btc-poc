use crate::bitcoin::{wallet, Address};

#[derive(Clone)]
pub struct WalletOutputs {
    pub fund_input: wallet::Output,
    pub fund_change_address: Address,
    pub redeem_address: Address,
    pub refund_address: Address,
}
