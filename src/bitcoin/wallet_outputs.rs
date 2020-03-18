use crate::bitcoin::{wallet, Address};

#[derive(Clone)]
pub struct WalletOutputs {
    pub fund_input: wallet::Output,
    pub fund_change_address: Address, // (Address, u64),
    pub redeem_address: Address,
    pub refund_address: Address,
}

// impl WalletOutputs {
//     pub fn new(
//         asset: u64,
//         fee: u64,
//         expiry: u32,
//         input: wallet::Output,
//         change_address: Address,
//         refund_address: Address,
//         redeem_address: Address,
//     ) -> Result<Self, ()> {

//         Ok(Self {
//             asset,
//             fee,
//             expiry,
//             input,
//             change: (change_address, change_amount),
//             refund_address,
//             redeem_address,
//         })
//     }
// }
