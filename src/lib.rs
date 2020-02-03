#![allow(non_snake_case)]
pub mod alice;
pub mod bitcoin;
pub mod bob;
pub mod commit;
pub mod grin;
pub mod messages;

// TODO: Do we need inputs, outputs and change outputs for bitcoin?
// TODO: Encode direction of swap here
pub struct SetupParameters {
    grin_amount: u64,
    bitcoin_amount: u64,
    grin_fee: u64, // for simplicity we don't model separate fee values for different transactions
    bitcoin_fee: u64,
    grin_expiry: u64,    // block height
    bitcoin_expiry: u32, // absolute timestamp
}
