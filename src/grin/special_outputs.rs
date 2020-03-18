use crate::{PublicKey, SecretKey};

#[derive(Clone)]
pub struct SpecialOutputs {
    pub fund_input_key: PublicKey,
    pub redeem_output_key: PublicKey,
    pub refund_output_key: PublicKey,
    // TODO: this doesn't belong here
    pub bulletproof_common_nonce: SecretKey,
}
