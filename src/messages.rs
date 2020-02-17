use crate::{
    bitcoin,
    commit::{Commitment, Opening},
    grin,
};

// Sent by Alice
pub struct Message0 {
    pub commitment: Commitment,
    pub bulletproof_round_1_alice: grin::bulletproof::Round1,
}

// Sent by Bob
pub struct Message1 {
    pub PKs_alpha: grin::PKs,
    pub PKs_beta: bitcoin::PKs,
    pub bulletproof_round_1_bob: grin::bulletproof::Round1,
}

// Sent by Alice
pub struct Message2 {
    pub opening: Opening,
    pub beta_redeemer_sigs: bitcoin::Signature,
}

// Sent by Bob
pub struct Message3 {
    pub beta_redeem_encsig: bitcoin::EncryptedSignature,
    pub alpha_redeemer_sigs: grin::GrinRedeemerSignatures,
    // depending on whether Grin is alpha or beta this will be in Message3 or Message4
    pub bulletproof_round_2_bob: grin::bulletproof::Round2,
}

// Sent by Alice
pub struct Message4 {
    pub alpha_redeem_encsig: grin::EncryptedSignature,
}
