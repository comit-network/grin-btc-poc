use crate::{
    bitcoin,
    commit::{Commitment, Opening},
    grin,
};

// Sent by Alice
pub struct Message0(pub Commitment);

// Sent by Bob
pub struct Message1 {
    pub PKs_alpha: grin::PKs,
    pub PKs_beta: bitcoin::PKs,
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
}

// Sent by Alice
pub struct Message4 {
    pub alpha_redeem_encsig: grin::EncryptedSignature,
}
