use crate::{
    bitcoin,
    commit::{Commitment, Opening},
    ecdsa, grin,
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
    pub beta_redeemer_signatures: bitcoin::Signature,
}

// Sent by Bob
pub struct Message3 {
    pub beta_encrypted_redeem_signature: ecdsa::EncryptedSignature,
    pub alpha_redeemer_signatures: grin::GrinRedeemerSignatures,
}

// Sent by Alice
pub struct Message4;
