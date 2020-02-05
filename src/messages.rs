use crate::{
    bitcoin,
    commit::{Commitment, Opening},
    ecdsa, grin,
};

pub struct Message0(pub Commitment);

pub struct Message1 {
    pub PKs_grin: grin::PKs,
    pub PKs_bitcoin: bitcoin::PKs,
}

pub struct Message2 {
    pub opening: Opening,
    pub alice_beta_refund_signature: bitcoin::Signature,
}

pub struct Message3 {
    pub bob_beta_encrypted_redeem_signature: ecdsa::EncryptedSignature,
}
