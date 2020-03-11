use crate::{
    commit::{Commitment, Opening},
    grin,
};

// Sent by Alice
pub struct Message0 {
    pub commitment: Commitment,
    pub bulletproof_round_1_alice: grin::bulletproof::Round1,
}

// Sent by Bob
pub struct Message1<A, B> {
    pub PKs_alpha: A,
    pub PKs_beta: B,
    pub bulletproof_round_1_bob: grin::bulletproof::Round1,
}

// Sent by Alice
pub struct Message2<B> {
    pub opening: Opening,
    pub beta_redeemer_sigs: B,
}

// Sent by Bob
pub struct Message3<A, B> {
    pub alpha_redeemer_sigs: A,
    pub beta_redeem_encsig: B,
}

// Sent by Alice
pub struct Message4<A> {
    pub alpha_redeem_encsig: A,
}
