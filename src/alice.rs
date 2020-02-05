use crate::{
    bitcoin::{self, Hash, SighashComponents},
    commit::{Commitment, Opening},
    grin, keypair,
    messages::{Message0, Message1, Message2},
    setup_parameters::SetupParameters,
};
use secp256k1zkp::Message;

// TODO: Figure out what to do with bulletproof keys, if anything. For now,
// ignore them since we don't know how we are gonna tackle them
pub struct Alice0 {
    init: SetupParameters,
    SKs_alpha: grin::SKs,
    SKs_beta: bitcoin::SKs,
    y: keypair::KeyPair,
}

impl Alice0 {
    pub fn new(init: SetupParameters) -> (Self, Message0) {
        let SKs_alpha = grin::SKs::keygen();
        let SKs_beta = bitcoin::SKs::keygen();
        let y = keypair::KeyPair::from_slice(b"yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy");

        let commitment = Commitment::commit(&SKs_alpha.public(), &SKs_beta.public(), &y.public_key);
        let message = Message0(commitment);

        let state = Alice0 {
            init,
            SKs_alpha,
            SKs_beta,
            y,
        };

        (state, message)
    }

    pub fn receive(self, message1: Message1) -> Result<(Alice1, Message2), ()> {
        let opening = Opening::new(
            self.SKs_alpha.public(),
            self.SKs_beta.public(),
            self.y.public_key,
        );

        let alice_beta_refund_signature =
            bitcoin::sign::redeemer(&self.init.beta, &self.SKs_beta, &message1.PKs_bitcoin);

        let message = Message2 {
            opening,
            alice_beta_refund_signature,
        };

        let state = Alice1 {
            init: self.init,
            SKs_alpha: self.SKs_alpha,
            SKs_beta: self.SKs_beta,
            bob_PKs_alpha: message1.PKs_grin,
            bob_PKs_beta: message1.PKs_bitcoin,
        };

        Ok((state, message))
    }
}

pub struct Alice1 {
    init: SetupParameters,
    SKs_alpha: grin::SKs,
    SKs_beta: bitcoin::SKs,
    bob_PKs_alpha: grin::PKs,
    bob_PKs_beta: bitcoin::PKs,
}
