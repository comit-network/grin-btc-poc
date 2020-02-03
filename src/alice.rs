use crate::{
    bitcoin,
    commit::{Commitment, Opening},
    grin,
    messages::{Message0, Message1, Message2},
};

// TODO: Figure out what to do with bulletproof keys, if anything. For now,
// ignore them since we don't know how we are gonna tackle them
pub struct Alice0 {
    SKs_grin: grin::SKs,
    SKs_bitcoin: bitcoin::SKs,
    y: grin::KeyPair,
}

impl Alice0 {
    pub fn new() -> (Self, Message0) {
        let SKs_grin = grin::SKs::keygen();
        let SKs_bitcoin = bitcoin::SKs::keygen();
        let y = grin::KeyPair::from_slice(b"yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy");

        let commitment =
            Commitment::commit(&SKs_grin.public(), &SKs_bitcoin.public(), &y.public_key);
        let message = Message0(commitment);

        let state = Alice0 {
            SKs_grin: SKs_grin.clone(),
            SKs_bitcoin: SKs_bitcoin.clone(),
            y,
        };

        (state, message)
    }

    pub fn receive(self, message1: Message1) -> (Alice1, Message2) {
        // TODO: Include first phase of signing in this message. It should depend on
        // whether we are doing grin-btc or btc-grin
        let opening = Opening::new(
            self.SKs_grin.public(),
            self.SKs_bitcoin.public(),
            self.y.public_key,
        );
        let message = Message2 { opening };

        let state = Alice1 {
            SKs_grin: self.SKs_grin,
            SKs_bitcoin: self.SKs_bitcoin,
            bob_PKs_grin: message1.PKs_grin,
            bob_PKs_bitcoin: message1.PKs_bitcoin,
        };

        (state, message)
    }
}

pub struct Alice1 {
    SKs_grin: grin::SKs,
    SKs_bitcoin: bitcoin::SKs,
    bob_PKs_grin: grin::PKs,
    bob_PKs_bitcoin: bitcoin::PKs,
}
