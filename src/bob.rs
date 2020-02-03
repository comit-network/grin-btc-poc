use crate::{
    bitcoin,
    commit::Commitment,
    grin,
    messages::{Message0, Message1, Message2},
};

pub struct Bob0 {
    SKs_grin: grin::SKs,
    SKs_bitcoin: bitcoin::SKs,
    alice_commitment: Commitment,
}

impl Bob0 {
    pub fn new(message0: Message0) -> (Bob0, Message1) {
        let SKs_grin = grin::SKs::keygen();
        let SKs_bitcoin = bitcoin::SKs::keygen();

        let message = Message1 {
            PKs_grin: SKs_grin.public(),
            PKs_bitcoin: SKs_bitcoin.public(),
        };

        let alice_commitment = message0.0;

        let state = Bob0 {
            SKs_grin,
            SKs_bitcoin,
            alice_commitment,
        };

        (state, message)
    }

    pub fn receive(self, message2: Message2) -> Result<Bob1, ()> {
        let (alice_PKs_grin, alice_PKs_bitcoin) = message2.opening.open(self.alice_commitment)?;

        Ok(Bob1 {
            SKs_grin: self.SKs_grin,
            SKs_bitcoin: self.SKs_bitcoin,
            alice_PKs_grin,
            alice_PKs_bitcoin,
        })
    }
}

pub struct Bob1 {
    SKs_grin: grin::SKs,
    SKs_bitcoin: bitcoin::SKs,
    alice_PKs_grin: grin::PKs,
    alice_PKs_bitcoin: bitcoin::PKs,
}
