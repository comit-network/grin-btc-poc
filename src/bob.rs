use crate::{
    bitcoin::{self, Hash},
    commit::Commitment,
    ecdsa, grin, keypair,
    messages::{Message0, Message1, Message2, Message3},
    setup_parameters::SetupParameters,
};
use secp256k1zkp::Message;

pub struct Bob0 {
    init: SetupParameters,
    SKs_alpha: grin::SKs,
    SKs_beta: bitcoin::SKs,
    alice_commitment: Commitment,
}

impl Bob0 {
    pub fn new(init: SetupParameters, message0: Message0) -> (Bob0, Message1) {
        let SKs_alpha = grin::SKs::keygen();
        let SKs_beta = bitcoin::SKs::keygen();

        let message = Message1 {
            PKs_grin: SKs_alpha.public(),
            PKs_bitcoin: SKs_beta.public(),
        };

        let alice_commitment = message0.0;

        let state = Bob0 {
            init,
            SKs_alpha,
            SKs_beta,
            alice_commitment,
        };

        (state, message)
    }

    pub fn receive(
        self,
        Message2 {
            opening,
            alice_beta_refund_signature,
        }: Message2,
    ) -> Result<(Bob1, Message3), ()> {
        let (alice_PKs_grin, alice_PKs_bitcoin, Y) = opening.open(self.alice_commitment)?;

        let (fund_action, refund_action, bob_beta_encrypted_redeem_signature) =
            bitcoin::sign::funder(
                &self.init.beta,
                &self.SKs_beta,
                &alice_PKs_bitcoin,
                &Y,
                &alice_beta_refund_signature,
            )?;

        Ok((
            Bob1 {
                SKs_alpha: self.SKs_alpha,
                SKs_beta: self.SKs_beta,
                alice_PKs_grin,
                alice_PKs_bitcoin,
                fund_action,
                refund_action,
            },
            Message3 {
                bob_beta_encrypted_redeem_signature,
            },
        ))
    }
}

pub struct Bob1 {
    SKs_alpha: grin::SKs,
    SKs_beta: bitcoin::SKs,
    alice_PKs_grin: grin::PKs,
    alice_PKs_bitcoin: bitcoin::PKs,
    fund_action: bitcoin::action::Fund,
    refund_action: bitcoin::action::Refund,
}
