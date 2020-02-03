use crate::{
    bitcoin::{self, Hash},
    commit::Commitment,
    grin,
    messages::{Message0, Message1, Message2},
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

    pub fn receive(self, message2: Message2) -> Result<Bob1, ()> {
        let (alice_PKs_grin, alice_PKs_bitcoin) = message2.opening.open(self.alice_commitment)?;

        let (fund_transaction, fund_output_script) = bitcoin::transaction::fund_transaction(
            &self.init.beta,
            &alice_PKs_bitcoin.X,
            &self.SKs_beta.x.public_key,
        );

        let refund_transaction =
            bitcoin::transaction::refund_transaction(&self.init.beta, fund_transaction.txid());

        let refund_digest = bitcoin::SighashComponents::new(&refund_transaction).sighash_all(
            &refund_transaction.input[0],
            &fund_output_script,
            fund_transaction.output[0].value,
        );
        let refund_digest = Message::from_slice(&refund_digest.into_inner())
            .expect("Should not fail because it is a hash");

        let alice_beta_refund_signature = message2.alice_beta_refund_signature;
        if !bitcoin::keypair::verify_ecdsa(
            &refund_digest,
            &alice_beta_refund_signature,
            &alice_PKs_bitcoin.X,
        ) {
            return Err(());
        }

        let bob_beta_refund_signature = self.SKs_beta.x.sign_ecdsa(&refund_digest);

        let refund_action = bitcoin::action::Refund::new(
            refund_transaction,
            alice_beta_refund_signature,
            bob_beta_refund_signature,
        );

        Ok(Bob1 {
            SKs_alpha: self.SKs_alpha,
            SKs_beta: self.SKs_beta,
            alice_PKs_grin,
            alice_PKs_bitcoin,
            refund_action,
        })
    }
}

pub struct Bob1 {
    SKs_alpha: grin::SKs,
    SKs_beta: bitcoin::SKs,
    alice_PKs_grin: grin::PKs,
    alice_PKs_bitcoin: bitcoin::PKs,
    refund_action: bitcoin::action::Refund,
}
