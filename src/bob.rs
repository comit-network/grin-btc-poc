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

        let (fund_transaction, fund_output_script) = bitcoin::transaction::fund_transaction(
            &self.init.beta,
            &alice_PKs_bitcoin.X,
            &self.SKs_beta.x.public_key,
        );

        let fund_action = bitcoin::action::Fund {
            transaction: fund_transaction.clone(),
            inputs: self
                .init
                .beta
                .inputs
                .iter()
                .map(|(i, _)| i.clone())
                .collect(),
        };

        let refund_transaction =
            bitcoin::transaction::refund_transaction(&self.init.beta, fund_transaction.txid());

        let refund_digest = bitcoin::SighashComponents::new(&refund_transaction).sighash_all(
            &refund_transaction.input[0],
            &fund_output_script,
            fund_transaction.output[0].value,
        );
        let refund_digest = Message::from_slice(&refund_digest.into_inner())
            .expect("Should not fail because it is a hash");

        if !keypair::verify_ecdsa(
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

        let redeem_transaction =
            bitcoin::transaction::redeem_transaction(&self.init.beta, fund_transaction.txid());
        let redeem_digest = bitcoin::SighashComponents::new(&redeem_transaction).sighash_all(
            &redeem_transaction.input[0],
            &fund_output_script,
            fund_transaction.output[0].value,
        );

        let bob_beta_encrypted_redeem_signature =
            ecdsa::encsign(&self.SKs_beta.x, &Y, &redeem_digest);

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
