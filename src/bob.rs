use crate::{
    bitcoin,
    commit::Commitment,
    grin, keypair,
    messages::{Message0, Message1, Message2, Message3},
    setup_parameters::{self, SetupParameters},
};

pub struct Bob0 {
    init: SetupParameters,
    secret_grin_init: setup_parameters::GrinRedeemerSecret,
    SKs_alpha: grin::SKs,
    SKs_beta: bitcoin::SKs,
    alice_commitment: Commitment,
}

impl Bob0 {
    pub fn new(
        init: SetupParameters,
        secret_grin_init: setup_parameters::GrinRedeemerSecret,
        message0: Message0,
    ) -> (Bob0, Message1) {
        let SKs_alpha = grin::SKs::keygen();
        let SKs_beta = bitcoin::SKs::keygen();

        let message = Message1 {
            PKs_alpha: SKs_alpha.public(),
            PKs_beta: SKs_beta.public(),
        };

        let alice_commitment = message0.0;

        let state = Bob0 {
            init,
            secret_grin_init,
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
            beta_redeemer_signatures: alice_beta_refund_signature,
        }: Message2,
    ) -> Result<(Bob1, Message3), ()> {
        let (alice_PKs_alpha, alice_PKs_beta, Y) = opening.open(self.alice_commitment)?;

        let (beta_fund_action, beta_refund_action, beta_encrypted_redeem_signature) =
            bitcoin::sign::funder(
                &self.init.beta,
                &self.SKs_beta,
                &alice_PKs_beta,
                &Y,
                &alice_beta_refund_signature,
            )?;

        let alpha_redeemer_signatures = grin::sign::redeemer(
            &self.init.alpha,
            &self.secret_grin_init,
            &self.SKs_alpha,
            &alice_PKs_alpha,
            &Y,
        );

        Ok((
            Bob1 {
                init: self.init,
                secret_grin_init: self.secret_grin_init,
                SKs_alpha: self.SKs_alpha,
                SKs_beta: self.SKs_beta,
                alice_PKs_alpha,
                alice_PKs_beta,
                Y,
                beta_fund_action,
                beta_refund_action,
            },
            Message3 {
                beta_encrypted_redeem_signature,
                alpha_redeemer_signatures,
            },
        ))
    }
}

pub struct Bob1 {
    init: SetupParameters,
    secret_grin_init: setup_parameters::GrinRedeemerSecret,
    SKs_alpha: grin::SKs,
    SKs_beta: bitcoin::SKs,
    alice_PKs_alpha: grin::PKs,
    alice_PKs_beta: bitcoin::PKs,
    Y: keypair::PublicKey,
    beta_fund_action: bitcoin::action::Fund,
    beta_refund_action: bitcoin::action::Refund,
}
