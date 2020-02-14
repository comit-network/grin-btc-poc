use crate::{
    bitcoin,
    commit::Commitment,
    grin, keypair,
    messages::{Message0, Message1, Message2, Message3, Message4},
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

        let state = Bob0 {
            init,
            secret_grin_init,
            SKs_alpha: SKs_alpha.clone(),
            SKs_beta: SKs_beta.clone(),
            alice_commitment: message0.0,
        };

        let message = Message1 {
            PKs_alpha: SKs_alpha.public(),
            PKs_beta: SKs_beta.public(),
        };

        (state, message)
    }

    pub fn receive(
        self,
        Message2 {
            opening,
            beta_redeemer_sigs: alice_beta_refund_signature,
        }: Message2,
    ) -> Result<(Bob1, Message3), ()> {
        let (alice_PKs_alpha, alice_PKs_beta, Y) = opening.open(self.alice_commitment)?;

        let (beta_actions, beta_redeem_encsig) = bitcoin::sign::funder(
            &self.init.beta,
            &self.SKs_beta,
            &alice_PKs_beta,
            &Y,
            &alice_beta_refund_signature,
        )?;

        let alpha_redeemer_sigs = grin::sign::redeemer(
            &self.init.alpha,
            &self.secret_grin_init,
            &self.SKs_alpha,
            &alice_PKs_alpha,
            &Y,
        );

        let state = Bob1 {
            init: self.init,
            secret_grin_init: self.secret_grin_init,
            SKs_alpha: self.SKs_alpha,
            SKs_beta: self.SKs_beta,
            alice_PKs_alpha,
            alice_PKs_beta,
            Y,
            beta_fund_action: beta_actions.fund,
            beta_refund_action: beta_actions.refund,
        };

        let message = Message3 {
            beta_redeem_encsig,
            alpha_redeemer_sigs,
        };

        Ok((state, message))
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

impl Bob1 {
    pub fn receive(self, message: Message4) -> Result<Bob2, ()> {
        let alpha_encrypted_redeem_action = grin::action::EncryptedRedeem::new(
            self.init.alpha,
            self.secret_grin_init,
            self.SKs_alpha,
            self.alice_PKs_alpha,
            self.Y,
            message.alpha_redeem_encsig,
        )?;

        Ok(Bob2 {
            beta_fund_action: self.beta_fund_action,
            beta_refund_action: self.beta_refund_action,
            alpha_encrypted_redeem_action,
        })
    }
}

pub struct Bob2 {
    beta_fund_action: bitcoin::action::Fund,
    beta_refund_action: bitcoin::action::Refund,
    alpha_encrypted_redeem_action: grin::action::EncryptedRedeem,
}
