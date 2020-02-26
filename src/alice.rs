use crate::{
    bitcoin,
    commit::{Commitment, Opening},
    grin, keypair,
    messages::{Message0, Message1, Message2, Message3, Message4},
    setup_parameters::{self, SetupParameters},
};

pub struct Alice0 {
    init: SetupParameters,
    secret_init_grin: setup_parameters::GrinFunderSecret,
    SKs_alpha: grin::SKs,
    SKs_beta: bitcoin::SKs,
    bulletproof_round_1_alice: grin::bulletproof::Round1,
    y: keypair::KeyPair,
}

impl Alice0 {
    pub fn new(
        init: SetupParameters,
        secret_init_grin: setup_parameters::GrinFunderSecret,
    ) -> anyhow::Result<(Self, Message0)> {
        let (SKs_alpha, bulletproof_round_1_alice) = grin::keygen()?;
        let SKs_beta = bitcoin::SKs::keygen();
        let y = keypair::KeyPair::new_random();

        let commitment = Commitment::commit(&SKs_alpha.public(), &SKs_beta.public(), &y.public_key);

        let state = Alice0 {
            init,
            secret_init_grin,
            SKs_alpha,
            SKs_beta,
            y,
            bulletproof_round_1_alice: bulletproof_round_1_alice.clone(),
        };

        let message = Message0 {
            commitment,
            bulletproof_round_1_alice,
        };

        Ok((state, message))
    }

    pub fn receive(mut self, mut message: Message1) -> anyhow::Result<(Alice1, Message2)> {
        let opening = Opening::new(
            self.SKs_alpha.public(),
            self.SKs_beta.public(),
            self.y.public_key,
        );

        grin::normalize_redeem_keys_alice(
            &mut self.SKs_alpha.r_redeem,
            &mut message.PKs_alpha.R_redeem,
            &mut self.y,
        )?;

        let beta_redeemer_sigs =
            bitcoin::sign::redeemer(&self.init.beta, &self.SKs_beta, &message.PKs_beta);

        let state = Alice1 {
            init: self.init,
            secret_init_grin: self.secret_init_grin,
            SKs_alpha: self.SKs_alpha,
            SKs_beta: self.SKs_beta,
            bob_PKs_alpha: message.PKs_alpha,
            bob_PKs_beta: message.PKs_beta,
            bulletproof_round_1_alice: self.bulletproof_round_1_alice,
            bulletproof_round_1_bob: message.bulletproof_round_1_bob,
            y: self.y,
        };

        let message = Message2 {
            opening,
            beta_redeemer_sigs,
        };

        Ok((state, message))
    }
}

pub struct Alice1 {
    init: SetupParameters,
    secret_init_grin: setup_parameters::GrinFunderSecret,
    SKs_alpha: grin::SKs,
    SKs_beta: bitcoin::SKs,
    bob_PKs_alpha: grin::PKs,
    bob_PKs_beta: bitcoin::PKs,
    bulletproof_round_1_alice: grin::bulletproof::Round1,
    bulletproof_round_1_bob: grin::bulletproof::Round1,
    y: keypair::KeyPair,
}

impl Alice1 {
    pub fn receive(self, message: Message3) -> anyhow::Result<(Alice2, Message4)> {
        let (alpha_actions, alpha_redeem_encsig) = grin::sign::funder(
            &self.init.alpha,
            &self.secret_init_grin,
            &self.SKs_alpha,
            &self.bob_PKs_alpha,
            &self.y.public_key,
            message.alpha_redeemer_sigs,
            &self.bulletproof_round_1_bob,
            &self.bulletproof_round_1_alice,
            &message.bulletproof_round_2_bob,
        )?;

        let beta_encrypted_redeem_action = bitcoin::action::EncryptedRedeem::new(
            &self.init.beta,
            &self.SKs_beta,
            &self.bob_PKs_beta,
            message.beta_redeem_encsig,
        );
        let beta_redeem_action = beta_encrypted_redeem_action.decrypt(&self.y);

        let state = Alice2 {
            alpha_fund_action: alpha_actions.fund,
            alpha_refund_action: alpha_actions.refund,
            beta_redeem_action,
        };

        let message = Message4 {
            alpha_redeem_encsig,
        };

        Ok((state, message))
    }
}

pub struct Alice2 {
    pub alpha_fund_action: grin::action::Fund,
    pub alpha_refund_action: grin::action::Refund,
    pub beta_redeem_action: bitcoin::action::Redeem,
}
