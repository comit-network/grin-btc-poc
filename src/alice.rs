use crate::{
    bitcoin,
    commit::{Commitment, Opening},
    grin, keypair,
    messages::{Message0, Message1, Message2, Message3, Message4},
    PublicKey,
};

pub struct Alice0<AL, BL> {
    alpha_state: AL,
    beta_state: BL,
    y: keypair::KeyPair,
}

impl Alice0<grin::AliceFunder0, bitcoin::AliceRedeemer0> {
    pub fn new(
        base_parameters_grin: grin::BaseParameters,
        base_parameters_bitcoin: bitcoin::BaseParameters,
        secret_init_grin: grin::FunderSecret,
    ) -> anyhow::Result<(Self, Message0)> {
        let grin_state = grin::alice::AliceFunder0::new(base_parameters_grin, secret_init_grin)?;
        let bitcoin_state = bitcoin::alice::AliceRedeemer0::new(base_parameters_bitcoin);

        Ok(Alice0::state_and_message(
            grin_state.clone(),
            bitcoin_state,
            grin_state.bulletproof_round_1_self,
        ))
    }

    pub fn receive(
        mut self,
        message: Message1<grin::PKs, bitcoin::PKs>,
    ) -> anyhow::Result<(
        Alice1<grin::AliceFunder1, bitcoin::AliceRedeemer1>,
        Message2<bitcoin::Signature>,
    )> {
        // Creating the opening must happen before transitioning Grin, because some keys
        // may be modified
        let opening = Opening::new(
            self.alpha_state.clone().into(),
            self.beta_state.clone().into(),
            self.y.public_key,
        );

        let grin_state = self.alpha_state.transition(
            message.PKs_alpha,
            &mut self.y,
            message.bulletproof_round_1_bob,
        )?;
        let (bitcoin_state, bitcoin_redeemer_refund_sig) =
            self.beta_state.transition(message.PKs_beta);

        Ok((
            Alice1 {
                y: self.y,
                alpha_state: grin_state,
                beta_state: bitcoin_state,
            },
            Message2 {
                opening,
                beta_redeemer_sigs: bitcoin_redeemer_refund_sig,
            },
        ))
    }
}

impl Alice0<bitcoin::AliceFunder0, grin::AliceRedeemer0> {
    pub fn new(
        base_parameters_bitcoin: bitcoin::BaseParameters,
        base_parameters_grin: grin::BaseParameters,
        secret_init_grin: grin::RedeemerSecret,
    ) -> anyhow::Result<(Self, Message0)> {
        let bitcoin_state = bitcoin::alice::AliceFunder0::new(base_parameters_bitcoin);
        let grin_state = grin::alice::AliceRedeemer0::new(base_parameters_grin, secret_init_grin)?;

        Ok(Alice0::state_and_message(
            bitcoin_state,
            grin_state.clone(),
            grin_state.bulletproof_round_1_self,
        ))
    }

    pub fn receive(
        mut self,
        message: Message1<bitcoin::PKs, grin::PKs>,
    ) -> anyhow::Result<(
        Alice1<bitcoin::AliceFunder1, grin::AliceRedeemer1>,
        Message2<grin::RedeemerSigs>,
    )> {
        let opening = Opening::new(
            self.alpha_state.clone().into(),
            self.beta_state.clone().into(),
            self.y.public_key,
        );

        let bitcoin_state = self.alpha_state.transition(message.PKs_alpha);
        let (grin_state, grin_redeemer_sigs) = self.beta_state.transition(
            message.PKs_beta,
            &mut self.y,
            message.bulletproof_round_1_bob,
        )?;

        Ok((
            Alice1 {
                y: self.y,
                alpha_state: bitcoin_state,
                beta_state: grin_state,
            },
            Message2 {
                opening,
                beta_redeemer_sigs: grin_redeemer_sigs,
            },
        ))
    }
}

impl<A, B> Alice0<A, B> {
    pub fn state_and_message(
        alpha_state: A,
        beta_state: B,
        bulletproof_round_1_alice: grin::bulletproof::Round1,
    ) -> (Self, Message0)
    where
        A: Into<Vec<PublicKey>> + Clone,
        B: Into<Vec<PublicKey>> + Clone,
    {
        let y = keypair::KeyPair::new_random();

        let commitment = Commitment::commit(
            alpha_state.clone().into(),
            beta_state.clone().into(),
            &y.public_key,
        );

        let state = Alice0 {
            alpha_state,
            beta_state,
            y,
        };

        let message = Message0 {
            commitment,
            bulletproof_round_1_alice,
        };

        (state, message)
    }
}

pub struct Alice1<AL, BL> {
    alpha_state: AL,
    beta_state: BL,
    y: keypair::KeyPair,
}

impl Alice1<grin::AliceFunder1, bitcoin::AliceRedeemer1> {
    pub fn receive(
        self,
        message: Message3<grin::RedeemerSigs, bitcoin::EncryptedSignature>,
    ) -> anyhow::Result<(
        Alice2<grin::AliceFunder2, bitcoin::AliceRedeemer2>,
        Message4,
    )> {
        let (grin_state, grin_redeem_encsig) = self.alpha_state.transition(
            message.alpha_redeemer_sigs,
            &self.y,
            message.bulletproof_round_2_bob,
        )?;
        let bitcoin_state = self
            .beta_state
            .transition(message.beta_redeem_encsig, &self.y);

        let state = Alice2 {
            alpha_state: grin_state,
            beta_state: bitcoin_state,
        };

        let message = Message4 {
            alpha_redeem_encsig: grin_redeem_encsig,
        };

        Ok((state, message))
    }
}

pub struct Alice2<AL, BL> {
    pub alpha_state: AL,
    pub beta_state: BL,
}
