use crate::{
    bitcoin,
    commit::Commitment,
    grin::{self, bulletproof, FunderSecret, RedeemerSecret},
    keypair,
    messages::{Message0, Message1, Message2, Message3, Message4},
};
use std::convert::TryInto;

pub struct Bob0<AL, BL> {
    alpha_state: AL,
    beta_state: BL,
    alice_commitment: Commitment,
}

impl Bob0<grin::BobRedeemer0, bitcoin::BobFunder0> {
    pub fn new(
        base_parameters_grin: grin::BaseParameters,
        base_parameters_bitcoin: bitcoin::BaseParameters,
        secret_init_grin: RedeemerSecret,
        message: Message0,
    ) -> anyhow::Result<(Self, Message1<grin::PKs, bitcoin::PKs>)> {
        let alice_commitment = message.commitment;

        let grin_state = grin::bob::BobRedeemer0::new(
            base_parameters_grin,
            secret_init_grin,
            message.bulletproof_round_1_alice,
        )?;
        let bitcoin_state = bitcoin::bob::BobFunder0::new(base_parameters_bitcoin);

        Ok(Bob0::state_and_message(
            grin_state.clone(),
            bitcoin_state,
            alice_commitment,
            grin_state.bulletproof_round_1_self,
        ))
    }

    pub fn receive(
        self,
        Message2 {
            opening,
            beta_redeemer_sigs: alice_bitcoin_refund_signature,
        }: Message2<bitcoin::Signature>,
    ) -> anyhow::Result<(
        Bob1<grin::BobRedeemer1, bitcoin::BobFunder1>,
        Message3<grin::RedeemerSigs, bitcoin::EncryptedSignature>,
    )> {
        let (alice_PKs_grin, alice_PKs_bitcoin, Y) = opening.open(self.alice_commitment)?;

        let (grin_state, grin_redeemer_sigs, bulletproof_round_1_self) =
            self.alpha_state.transition(alice_PKs_grin.try_into()?, Y)?;
        let (bitcoin_state, bitcoin_redeem_encsig) = self.beta_state.transition(
            alice_PKs_bitcoin.try_into()?,
            alice_bitcoin_refund_signature,
            &Y,
        )?;

        let state = Bob1 {
            alpha_state: grin_state,
            beta_state: bitcoin_state,
            Y,
        };

        let message = Message3 {
            alpha_redeemer_sigs: grin_redeemer_sigs,
            beta_redeem_encsig: bitcoin_redeem_encsig,
            bulletproof_round_2_bob: bulletproof_round_1_self,
        };

        Ok((state, message))
    }
}

impl Bob0<bitcoin::BobRedeemer0, grin::BobFunder0> {
    pub fn new(
        base_parameters_grin: grin::BaseParameters,
        base_parameters_bitcoin: bitcoin::BaseParameters,
        secret_init_grin: FunderSecret,
        message: Message0,
    ) -> anyhow::Result<(Self, Message1<bitcoin::PKs, grin::PKs>)> {
        let alice_commitment = message.commitment;

        let bitcoin_state = bitcoin::bob::BobRedeemer0::new(base_parameters_bitcoin);
        let grin_state = grin::bob::BobFunder0::new(
            base_parameters_grin,
            secret_init_grin,
            message.bulletproof_round_1_alice,
        )?;

        Ok(Bob0::state_and_message(
            bitcoin_state,
            grin_state.clone(),
            alice_commitment,
            grin_state.bulletproof_round_1_self,
        ))
    }

    pub fn receive(
        self,
        Message2 {
            opening,
            beta_redeemer_sigs: alice_bitcoin_refund_signature,
        }: Message2<bitcoin::Signature>,
    ) -> anyhow::Result<(
        Bob1<grin::BobRedeemer1, bitcoin::BobFunder1>,
        Message3<grin::RedeemerSigs, bitcoin::EncryptedSignature>,
    )> {
        unimplemented!()
    }
}

impl<A, B> Bob0<A, B> {
    pub fn state_and_message<APKs, BPKs>(
        alpha_state: A,
        beta_state: B,
        alice_commitment: Commitment,
        bulletproof_round_1_bob: bulletproof::Round1,
    ) -> (Self, Message1<APKs, BPKs>)
    where
        A: Into<APKs> + Clone,
        B: Into<BPKs> + Clone,
    {
        let state = Bob0 {
            alpha_state: alpha_state.clone(),
            beta_state: beta_state.clone(),
            alice_commitment,
        };

        let message = Message1 {
            PKs_alpha: alpha_state.into(),
            PKs_beta: beta_state.into(),
            bulletproof_round_1_bob,
        };

        (state, message)
    }
}

pub struct Bob1<AL, BL> {
    alpha_state: AL,
    beta_state: BL,
    Y: keypair::PublicKey,
}

impl Bob1<grin::BobRedeemer1, bitcoin::BobFunder1> {
    pub fn receive(
        self,
        message: Message4,
    ) -> anyhow::Result<Bob2<grin::BobRedeemer2, bitcoin::BobFunder2>> {
        let grin_state = self
            .alpha_state
            .transition(self.Y, message.alpha_redeem_encsig)?;
        let bitcoin_state = self.beta_state.transition()?;

        Ok(Bob2 {
            alpha_state: grin_state,
            beta_state: bitcoin_state,
        })
    }
}

pub struct Bob2<AL, BL> {
    pub alpha_state: AL,
    pub beta_state: BL,
}
