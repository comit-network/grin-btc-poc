use crate::{
    bitcoin,
    commit::{Commitment, Opening},
    grin,
    messages::{Message0, Message1, Message2, Message3, Message4},
    KeyPair, PublicKey,
};
use grin::bulletproof;

pub struct Alice0<AL, BL> {
    alpha_state: AL,
    beta_state: BL,
    y: KeyPair,
}

impl Alice0<grin::AliceFunder0, bitcoin::AliceRedeemer0> {
    pub fn new(
        offer_grin: grin::Offer,
        outputs_grin: grin::SpecialOutputs,
        output_keypairs_grin_funder: grin::SpecialOutputKeyPairsFunder,
        offer_bitcoin: bitcoin::Offer,
        outputs_bitcoin: bitcoin::WalletOutputs,
    ) -> anyhow::Result<(Self, Message0)> {
        let grin_state =
            grin::alice::AliceFunder0::new(offer_grin, outputs_grin, output_keypairs_grin_funder)?;
        let bitcoin_state = bitcoin::alice::AliceRedeemer0::new(offer_bitcoin, outputs_bitcoin);

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
        // Building the opening must happen now, because some keys may change when
        // transitioning Grin's state and Alice has already committed to the original
        // ones
        let opening = self.opening();

        let grin_state = self.alpha_state.transition(
            message.PKs_alpha,
            &mut self.y,
            message.bulletproof_round_1_bob,
        )?;
        let (bitcoin_state, bitcoin_redeemer_refund_sig) =
            self.beta_state.transition(message.PKs_beta)?;

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
        offer_bitcoin: bitcoin::Offer,
        outputs_bitcoin: bitcoin::WalletOutputs,
        offer_grin: grin::Offer,
        outputs_grin: grin::SpecialOutputs,
        output_keypairs_grin_redeemer: grin::SpecialOutputKeyPairsRedeemer,
    ) -> anyhow::Result<(Self, Message0)> {
        let bitcoin_state = bitcoin::alice::AliceFunder0::new(offer_bitcoin, outputs_bitcoin);
        let grin_state = grin::alice::AliceRedeemer0::new(
            offer_grin,
            outputs_grin,
            output_keypairs_grin_redeemer,
        )?;

        Ok(Alice0::state_and_message(
            bitcoin_state,
            grin_state.clone(),
            grin_state.bulletproof_round_1_self,
        ))
    }

    #[allow(clippy::type_complexity)]
    pub fn receive(
        mut self,
        message: Message1<bitcoin::PKs, grin::PKs>,
    ) -> anyhow::Result<(
        Alice1<bitcoin::AliceFunder1, grin::AliceRedeemer1>,
        Message2<(grin::RedeemerSigs, grin::bulletproof::Round2)>,
    )> {
        // Building the opening must happen now, because some keys may change when
        // transitioning Grin's state and Alice has already committed to the original
        // ones
        let opening = self.opening();

        let bitcoin_state = self.alpha_state.transition(message.PKs_alpha);
        let (grin_state, grin_redeemer_sigs, bulletproof_round_2_alice) =
            self.beta_state.transition(
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
                beta_redeemer_sigs: (grin_redeemer_sigs, bulletproof_round_2_alice),
            },
        ))
    }
}

//TODO: Move trait bounds from functions onto the impl Give the trait a
// descriptive name.  Maybe HasCoinTossingKeys with a function
// coin_tossing_keys()
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
        let y = KeyPair::new_random();

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

    pub fn opening(&self) -> Opening
    where
        A: Into<Vec<PublicKey>> + Clone,
        B: Into<Vec<PublicKey>> + Clone,
    {
        Opening::new(
            self.alpha_state.clone().into(),
            self.beta_state.clone().into(),
            self.y.public_key,
        )
    }
}

pub struct Alice1<AL, BL> {
    alpha_state: AL,
    beta_state: BL,
    y: KeyPair,
}

impl Alice1<grin::AliceFunder1, bitcoin::AliceRedeemer1> {
    pub fn receive(
        self,
        message: Message3<(grin::RedeemerSigs, bulletproof::Round2), bitcoin::EncryptedSignature>,
    ) -> anyhow::Result<(
        Alice2<grin::AliceFunder2, bitcoin::AliceRedeemer2>,
        Message4<grin::EncryptedSignature>,
    )> {
        let (grin_state, grin_redeem_encsig) = self.alpha_state.transition(
            message.alpha_redeemer_sigs.0,
            &self.y,
            message.alpha_redeemer_sigs.1,
        )?;
        let bitcoin_state = self
            .beta_state
            .transition(message.beta_redeem_encsig, &self.y)?;

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

impl Alice1<bitcoin::AliceFunder1, grin::AliceRedeemer1> {
    pub fn receive(
        self,
        Message3 {
            alpha_redeemer_sigs: bob_bitcoin_refund_signature,
            beta_redeem_encsig: grin_redeem_encsig,
            ..
        }: Message3<bitcoin::Signature, grin::EncryptedSignature>,
    ) -> anyhow::Result<(
        Alice2<bitcoin::AliceFunder2, grin::AliceRedeemer2>,
        Message4<bitcoin::EncryptedSignature>,
    )> {
        let (bitcoin_state, bitcoin_redeem_encsig) = self
            .alpha_state
            .transition(bob_bitcoin_refund_signature, &self.y)?;
        let grin_state = self.beta_state.transition(self.y, grin_redeem_encsig)?;

        let state = Alice2 {
            alpha_state: bitcoin_state,
            beta_state: grin_state,
        };

        let message = Message4 {
            alpha_redeem_encsig: bitcoin_redeem_encsig,
        };

        Ok((state, message))
    }
}

pub struct Alice2<AL, BL> {
    pub alpha_state: AL,
    pub beta_state: BL,
}
