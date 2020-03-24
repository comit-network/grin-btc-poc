use crate::{
    bitcoin,
    commit::{CoinTossingKeys, Commitment, Opening},
    grin,
    messages::{Message0, Message1, Message2, Message3, Message4},
    KeyPair,
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

        // Compose together the keys generated for Grin and Bitcoin with the things that
        // only Alice has to generate i.e. the encryption key and the commitment
        Ok(Alice0::state_and_message(
            grin_state.clone(),
            bitcoin_state,
            grin_state.bulletproof_round_1_self,
        ))
    }

    pub fn receive(
        self,
        message: Message1<grin::PKs, bitcoin::PKs>,
    ) -> anyhow::Result<(
        Alice1<grin::AliceFunder1, bitcoin::AliceRedeemer1>,
        Message2<bitcoin::Signature>,
    )> {
        let opening = self.opening();

        let grin_state = self
            .alpha_state
            .transition(message.PKs_alpha, message.bulletproof_round_1_bob)?;
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
    /// Start the key generation for Alice when swapping bitcoin for grin. Also
    /// prepare commitment to public keys, which will be sent to Bob, and kick
    /// off multi-party bulletproof protocol.
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

    /// Incorporate Bob public keys from `Message1` and execute Grin signing
    /// protocol for Alice as redeemer of Grin. Also prepare opening of
    /// prior commitment to public keys, which will be sent to Bob, and
    /// continue with multi-party bulletproof protocol.
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

impl<A, B> Alice0<A, B>
where
    A: Into<CoinTossingKeys> + Clone,
    B: Into<CoinTossingKeys> + Clone,
{
    /// Compose the state of alpha ledger and beta ledger after key generation,
    /// together with the encryption keypair, something which only Alice
    /// generates; generate the commitment to Alice's public keys which will be
    /// sent to Bob; and add the first round of the bulletproof protocol for
    /// Alice to the message to be sent to Bob.
    pub fn state_and_message(
        alpha_state: A,
        beta_state: B,
        bulletproof_round_1_alice: grin::bulletproof::Round1,
    ) -> (Self, Message0) {
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

    /// Generate the opening which will reveal to Bob the keys Alice committed
    /// to. Bob will be able to verify this by hashing the opening and comparing
    /// it with the commitment.
    pub fn opening(&self) -> Opening {
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

/// Generate redeem action by decrypting the encrypted redeem signature sent by
/// Bob in `Message3`; execute signing protocol for Alice as funder of Bitcoin
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
