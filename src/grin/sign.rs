use crate::{
    grin::{
        action, bulletproof, compute_excess_pk, compute_excess_sk, compute_offset, KernelFeatures,
        Offer, PKs, SKs, SpecialOutputKeyPairsFunder, SpecialOutputKeyPairsRedeemer,
        SpecialOutputs,
    },
    keypair::{random_secret_key, KeyPair, PublicKey, SECP},
    schnorr,
};

pub struct RedeemerSigs {
    pub s_fund: schnorr::PartialSignature,
    pub s_refund: schnorr::PartialSignature,
    pub s_hat_redeem: schnorr::PartialEncryptedSignature,
}

#[allow(clippy::too_many_arguments)]
pub fn redeemer(
    offer: &Offer,
    special_outputs: &SpecialOutputs,
    special_output_keypairs_redeemer: &SpecialOutputKeyPairsRedeemer,
    redeemer_SKs: &SKs,
    funder_PKs: &PKs,
    Y: &PublicKey,
    bulletproof_common_nonce: &bulletproof::CommonNonce,
    bulletproof_round_1_redeemer: &bulletproof::Round1,
    bulletproof_round_1_funder: &bulletproof::Round1,
) -> anyhow::Result<(RedeemerSigs, bulletproof::Round2)> {
    let (s_fund, bulletproof_round_2_redeemer) = {
        let offset = compute_offset(&funder_PKs.R_fund, &redeemer_SKs.r_fund.public_key)?;

        let half_excess_keypair_redeemer = KeyPair::new(compute_excess_sk(
            vec![],
            vec![&redeemer_SKs.x.secret_key],
            Some(&offset),
        )?);

        let s_fund = {
            let half_excess_pk_funder = compute_excess_pk(
                vec![&special_outputs.fund_input_key],
                vec![&funder_PKs.X],
                None,
            )?;

            schnorr::sign_2p_0(
                &half_excess_keypair_redeemer,
                &redeemer_SKs.r_fund,
                &half_excess_pk_funder,
                &funder_PKs.R_fund,
                &KernelFeatures::Plain { fee: 0 }.kernel_sig_msg()?,
            )?
        };

        let bulletproof_round_2_redeemer = {
            let excess_pk = PublicKey::from_combination(&*SECP, vec![
                &redeemer_SKs.x.public_key,
                &funder_PKs.X,
            ])?;

            bulletproof::Round2::new(
                &redeemer_SKs.x.secret_key,
                &redeemer_SKs.x.secret_key,
                &excess_pk,
                offer.fund_output_amount(),
                &bulletproof_common_nonce,
                &bulletproof_round_1_redeemer,
                &bulletproof_round_1_funder,
            )?
        };

        (s_fund, bulletproof_round_2_redeemer)
    };

    let s_refund = {
        let offset = compute_offset(&funder_PKs.R_refund, &redeemer_SKs.r_refund.public_key)?;

        let half_excess_keypair_redeemer = {
            let half_excess_sk_redeemer =
                compute_excess_sk(vec![&redeemer_SKs.x.secret_key], vec![], Some(&offset))?;
            KeyPair::new(half_excess_sk_redeemer)
        };

        let half_excess_pk_funder = compute_excess_pk(
            vec![&funder_PKs.X],
            vec![&special_outputs.refund_output_key],
            None,
        )?;

        schnorr::sign_2p_0(
            &half_excess_keypair_redeemer,
            &redeemer_SKs.r_refund,
            &half_excess_pk_funder,
            &funder_PKs.R_refund,
            &KernelFeatures::HeightLocked {
                fee: 0,
                lock_height: offer.expiry,
            }
            .kernel_sig_msg()?,
        )?
    };

    let s_hat_redeem = {
        let offset = compute_offset(&funder_PKs.R_redeem, &redeemer_SKs.r_redeem.public_key)?;

        let half_excess_keypair_redeemer = KeyPair::new(compute_excess_sk(
            vec![&redeemer_SKs.x.secret_key],
            vec![
                &special_output_keypairs_redeemer
                    .redeem_output_key
                    .secret_key,
            ],
            Some(&offset),
        )?);

        let half_excess_pk_funder = compute_excess_pk(vec![&funder_PKs.X], vec![], None)?;

        schnorr::encsign_2p_0(
            &half_excess_keypair_redeemer,
            &redeemer_SKs.r_redeem,
            &half_excess_pk_funder,
            &funder_PKs.R_redeem,
            &Y,
            &KernelFeatures::Plain { fee: 0 }.kernel_sig_msg()?,
        )?
    };

    Ok((
        RedeemerSigs {
            s_fund,
            s_refund,
            s_hat_redeem,
        },
        bulletproof_round_2_redeemer,
    ))
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum RedeemerSignatureError {
    #[error("fund")]
    Fund,
    #[error("redeem")]
    Redeem,
    #[error("refund")]
    Refund,
}

pub struct FunderActions {
    pub fund: action::Fund,
    pub refund: action::Refund,
}

#[allow(clippy::too_many_arguments)]
pub fn funder(
    offer: &Offer,
    special_outputs: &SpecialOutputs,
    special_output_keypairs_funder: &SpecialOutputKeyPairsFunder,
    funder_SKs: &SKs,
    redeemer_PKs: &PKs,
    Y: &PublicKey,
    RedeemerSigs {
        s_fund: s_fund_redeemer,
        s_refund: s_refund_redeemer,
        s_hat_redeem: s_hat_redeem_redeemer,
    }: RedeemerSigs,
    bulletproof_common_nonce: &bulletproof::CommonNonce,
    bulletproof_round_1_redeemer: &bulletproof::Round1,
    bulletproof_round_1_funder: &bulletproof::Round1,
    bulletproof_round_2_redeemer: &bulletproof::Round2,
) -> anyhow::Result<(FunderActions, schnorr::EncryptedSignature)> {
    let X = PublicKey::from_combination(&*SECP, vec![&redeemer_PKs.X, &funder_SKs.x.public_key])?;

    let fund = {
        let offset = compute_offset(&funder_SKs.r_fund.public_key, &redeemer_PKs.R_fund)?;

        let half_excess_keypair_funder = KeyPair::new(compute_excess_sk(
            vec![&special_output_keypairs_funder.fund_input_key.secret_key],
            vec![&funder_SKs.x.secret_key],
            None,
        )?);

        let half_excess_pk_redeemer =
            compute_excess_pk(vec![], vec![&redeemer_PKs.X], Some(&offset))?;

        let kernel_features = KernelFeatures::Plain { fee: 0 };

        let (excess_sig, excess_pk) = schnorr::sign_2p_1(
            &half_excess_keypair_funder,
            &funder_SKs.r_fund,
            &half_excess_pk_redeemer,
            &redeemer_PKs.R_fund,
            &kernel_features.kernel_sig_msg()?,
            &s_fund_redeemer,
        )
        .map_err(|_| RedeemerSignatureError::Fund)?;

        let bulletproof = {
            let bulletproof_round_2_funder = bulletproof::Round2::new(
                &funder_SKs.x.secret_key,
                &funder_SKs.x.secret_key,
                &X,
                offer.fund_output_amount(),
                &bulletproof_common_nonce,
                &bulletproof_round_1_redeemer,
                &bulletproof_round_1_funder,
            )?;
            bulletproof::Round3::new(
                &funder_SKs.x.secret_key,
                &funder_SKs.x.secret_key,
                &X,
                offer.fund_output_amount(),
                &bulletproof_common_nonce,
                &bulletproof_round_1_redeemer,
                &bulletproof_round_1_funder,
                &bulletproof_round_2_redeemer,
                &bulletproof_round_2_funder,
            )?
            .bulletproof
        };

        action::Fund::new(
            vec![(
                offer.fund_output_amount(),
                special_output_keypairs_funder.fund_input_key.public_key,
            )],
            vec![(offer.fund_output_amount(), X, bulletproof)],
            excess_pk,
            excess_sig,
            kernel_features,
            offset,
            (
                offer.fund_output_amount(),
                special_output_keypairs_funder.fund_input_key.clone(),
            ),
        )?
    };

    let refund = {
        let offset = compute_offset(&funder_SKs.r_refund.public_key, &redeemer_PKs.R_refund)?;

        let half_excess_keypair_funder = KeyPair::new(compute_excess_sk(
            vec![&funder_SKs.x.secret_key],
            vec![&special_output_keypairs_funder.refund_output_key.secret_key],
            None,
        )?);

        let half_excess_pk_redeemer =
            compute_excess_pk(vec![&redeemer_PKs.X], vec![], Some(&offset))?;

        let kernel_features = KernelFeatures::HeightLocked {
            fee: 0,
            lock_height: offer.expiry,
        };

        let (excess_sig, excess) = schnorr::sign_2p_1(
            &half_excess_keypair_funder,
            &funder_SKs.r_refund,
            &half_excess_pk_redeemer,
            &redeemer_PKs.R_refund,
            &kernel_features.kernel_sig_msg()?,
            &s_refund_redeemer,
        )
        .map_err(|_| RedeemerSignatureError::Refund)?;

        let bulletproof = SECP.bullet_proof(
            offer.fund_output_amount(),
            special_output_keypairs_funder
                .refund_output_key
                .secret_key
                .clone(),
            random_secret_key(),
            random_secret_key(),
            None,
            None,
        );

        action::Refund::new(
            vec![(offer.fund_output_amount(), X)],
            vec![(
                offer.fund_output_amount(),
                special_output_keypairs_funder.refund_output_key.public_key,
                bulletproof,
            )],
            excess,
            excess_sig,
            kernel_features,
            offset,
            (
                offer.fund_output_amount(),
                special_output_keypairs_funder.refund_output_key.clone(),
            ),
            offer.fee,
        )?
    };

    let encsign_redeem = {
        let offset = compute_offset(&funder_SKs.r_redeem.public_key, &redeemer_PKs.R_redeem)?;

        let half_excess_keypair_funder = KeyPair::new(compute_excess_sk(
            vec![&funder_SKs.x.secret_key],
            vec![],
            None,
        )?);

        let half_excess_pk_redeemer = compute_excess_pk(
            vec![&redeemer_PKs.X],
            vec![&special_outputs.redeem_output_key],
            Some(&offset),
        )?;

        schnorr::encsign_2p_1(
            &half_excess_keypair_funder,
            &funder_SKs.r_redeem,
            &half_excess_pk_redeemer,
            &redeemer_PKs.R_redeem,
            &Y,
            &KernelFeatures::Plain { fee: 0 }.kernel_sig_msg()?,
            &s_hat_redeem_redeemer,
        )
        .map_err(|_| RedeemerSignatureError::Redeem)?
    };

    Ok((FunderActions { fund, refund }, encsign_redeem))
}
