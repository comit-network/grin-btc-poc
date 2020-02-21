use crate::{
    grin::{
        action, bulletproof, compute_excess_pk, compute_excess_sk, compute_offset, KernelFeatures,
        PKs, SKs,
    },
    keypair::{random_secret_key, KeyPair, PublicKey, SECP},
    schnorr, setup_parameters,
};

pub struct GrinRedeemerSignatures {
    pub s_fund: schnorr::PartialSignature,
    pub s_refund: schnorr::PartialSignature,
    pub s_hat_redeem: schnorr::PartialEncryptedSignature,
}

pub fn redeemer(
    init: &setup_parameters::Grin,
    secret_init: &setup_parameters::GrinRedeemerSecret,
    redeemer_SKs: &SKs,
    funder_PKs: &PKs,
    Y: &PublicKey,
    bulletproof_round_1_redeemer: &bulletproof::Round1,
    bulletproof_round_1_funder: &bulletproof::Round1,
) -> anyhow::Result<(GrinRedeemerSignatures, bulletproof::Round2)> {
    let (s_fund, bulletproof_round_2_redeemer) = {
        let offset = compute_offset(&funder_PKs.R_fund, &redeemer_SKs.r_fund.public_key)?;

        let half_excess_keypair_redeemer = KeyPair::new(compute_excess_sk(
            vec![],
            vec![&redeemer_SKs.x.secret_key],
            Some(&offset),
        )?);

        let s_fund = {
            let half_excess_pk_funder =
                compute_excess_pk(vec![&init.fund_input_key], vec![&funder_PKs.X], None)?;

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
                init.fund_output_amount(),
                &init.bulletproof_common_nonce,
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

        let half_excess_pk_funder =
            compute_excess_pk(vec![&funder_PKs.X], vec![&init.refund_output_key], None)?;

        schnorr::sign_2p_0(
            &half_excess_keypair_redeemer,
            &redeemer_SKs.r_refund,
            &half_excess_pk_funder,
            &funder_PKs.R_refund,
            &KernelFeatures::HeightLocked {
                fee: 0,
                lock_height: init.expiry,
            }
            .kernel_sig_msg()?,
        )?
    };

    let s_hat_redeem = {
        let offset = compute_offset(&funder_PKs.R_redeem, &redeemer_SKs.r_redeem.public_key)?;

        let half_excess_keypair_redeemer = KeyPair::new(compute_excess_sk(
            vec![&redeemer_SKs.x.secret_key],
            vec![&secret_init.redeem_output_key.secret_key],
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
        GrinRedeemerSignatures {
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

pub struct GrinFunderActions {
    pub fund: action::Fund,
    pub refund: action::Refund,
}

pub fn funder(
    init: &setup_parameters::Grin,
    secret_init: &setup_parameters::GrinFunderSecret,
    funder_SKs: &SKs,
    redeemer_PKs: &PKs,
    Y: &PublicKey,
    GrinRedeemerSignatures {
        s_fund: s_fund_redeemer,
        s_refund: s_refund_redeemer,
        s_hat_redeem: s_hat_redeem_redeemer,
    }: GrinRedeemerSignatures,
    bulletproof_round_1_redeemer: &bulletproof::Round1,
    bulletproof_round_1_funder: &bulletproof::Round1,
    bulletproof_round_2_redeemer: &bulletproof::Round2,
) -> anyhow::Result<(GrinFunderActions, schnorr::EncryptedSignature)> {
    let X = PublicKey::from_combination(&*SECP, vec![&redeemer_PKs.X, &funder_SKs.x.public_key])?;

    let fund = {
        let offset = compute_offset(&funder_SKs.r_fund.public_key, &redeemer_PKs.R_fund)?;

        let half_excess_keypair_funder = KeyPair::new(compute_excess_sk(
            vec![&secret_init.fund_input_key.secret_key],
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
                init.fund_output_amount(),
                &init.bulletproof_common_nonce,
                &bulletproof_round_1_redeemer,
                &bulletproof_round_1_funder,
            )?;
            bulletproof::Round3::new(
                &funder_SKs.x.secret_key,
                &funder_SKs.x.secret_key,
                &X,
                init.fund_output_amount(),
                &init.bulletproof_common_nonce,
                &bulletproof_round_1_redeemer,
                &bulletproof_round_1_funder,
                &bulletproof_round_2_redeemer,
                &bulletproof_round_2_funder,
            )?
            .bulletproof
        };

        action::Fund::new(
            vec![(
                init.fund_output_amount(),
                secret_init.fund_input_key.public_key,
            )],
            vec![(init.fund_output_amount(), X, bulletproof)],
            excess_pk,
            excess_sig,
            kernel_features,
            offset,
            (
                init.fund_output_amount(),
                secret_init.fund_input_key.clone(),
                init.fee,
            ),
        )?
    };

    let refund = {
        let offset = compute_offset(&funder_SKs.r_refund.public_key, &redeemer_PKs.R_refund)?;

        let half_excess_keypair_funder = KeyPair::new(compute_excess_sk(
            vec![&funder_SKs.x.secret_key],
            vec![&secret_init.refund_output_key.secret_key],
            None,
        )?);

        let half_excess_pk_redeemer =
            compute_excess_pk(vec![&redeemer_PKs.X], vec![], Some(&offset))?;

        let kernel_features = KernelFeatures::HeightLocked {
            fee: 0,
            lock_height: init.expiry,
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
            init.refund_output_amount(),
            secret_init.refund_output_key.secret_key.clone(),
            random_secret_key(),
            random_secret_key(),
            None,
            None,
        );

        action::Refund::new(
            vec![(init.fund_output_amount(), X)],
            vec![(
                init.refund_output_amount(),
                secret_init.refund_output_key.public_key,
                bulletproof,
            )],
            excess,
            excess_sig,
            kernel_features,
            offset,
            secret_init.refund_output_key.clone(),
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
            vec![&init.redeem_output_key],
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

    Ok((GrinFunderActions { fund, refund }, encsign_redeem))
}
