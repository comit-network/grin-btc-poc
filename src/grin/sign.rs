use crate::{
    grin::{self, bulletproof, PKs, SKs},
    keypair::{random_secret_key, KeyPair, Negate, PublicKey, SECP},
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
) -> (GrinRedeemerSignatures, bulletproof::Round2) {
    let s_fund = {
        let offset = grin::compute_offset(&funder_PKs.R_fund, &redeemer_SKs.r_fund.public_key);
        &offset;
        let half_excess_pk_funder =
            grin::compute_excess_pk(vec![&init.fund_input_key], vec![&funder_PKs.X], None).unwrap();

        // TODO: Extract into grin::compute_excess_sk
        let mut half_excess_sk_redeemer = redeemer_SKs.x.secret_key.clone();
        half_excess_sk_redeemer
            .add_assign(&*SECP, &offset.negate())
            .unwrap();

        schnorr::sign_2p_0(
            &KeyPair::new(half_excess_sk_redeemer),
            &redeemer_SKs.r_fund,
            &half_excess_pk_funder,
            &funder_PKs.R_fund,
            &grin::KernelFeatures::Plain { fee: init.fee }
                .kernel_sig_msg()
                .unwrap(),
        )
    };

    let bulletproof_round_2_redeemer = {
        let X_fund =
            PublicKey::from_combination(&*SECP, vec![&redeemer_SKs.x.public_key, &funder_PKs.X])
                .unwrap();
        bulletproof::Round2::new(
            &redeemer_SKs.x.secret_key,
            &X_fund,
            init.fund_output_amount(),
            &init.bulletproof_common_nonce,
            &bulletproof_round_1_redeemer,
            &bulletproof_round_1_funder,
        )
    };

    let s_refund = {
        let offset = grin::compute_offset(&funder_PKs.R_refund, &redeemer_SKs.r_refund.public_key);
        let half_excess_pk_funder =
            grin::compute_excess_pk(vec![&funder_PKs.X], vec![&init.refund_output_key], None)
                .unwrap();

        let mut half_excess_sk_redeemer = redeemer_SKs.x.secret_key.negate().clone();
        half_excess_sk_redeemer
            .add_assign(&*SECP, &offset.negate())
            .unwrap();

        schnorr::sign_2p_0(
            &KeyPair::new(half_excess_sk_redeemer),
            &redeemer_SKs.r_refund,
            &half_excess_pk_funder,
            &funder_PKs.R_refund,
            &grin::KernelFeatures::HeightLocked {
                fee: init.fee,
                lock_height: init.expiry,
            }
            .kernel_sig_msg()
            .unwrap(),
        )
    };

    let s_hat_redeem = {
        let offset = grin::compute_offset(&funder_PKs.R_redeem, &redeemer_SKs.r_redeem.public_key);
        let mut half_kernel_sk = (redeemer_SKs.x.secret_key).negate();
        half_kernel_sk
            .add_assign(&*SECP, &secret_init.redeem_output_key.secret_key)
            .unwrap();
        half_kernel_sk.add_assign(&*SECP, &offset.negate()).unwrap();

        schnorr::encsign_2p_0(
            &KeyPair::new(half_kernel_sk),
            &redeemer_SKs.r_redeem,
            &(funder_PKs.X).negate(),
            &funder_PKs.R_redeem,
            &Y,
            &grin::KernelFeatures::Plain { fee: init.fee }
                .kernel_sig_msg()
                .unwrap(),
        )
    };

    (
        GrinRedeemerSignatures {
            s_fund,
            s_refund,
            s_hat_redeem,
        },
        bulletproof_round_2_redeemer,
    )
}

#[derive(Debug, Clone)]
pub enum RedeemerSignatureError {
    Fund,
    Redeem,
    Refund,
}

pub struct GrinFunderActions {
    pub fund: grin::action::Fund,
    pub refund: grin::action::Refund,
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
) -> Result<(GrinFunderActions, schnorr::EncryptedSignature), RedeemerSignatureError> {
    let fund = {
        let offset = grin::compute_offset(&funder_SKs.r_fund.public_key, &redeemer_PKs.R_fund);

        let half_excess_sk_funder = {
            let mut half_excess_sk_funder = funder_SKs.x.secret_key.clone();
            half_excess_sk_funder
                .add_assign(&*SECP, &secret_init.fund_input_key.secret_key.negate())
                .unwrap();

            KeyPair::new(half_excess_sk_funder)
        };
        let half_excess_pk_redeemer =
            grin::compute_excess_pk(vec![], vec![&redeemer_PKs.X], Some(&offset)).unwrap();

        let kernel_features = grin::KernelFeatures::Plain { fee: init.fee };

        let (excess_sig, excess) = schnorr::sign_2p_1(
            &half_excess_sk_funder,
            &funder_SKs.r_fund,
            &half_excess_pk_redeemer,
            &redeemer_PKs.R_fund,
            &kernel_features.kernel_sig_msg().unwrap(),
            &s_fund_redeemer,
        )
        .map_err(|_| RedeemerSignatureError::Fund)?;

        let bulletproof = {
            let X_fund = PublicKey::from_combination(&*SECP, vec![
                &redeemer_PKs.X,
                &funder_SKs.x.public_key,
            ])
            .unwrap();
            let bulletproof_round_2_funder = bulletproof::Round2::new(
                &funder_SKs.x.secret_key,
                &X_fund,
                init.fund_output_amount(),
                &init.bulletproof_common_nonce,
                &bulletproof_round_1_redeemer,
                &bulletproof_round_1_funder,
            );
            bulletproof::Round3::new(
                &funder_SKs.x.secret_key,
                &X_fund,
                init.fund_output_amount(),
                &init.bulletproof_common_nonce,
                &bulletproof_round_1_redeemer,
                &bulletproof_round_1_funder,
                &bulletproof_round_2_redeemer,
                &bulletproof_round_2_funder,
            )
            .bulletproof
        };

        grin::action::Fund::new(
            vec![(
                init.fund_input_amount(),
                secret_init.fund_input_key.public_key,
            )],
            vec![(
                init.fund_output_amount(),
                PublicKey::from_combination(&*SECP, vec![
                    &funder_SKs.x.public_key,
                    &redeemer_PKs.X,
                ])
                .unwrap(),
            )],
            excess,
            excess_sig,
            kernel_features,
            secret_init.fund_input_key.clone(),
            bulletproof,
        )
    };

    let refund = {
        let offset = grin::compute_offset(&funder_SKs.r_refund.public_key, &redeemer_PKs.R_refund);

        let half_excess_sk_funder = {
            let mut half_excess_sk_funder = funder_SKs.x.secret_key.negate();
            half_excess_sk_funder
                .add_assign(&*SECP, &secret_init.refund_output_key.secret_key)
                .unwrap();

            KeyPair::new(half_excess_sk_funder)
        };
        let half_excess_pk_redeemer =
            grin::compute_excess_pk(vec![&redeemer_PKs.X], vec![], Some(&offset)).unwrap();

        let kernel_features = grin::KernelFeatures::HeightLocked {
            fee: init.fee,
            lock_height: init.expiry,
        };

        let (excess_sig, excess) = schnorr::sign_2p_1(
            &half_excess_sk_funder,
            &funder_SKs.r_refund,
            &half_excess_pk_redeemer,
            &redeemer_PKs.R_refund,
            &kernel_features.kernel_sig_msg().unwrap(),
            &s_refund_redeemer,
        )
        .map_err(|_| RedeemerSignatureError::Refund)?;

        // WARNING: Is the private nonce really not needed?
        let bulletproof = SECP.bullet_proof(
            init.redeem_output_amount(),
            funder_SKs.x.secret_key.clone(),
            random_secret_key(),
            random_secret_key(),
            None,
            None,
        );

        grin::action::Refund::new(
            vec![(
                init.fund_output_amount(),
                PublicKey::from_combination(&*SECP, vec![
                    &funder_SKs.x.public_key,
                    &redeemer_PKs.X,
                ])
                .unwrap(),
            )],
            vec![(
                init.refund_output_amount(),
                secret_init.refund_output_key.public_key,
            )],
            excess,
            excess_sig,
            kernel_features,
            secret_init.refund_output_key.clone(),
            bulletproof,
        )
    };

    let encsign_redeem = {
        let offset = grin::compute_offset(&funder_SKs.r_redeem.public_key, &redeemer_PKs.R_redeem);

        let half_excess_sk_funder = funder_SKs.x.negate();
        let half_excess_pk_redeemer = grin::compute_excess_pk(
            vec![&redeemer_PKs.X],
            vec![&init.redeem_output_key],
            Some(&offset),
        )
        .unwrap();

        schnorr::encsign_2p_1(
            &half_excess_sk_funder,
            &funder_SKs.r_redeem,
            &half_excess_pk_redeemer,
            &redeemer_PKs.R_redeem,
            &Y,
            &grin::KernelFeatures::Plain { fee: init.fee }
                .kernel_sig_msg()
                .unwrap(),
            &s_hat_redeem_redeemer,
        )
        .map_err(|_| RedeemerSignatureError::Redeem)?
    };

    Ok((GrinFunderActions { fund, refund }, encsign_redeem))
}
