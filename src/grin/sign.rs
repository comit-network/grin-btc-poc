use crate::{
    grin::{self, PKs, SKs},
    keypair::{Negate, PublicKey, G, SECP},
    schnorr, setup_parameters,
};

pub struct GrinRedeemerSignatures {
    pub s_fund: schnorr::PartialSignature,
    pub s_refund: schnorr::PartialSignature,
    pub s_hat_redeem: schnorr::PartialEncryptedSignature,
}

// TODO: For fund it should return both the Schnorr partial signature and the
// half-bulletproof
pub fn redeemer(
    init: &setup_parameters::Grin,
    secret_init: &setup_parameters::GrinRedeemerSecret,
    redeemer_SKs: &SKs,
    funder_PKs: &PKs,
    Y: &PublicKey,
) -> GrinRedeemerSignatures {
    // fund
    let s_fund = {
        let offset = grin::compute_offset(&funder_PKs.R_fund, &redeemer_SKs.r_fund.public_key);
        &offset;
        let X_fund = grin::compute_public_excess(
            vec![&init.fund_input_key],
            vec![&funder_PKs.X, &redeemer_SKs.x.public_key],
            &offset,
        );

        let R_fund = PublicKey::from_combination(&*SECP, vec![
            &funder_PKs.R_fund,
            &redeemer_SKs.r_fund.public_key,
        ])
        .unwrap();

        let mut half_kernel_sk = redeemer_SKs.x.secret_key.clone();
        half_kernel_sk.add_assign(&*SECP, &offset.negate()).unwrap();

        crate::keypair::KeyPair::new(half_kernel_sk.clone()).public_key;
        // WARNING: This might change the R value if R_y is not a quadratic residue.
        let signature = grin::calculate_partial_sig(
            &*SECP,
            &half_kernel_sk,
            &redeemer_SKs.r_fund.secret_key,
            &R_fund,
            Some(&X_fund),
            &grin::KernelFeatures::Plain { fee: init.fee }
                .kernel_sig_msg()
                .unwrap(),
        )
        .expect("could not calculate partial signature");
        schnorr::PartialSignature::from(&signature)
    };

    // refund
    let s_refund = {
        let offset = grin::compute_offset(&funder_PKs.R_refund, &redeemer_SKs.r_refund.public_key);
        let X_refund = grin::compute_public_excess(
            vec![&funder_PKs.X, &redeemer_SKs.x.public_key],
            vec![&init.refund_output_key],
            &offset,
        );

        let R_refund = PublicKey::from_combination(&*SECP, vec![
            &funder_PKs.R_refund,
            &redeemer_SKs.r_refund.public_key,
        ])
        .unwrap();

        let mut half_kernel_sk = redeemer_SKs.x.secret_key.negate().clone();
        half_kernel_sk.add_assign(&*SECP, &offset.negate()).unwrap();

        let signature = grin::calculate_partial_sig(
            &*SECP,
            &half_kernel_sk,
            &redeemer_SKs.r_refund.secret_key,
            &R_refund,
            Some(&X_refund),
            &grin::KernelFeatures::HeightLocked {
                fee: init.fee,
                lock_height: init.expiry,
            }
            .kernel_sig_msg()
            .unwrap(),
        )
        .expect("could not calculate partial signature");
        schnorr::PartialSignature::from(&signature)
    };

    // redeem
    let s_hat_redeem = {
        let offset = grin::compute_offset(&funder_PKs.R_redeem, &redeemer_SKs.r_redeem.public_key);
        let X_redeem = grin::compute_public_excess(
            vec![&funder_PKs.X, &redeemer_SKs.x.public_key],
            vec![&init.redeem_output_key],
            &offset,
        );

        let R_redeem = PublicKey::from_combination(&*SECP, vec![
            &funder_PKs.R_redeem,
            &redeemer_SKs.r_redeem.public_key,
            &Y,
        ])
        .unwrap();

        let mut half_kernel_sk = (redeemer_SKs.x.secret_key).negate();
        half_kernel_sk
            .add_assign(&*SECP, &secret_init.redeem_output_key.secret_key)
            .unwrap();
        half_kernel_sk.add_assign(&*SECP, &offset.negate()).unwrap();

        let signature = grin::calculate_partial_sig(
            &*SECP,
            &half_kernel_sk,
            &redeemer_SKs.r_redeem.secret_key,
            &R_redeem,
            Some(&X_redeem),
            &grin::KernelFeatures::Plain { fee: init.fee }
                .kernel_sig_msg()
                .unwrap(),
        )
        .expect("could not calculate partial signature");
        schnorr::PartialSignature::from(&signature)
    };

    GrinRedeemerSignatures {
        s_fund,
        s_refund,
        s_hat_redeem,
    }
}

#[derive(Debug, Clone)]
pub enum RedeemerSignatureError {
    Fund,
    Redeem,
    Refund,
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
) -> Result<(), RedeemerSignatureError> {
    // verify redeemer fund half-signature
    {
        let R_fund = PublicKey::from_combination(&*SECP, vec![
            &funder_SKs.r_fund.public_key,
            &redeemer_PKs.R_fund,
        ])
        .unwrap();

        let offset = grin::compute_offset(&funder_SKs.r_fund.public_key, &redeemer_PKs.R_fund);
        let mut offsetG = G.clone();
        offsetG.mul_assign(&*SECP, &offset).unwrap();

        let half_kernel_pk =
            PublicKey::from_combination(&*SECP, vec![&redeemer_PKs.X, &offsetG.negate()]).unwrap();

        let X_fund = grin::compute_public_excess(
            vec![&init.fund_input_key],
            vec![&funder_SKs.x.public_key, &redeemer_PKs.X],
            &offset,
        );

        let sig_fund_redeemer = s_fund_redeemer.to_signature(&redeemer_PKs.R_fund);
        grin::verify_partial_sig(
            &*SECP,
            &sig_fund_redeemer,
            &R_fund,
            &half_kernel_pk,
            Some(&X_fund),
            &grin::KernelFeatures::Plain { fee: init.fee }
                .kernel_sig_msg()
                .unwrap(),
        )
        .map_err(|_| RedeemerSignatureError::Fund)?
    };

    // verify redeemer refund half-signature
    {
        let R_refund = PublicKey::from_combination(&*SECP, vec![
            &funder_SKs.r_refund.public_key,
            &redeemer_PKs.R_refund,
        ])
        .unwrap();

        let offset = grin::compute_offset(&funder_SKs.r_refund.public_key, &redeemer_PKs.R_refund);
        let mut offsetG = G.clone();
        offsetG.mul_assign(&*SECP, &offset).unwrap();

        let half_kernel_pk =
            PublicKey::from_combination(&*SECP, vec![&redeemer_PKs.X.negate(), &offsetG.negate()])
                .unwrap();

        let X_refund = grin::compute_public_excess(
            vec![&funder_SKs.x.public_key, &redeemer_PKs.X],
            vec![&init.refund_output_key],
            &offset,
        );

        let sig_refund_redeemer = s_refund_redeemer.to_signature(&redeemer_PKs.R_refund);
        grin::verify_partial_sig(
            &*SECP,
            &sig_refund_redeemer,
            &R_refund,
            &half_kernel_pk,
            Some(&X_refund),
            &grin::KernelFeatures::HeightLocked {
                fee: init.fee,
                lock_height: init.expiry,
            }
            .kernel_sig_msg()
            .unwrap(),
        )
        .map_err(|_| RedeemerSignatureError::Refund)?
    }

    // verify redeemer redeem encrypted half-signature
    {
        let R_redeem = PublicKey::from_combination(&*SECP, vec![
            &funder_SKs.r_redeem.public_key,
            &redeemer_PKs.R_redeem,
            &Y,
        ])
        .unwrap();

        let offset = grin::compute_offset(&funder_SKs.r_redeem.public_key, &redeemer_PKs.R_redeem);
        let mut offsetG = G.clone();
        offsetG.mul_assign(&*SECP, &offset).unwrap();

        let half_kernel_pk = PublicKey::from_combination(&*SECP, vec![
            &init.redeem_output_key,
            &redeemer_PKs.X.negate(),
            &offsetG.negate(),
        ])
        .unwrap();

        let X_redeem = grin::compute_public_excess(
            vec![&funder_SKs.x.public_key, &redeemer_PKs.X],
            vec![&init.redeem_output_key],
            &offset,
        );

        let sig_hat_redeem_redeemer = s_hat_redeem_redeemer.to_signature(&redeemer_PKs.R_redeem);
        grin::verify_partial_sig(
            &*SECP,
            &sig_hat_redeem_redeemer,
            &R_redeem,
            &half_kernel_pk,
            Some(&X_redeem),
            &grin::KernelFeatures::Plain { fee: init.fee }
                .kernel_sig_msg()
                .unwrap(),
        )
        .map_err(|_| RedeemerSignatureError::Redeem)?
    }

    Ok(())
}
