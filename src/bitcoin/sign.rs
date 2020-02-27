use crate::{
    bitcoin::{
        self, action,
        transaction::{fund_transaction, redeem_transaction, refund_transaction},
        PKs, SKs,
    },
    ecdsa,
    keypair::{self, PublicKey},
};
use ::bitcoin::{hashes::Hash, util::bip143::SighashComponents};
use secp256k1zkp::{self, Message};

// TODO: Remove Y from spec version
// TODO: Remove redeem signature from output in spec
pub fn redeemer(
    init: &bitcoin::BaseParameters,
    redeemer_SKs: &SKs,
    funder_PKs: &PKs,
) -> secp256k1zkp::Signature {
    let (fund_transaction, fund_output_script) =
        fund_transaction(&init, &redeemer_SKs.x.public_key, &funder_PKs.X);

    let refund_transaction = refund_transaction(&init, fund_transaction.txid());

    let refund_digest = SighashComponents::new(&refund_transaction).sighash_all(
        &refund_transaction.input[0],
        &fund_output_script,
        fund_transaction.output[0].value,
    );
    let refund_digest = Message::from_slice(&refund_digest.into_inner())
        .expect("should not fail because it is a hash");

    redeemer_SKs.x.sign_ecdsa(&refund_digest)
}

pub struct FunderActions {
    pub fund: action::Fund,
    pub refund: action::Refund,
}

// TODO: Modify the spec to not pass redeemer's redeem signature to funder
pub fn funder(
    base_parameters: &bitcoin::BaseParameters,
    funder_SKs: &SKs,
    redeemer_PKs: &PKs,
    Y: &PublicKey,
    redeemer_refund_signature: &secp256k1zkp::Signature,
) -> anyhow::Result<(FunderActions, ecdsa::EncryptedSignature)> {
    let (fund_transaction, fund_output_script) =
        fund_transaction(&base_parameters, &redeemer_PKs.X, &funder_SKs.x.public_key);

    let fund = action::Fund {
        transaction: fund_transaction.clone(),
    };

    let refund = {
        let refund_transaction = refund_transaction(&base_parameters, fund_transaction.txid());

        let refund_digest = SighashComponents::new(&refund_transaction).sighash_all(
            &refund_transaction.input[0],
            &fund_output_script,
            fund_transaction.output[0].value,
        );
        let refund_digest = Message::from_slice(&refund_digest.into_inner())
            .expect("Should not fail because it is a hash");

        if !keypair::verify_ecdsa(&refund_digest, &redeemer_refund_signature, &redeemer_PKs.X) {
            return Err(anyhow::anyhow!(
                "failed to verify redeemer's Bitcoin refund signature"
            ));
        }

        let funder_refund_signature = funder_SKs.x.sign_ecdsa(&refund_digest);

        action::Refund::new(
            refund_transaction,
            *redeemer_refund_signature,
            funder_refund_signature,
        )
    };

    let encrypted_redeem_signature = {
        let redeem_transaction = redeem_transaction(&base_parameters, fund_transaction.txid());
        let redeem_digest = SighashComponents::new(&redeem_transaction).sighash_all(
            &redeem_transaction.input[0],
            &fund_output_script,
            fund_transaction.output[0].value,
        );

        ecdsa::encsign(&funder_SKs.x, &Y, &redeem_digest)
    };

    Ok((FunderActions { fund, refund }, encrypted_redeem_signature))
}
