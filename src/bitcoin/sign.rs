use crate::{
    bitcoin::{
        action,
        transaction::{fund_transaction, redeem_transaction, refund_transaction},
        Offer, PKs, SKs, WalletOutputs,
    },
    ecdsa,
    keypair::{self, PublicKey},
};
use ::bitcoin::{hashes::Hash, util::bip143::SighashComponents};
use secp256k1zkp::{self, Message};

// TODO: Remove Y from spec version
// TODO: Remove redeem signature from output in spec
pub fn redeemer(
    offer: &Offer,
    wallet_outputs: &WalletOutputs,
    redeemer_SKs: &SKs,
    funder_PKs: &PKs,
) -> anyhow::Result<secp256k1zkp::Signature> {
    let (fund_transaction, fund_output_script) = fund_transaction(
        &offer,
        &wallet_outputs,
        &redeemer_SKs.x.public_key,
        &funder_PKs.X,
    )?;

    let refund_transaction = refund_transaction(&offer, &wallet_outputs, fund_transaction.txid());

    let refund_digest = SighashComponents::new(&refund_transaction).sighash_all(
        &refund_transaction.input[0],
        &fund_output_script,
        fund_transaction.output[0].value,
    );
    let refund_digest = Message::from_slice(&refund_digest.into_inner())
        .expect("should not fail because it is a hash");

    Ok(redeemer_SKs.x.sign_ecdsa(&refund_digest))
}

pub struct FunderActions {
    pub fund: action::Fund,
    pub refund: action::Refund,
}

// TODO: Modify the spec to not pass redeemer's redeem signature to funder
pub fn funder(
    offer: &Offer,
    wallet_outputs: &WalletOutputs,
    funder_SKs: &SKs,
    redeemer_PKs: &PKs,
    Y: &PublicKey,
    redeemer_refund_signature: &secp256k1zkp::Signature,
) -> anyhow::Result<(FunderActions, ecdsa::EncryptedSignature)> {
    let (fund_transaction, fund_output_script) = fund_transaction(
        &offer,
        &wallet_outputs,
        &redeemer_PKs.X,
        &funder_SKs.x.public_key,
    )?;

    // Input to be signed by wallet before broadcast
    let fund = action::Fund {
        transaction: fund_transaction.clone(),
    };

    let refund = {
        let refund_transaction =
            refund_transaction(&offer, &wallet_outputs, fund_transaction.txid());

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
            fund_output_script.clone(),
        )
    };

    let encrypted_redeem_signature = {
        let redeem_transaction =
            redeem_transaction(&offer, &wallet_outputs, fund_transaction.txid());
        let redeem_digest = SighashComponents::new(&redeem_transaction).sighash_all(
            &redeem_transaction.input[0],
            &fund_output_script,
            fund_transaction.output[0].value,
        );

        ecdsa::encsign(&funder_SKs.x, &Y, &redeem_digest)
    };

    Ok((FunderActions { fund, refund }, encrypted_redeem_signature))
}
