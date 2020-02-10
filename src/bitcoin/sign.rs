use crate::{
    bitcoin::{self, Hash, SighashComponents},
    ecdsa,
    keypair::{self, PublicKey},
    setup_parameters,
};
use secp256k1zkp::{self, Message};

// TODO: Remove Y from spec version
// TODO: Remove redeem signature from output in spec
pub fn redeemer(
    init: &setup_parameters::Bitcoin,
    redeemer_SKs: &bitcoin::SKs,
    funder_PKs: &bitcoin::PKs,
) -> secp256k1zkp::Signature {
    let (fund_transaction, fund_output_script) =
        bitcoin::transaction::fund_transaction(&init, &redeemer_SKs.x.public_key, &funder_PKs.X);

    let refund_transaction =
        bitcoin::transaction::refund_transaction(&init, fund_transaction.txid());

    let refund_digest = SighashComponents::new(&refund_transaction).sighash_all(
        &refund_transaction.input[0],
        &fund_output_script,
        fund_transaction.output[0].value,
    );
    let refund_digest = Message::from_slice(&refund_digest.into_inner())
        .expect("Should not fail because it is a hash");

    redeemer_SKs.x.sign_ecdsa(&refund_digest)
}

// TODO: Modify the spec to not pass redeemer's redeem signature to funder
pub fn funder(
    init: &setup_parameters::Bitcoin,
    funder_SKs: &bitcoin::SKs,
    redeemer_PKs: &bitcoin::PKs,
    Y: &PublicKey,
    redeemer_refund_signature: &secp256k1zkp::Signature,
) -> Result<
    (
        bitcoin::action::Fund,
        bitcoin::action::Refund,
        ecdsa::EncryptedSignature,
    ),
    (),
> {
    let (fund_transaction, fund_output_script) =
        bitcoin::transaction::fund_transaction(&init, &redeemer_PKs.X, &funder_SKs.x.public_key);

    let fund_action = bitcoin::action::Fund {
        transaction: fund_transaction.clone(),
        inputs: init.inputs.iter().map(|(i, _)| i.clone()).collect(),
    };

    let refund_transaction =
        bitcoin::transaction::refund_transaction(&init, fund_transaction.txid());

    let refund_digest = bitcoin::SighashComponents::new(&refund_transaction).sighash_all(
        &refund_transaction.input[0],
        &fund_output_script,
        fund_transaction.output[0].value,
    );
    let refund_digest = Message::from_slice(&refund_digest.into_inner())
        .expect("Should not fail because it is a hash");

    if !keypair::verify_ecdsa(&refund_digest, &redeemer_refund_signature, &redeemer_PKs.X) {
        return Err(());
    }

    let funder_refund_signature = funder_SKs.x.sign_ecdsa(&refund_digest);

    let refund_action = bitcoin::action::Refund::new(
        refund_transaction,
        redeemer_refund_signature.clone(),
        funder_refund_signature,
    );

    let redeem_transaction =
        bitcoin::transaction::redeem_transaction(&init, fund_transaction.txid());
    let redeem_digest = bitcoin::SighashComponents::new(&redeem_transaction).sighash_all(
        &redeem_transaction.input[0],
        &fund_output_script,
        fund_transaction.output[0].value,
    );

    let encrypted_redeem_signature = ecdsa::encsign(&funder_SKs.x, &Y, &redeem_digest);

    Ok((fund_action, refund_action, encrypted_redeem_signature))
}
