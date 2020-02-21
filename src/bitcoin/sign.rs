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
        .expect("should not fail because it is a hash");

    redeemer_SKs.x.sign_ecdsa(&refund_digest)
}

pub struct BitcoinFunderActions {
    pub fund: bitcoin::action::Fund,
    pub refund: bitcoin::action::Refund,
}

// TODO: Modify the spec to not pass redeemer's redeem signature to funder
pub fn funder(
    init: &setup_parameters::Bitcoin,
    funder_SKs: &bitcoin::SKs,
    redeemer_PKs: &bitcoin::PKs,
    Y: &PublicKey,
    redeemer_refund_signature: &secp256k1zkp::Signature,
) -> anyhow::Result<(BitcoinFunderActions, ecdsa::EncryptedSignature)> {
    let (fund_transaction, fund_output_script) =
        bitcoin::transaction::fund_transaction(&init, &redeemer_PKs.X, &funder_SKs.x.public_key);

    let fund = bitcoin::action::Fund {
        transaction: fund_transaction.clone(),
        inputs: init.inputs.iter().map(|(i, _)| *i).collect(),
    };

    let refund = {
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
            return Err(anyhow::anyhow!(
                "failed to verify redeemer's Bitcoin refund signature"
            ));
        }

        let funder_refund_signature = funder_SKs.x.sign_ecdsa(&refund_digest);

        bitcoin::action::Refund::new(
            refund_transaction,
            *redeemer_refund_signature,
            funder_refund_signature,
        )
    };

    let encrypted_redeem_signature = {
        let redeem_transaction =
            bitcoin::transaction::redeem_transaction(&init, fund_transaction.txid());
        let redeem_digest = bitcoin::SighashComponents::new(&redeem_transaction).sighash_all(
            &redeem_transaction.input[0],
            &fund_output_script,
            fund_transaction.output[0].value,
        );

        ecdsa::encsign(&funder_SKs.x, &Y, &redeem_digest)
    };

    Ok((
        BitcoinFunderActions { fund, refund },
        encrypted_redeem_signature,
    ))
}
