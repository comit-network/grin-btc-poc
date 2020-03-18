use crate::bitcoin::{Offer, WalletOutputs};
use ::bitcoin::{
    blockdata::{opcodes, script},
    hashes::sha256d::Hash,
    network::constants::Network,
    Address, OutPoint, Script, Transaction, TxIn, TxOut,
};
use secp256k1zkp::key::PublicKey;

pub fn fund_transaction(
    offer: &Offer,
    wallet_outputs: &WalletOutputs,
    redeemer_key: &PublicKey,
    funder_key: &PublicKey,
) -> anyhow::Result<(Transaction, Script)> {
    let fund_output_script = script::Builder::new()
        .push_int(2)
        .push_key(&::bitcoin::util::key::PublicKey {
            key: *redeemer_key,
            compressed: true,
        })
        .push_key(&::bitcoin::util::key::PublicKey {
            key: *funder_key,
            compressed: true,
        })
        .push_int(2)
        .push_opcode(opcodes::all::OP_CHECKMULTISIG)
        .into_script();

    let fund_output_addr = Address::p2wsh(&fund_output_script, Network::Regtest);
    let transaction = Transaction {
        input: vec![TxIn {
            previous_output: wallet_outputs.fund_input.outpoint,
            sequence: 0xffff_ffff,
            witness: Vec::new(),
            script_sig: Script::new(),
        }],
        output: vec![
            TxOut {
                script_pubkey: fund_output_addr.script_pubkey(),
                value: offer.fund_output_amount(),
            },
            TxOut {
                script_pubkey: wallet_outputs.fund_change_address.script_pubkey(),
                value: offer.change_output_amount(wallet_outputs.fund_input.txout.value)?,
            },
        ],
        lock_time: 0,
        version: 2,
    };

    Ok((transaction, fund_output_script))
}

pub fn refund_transaction(
    offer: &Offer,
    wallet_outputs: &WalletOutputs,
    fund_transaction_id: Hash,
) -> Transaction {
    Transaction {
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: fund_transaction_id,
                vout: 0,
            },
            sequence: 0xffff_ffff,
            witness: Vec::new(),
            script_sig: Script::new(),
        }],
        output: vec![TxOut {
            script_pubkey: wallet_outputs.refund_address.script_pubkey(),
            value: offer.refund_output_amount(),
        }],
        lock_time: offer.expiry,
        version: 2,
    }
}

pub fn redeem_transaction(
    offer: &Offer,
    wallet_outputs: &WalletOutputs,
    fund_transaction_id: Hash,
) -> Transaction {
    Transaction {
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: fund_transaction_id,
                vout: 0,
            },
            sequence: 0xffff_ffff,
            witness: Vec::new(),
            script_sig: Script::new(),
        }],
        output: vec![TxOut {
            script_pubkey: wallet_outputs.redeem_address.script_pubkey(),
            value: offer.redeem_output_amount(),
        }],
        lock_time: 0,
        version: 2,
    }
}
