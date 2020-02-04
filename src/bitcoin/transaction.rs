use crate::setup_parameters;
use ::bitcoin::{
    blockdata::script, hashes::sha256d::Hash, network::constants::Network, Address, OutPoint,
    Script, Transaction, TxIn, TxOut,
};
use secp256k1zkp::key::PublicKey;

pub fn fund_transaction(
    init: &setup_parameters::Bitcoin,
    alice_key: &PublicKey,
    bob_key: &PublicKey,
) -> (Transaction, Script) {
    let fund_output_script = script::Builder::new()
        .push_int(2)
        .push_key(&::bitcoin::util::key::PublicKey {
            key: alice_key.clone(),
            compressed: true,
        })
        .push_key(&::bitcoin::util::key::PublicKey {
            key: bob_key.clone(),
            compressed: true,
        })
        .push_int(2)
        .into_script();

    let fund_output_addr = Address::p2wsh(&fund_output_script, Network::Regtest);
    let transaction = Transaction {
        input: init
            .inputs
            .iter()
            .map(|i| TxIn {
                previous_output: i.0.clone(),
                sequence: 0xffffffff,
                witness: Vec::new(),
                script_sig: Script::new(),
            })
            .collect(),
        output: vec![
            TxOut {
                script_pubkey: fund_output_addr.script_pubkey(),
                value: init.asset + init.fee, // funder pays for fee of redeem/refund tx
            },
            TxOut {
                script_pubkey: init.change.0.script_pubkey(),
                value: init.change.1,
            },
        ],
        lock_time: 0,
        version: 2,
    };

    (transaction, fund_output_script)
}

pub fn refund_transaction(
    init: &setup_parameters::Bitcoin,
    fund_transaction_id: Hash,
) -> Transaction {
    Transaction {
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: fund_transaction_id,
                vout: 0,
            },
            sequence: 0xffffffff,
            witness: Vec::new(),
            script_sig: Script::new(),
        }],
        output: vec![TxOut {
            script_pubkey: init.refund_address.script_pubkey(),
            value: init.asset,
        }],
        lock_time: init.expiry,
        version: 2,
    }
}

pub fn redeem_transaction(
    init: &setup_parameters::Bitcoin,
    fund_transaction_id: Hash,
) -> Transaction {
    Transaction {
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: fund_transaction_id,
                vout: 0,
            },
            sequence: 0xffffffff,
            witness: Vec::new(),
            script_sig: Script::new(),
        }],
        output: vec![TxOut {
            script_pubkey: init.redeem_address.script_pubkey(),
            value: init.redeem_output_amount(),
        }],
        lock_time: 0,
        version: 2,
    }
}
