#![allow(non_snake_case)]

use grin_btc_poc::{
    ecdsa,
    keypair::{KeyPair, PublicKey, SECP},
    schnorr,
};
use secp256k1zkp::{aggsig, Message};

#[test]
fn recover_from_ecdsa_to_decrypt_schnorr() {
    let x0 = KeyPair::new_random();
    let x1 = KeyPair::new_random();
    let r0 = KeyPair::new_random();
    let r1 = KeyPair::new_random();

    let y = KeyPair::new_random();

    let (r0, r1, y) = schnorr::normalize_keypairs(r0, r1, y);

    let message = b"tttttttttttttttttttttttttttttttt";

    let schnorr_partial_encsig = schnorr::encsign_2p_0(
        &x0,
        &r0,
        &x1.public_key,
        &r1.public_key,
        &y.public_key,
        &Message::from_slice(message).unwrap(),
    );

    let schnorr_encsig = schnorr::encsign_2p_1(
        &x1,
        &r1,
        &x0.public_key,
        &r0.public_key,
        &y.public_key,
        &Message::from_slice(message).unwrap(),
        &schnorr_partial_encsig,
    )
    .unwrap();

    let x = KeyPair::new_random();

    let ecdsa_encsig = ecdsa::encsign(&x, &y.public_key, message);

    let ecdsa_sig = ecdsa::decsig(&y, &ecdsa_encsig);

    let rec_key = ecdsa::reckey(&y.public_key, &ecdsa_encsig);
    let y_tag = ecdsa::recover(&ecdsa_sig, &rec_key).unwrap();

    let R_hat = PublicKey::from_combination(&*SECP, vec![&r0.public_key, &r1.public_key]).unwrap();
    let schnorr_sig = schnorr::decsig(&KeyPair::new(y_tag), &schnorr_encsig, &R_hat);

    let X = PublicKey::from_combination(&*SECP, vec![&x0.public_key, &x1.public_key]).unwrap();

    assert!(aggsig::verify_single(
        &*SECP,
        &schnorr_sig,
        &Message::from_slice(message).unwrap(),
        None,
        &X,
        Some(&X),
        None,
        false
    ))
}
