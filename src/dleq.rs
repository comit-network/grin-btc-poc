use crate::keypair::{
    ConvertBigInt, KeyPair, PublicKey, SecretKey, XCoor, CURVE_ORDER, G, HALF_CURVE_ORDER, SECP,
};
use gmp::mpz::Mpz;
use sha2::{Digest, Sha256};
use std::borrow::Borrow;

pub struct Proof {
    s: SecretKey,
    c: SecretKey,
}

fn prove(R_hat: PublicKey, Y: PublicKey, R: PublicKey, witness: SecretKey) -> Proof {
    let secret_nonce = KeyPair::new_random();

    let public_nonce_1 = secret_nonce.public_key;
    let mut public_nonce_2 = Y.clone();
    public_nonce_2
        .mul_assign(&*SECP, &secret_nonce.secret_key)
        .unwrap();

    let mut hasher = Sha256::default();
    hasher.input(&G.serialize_vec(&*SECP, true)[..]);
    hasher.input(&R_hat.serialize_vec(&*SECP, true)[..]);
    hasher.input(&Y.serialize_vec(&*SECP, true)[..]);
    hasher.input(&R.serialize_vec(&*SECP, true)[..]);
    hasher.input(&public_nonce_1.serialize_vec(&*SECP, true));
    hasher.input(&public_nonce_2.serialize_vec(&*SECP, true));

    let c = SecretKey::from_slice(&*SECP, &hasher.result()[..]).unwrap();
    let mut s = c.clone();
    s.mul_assign(&*SECP, &witness).unwrap();
    s.add_assign(&*SECP, &secret_nonce.secret_key).unwrap();

    Proof { s, c }
}
