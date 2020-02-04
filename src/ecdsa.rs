use crate::{
    dleq,
    keypair::{
        random_secret_key, ConvertBigInt, KeyPair, PublicKey, SecretKey, XCoor, CURVE_ORDER, G,
        HALF_CURVE_ORDER, SECP,
    },
};
use gmp::mpz::Mpz;
use std::borrow::Borrow;

pub struct Signature {
    s: Mpz,
    Rx: Mpz,
}

fn sign(x: &KeyPair, message_hash: &[u8]) -> Signature {
    let r = KeyPair::new_random();

    // Get x-coordinate modulo q
    let Rx = r.public_key.x_coor().mod_floor(&*CURVE_ORDER);

    // TODO: only use Mpz arithmetic for inverting, rest should go back to
    // secp256k1::SecretKey arithmetic
    let r_inv = r.secret_key.to_bigint().invert(&*CURVE_ORDER).unwrap();

    let message_hash = Mpz::from(message_hash);

    let x = x.secret_key.to_bigint();
    let s = {
        let s = (x * Rx.clone()).mod_floor(&*CURVE_ORDER);
        let s = (message_hash + s).mod_floor(&*CURVE_ORDER);
        let s = (r_inv * s).mod_floor(&*CURVE_ORDER);

        if s > *HALF_CURVE_ORDER {
            s - &*CURVE_ORDER
        } else {
            s
        }
    };

    Signature { s, Rx }
}

pub struct EncryptedSignature {
    R: PublicKey,
    R_hat: PublicKey,
    s_hat: SecretKey,
    proof: dleq::Proof,
}

pub fn encsign(x: &KeyPair, Y: &PublicKey, message_hash: &[u8]) -> EncryptedSignature {
    // TODO: generate secret key randomly and make dleq::prove abstract (taking both
    // generators)
    let r = random_secret_key();
    let mut R_hat = G.clone();
    R_hat.mul_assign(&*SECP, &r).unwrap();

    let mut R = Y.clone();
    R.mul_assign(&*SECP, &r).unwrap();

    let proof = dleq::prove(&G, &R_hat, &Y, &R, &r);

    // TODO: implement x_coor_mod_q() -> SecretKey on XCoor
    let Rx = R_hat.x_coor().mod_floor(&*CURVE_ORDER);
    let Rx = SecretKey::from_bigint(&Rx).unwrap();

    let mut s_hat = Rx.clone();
    s_hat.mul_assign(&*SECP, &x.secret_key).unwrap();
    s_hat
        .add_assign(
            &*SECP,
            &SecretKey::from_slice(&*SECP, &message_hash).expect("TODO: mod q the message hash"),
        )
        .unwrap();

    // TODO: implement invert on secp256k1::SecretKey
    let r_inv = r.to_bigint().invert(&*CURVE_ORDER).unwrap();
    let r_inv = SecretKey::from_bigint(&r_inv).unwrap();

    s_hat.mul_assign(&*SECP, &r_inv).unwrap();

    EncryptedSignature {
        R,
        R_hat,
        s_hat,
        proof,
    }
}

/// ECDSA verification
/// Does not check low s
fn verify(X: &PublicKey, message_hash: &[u8], signature: &Signature) -> bool {
    let message_hash = Mpz::from(message_hash);

    let s_inv = signature.s.invert(&*CURVE_ORDER).unwrap();

    let u0 = (message_hash * s_inv.clone()).mod_floor(&*CURVE_ORDER);
    let u1 = (signature.Rx.clone() * s_inv).mod_floor(&*CURVE_ORDER);

    let mut U0 = G.clone();
    U0.mul_assign(&*SECP, &SecretKey::from_bigint(&u0).unwrap())
        .unwrap();
    let mut U1 = X.clone();
    U1.mul_assign(&*SECP, &SecretKey::from_bigint(&u1).unwrap())
        .unwrap();

    let R_tag = PublicKey::from_combination(&*SECP, vec![&U0, &U1]).unwrap();

    R_tag.x_coor() == signature.Rx
}

impl From<Signature> for secp256k1zkp::Signature {
    fn from(from: Signature) -> Self {
        let mut buffer = [0u8; 64];

        let vec: Vec<u8> = from.Rx.borrow().into();
        dbg!(&vec);
        buffer[0..32].copy_from_slice(&vec);
        let vec: Vec<u8> = from.s.borrow().into();
        dbg!(&vec);
        buffer[32..64].copy_from_slice(&vec);

        secp256k1zkp::Signature::from_compact(&*SECP, &buffer[..]).unwrap()
    }
}

mod tests {
    use super::*;
    use secp256k1zkp::Message;

    #[test]
    fn valid_signature_using_secp() {
        let x = KeyPair::new_random();
        let message_hash = b"hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh";
        let _message_hash = &Message::from_slice(message_hash).unwrap();

        let signature = sign(&x, message_hash);

        assert!(SECP
            .verify(_message_hash, &signature.into(), &x.public_key)
            .is_ok())
    }

    #[test]
    fn sign_and_verify() {
        let x = KeyPair::new_random();
        let message_hash = b"hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh";

        let signature = sign(&x, message_hash);

        assert!(verify(&x.public_key, message_hash, &signature))
    }
}
