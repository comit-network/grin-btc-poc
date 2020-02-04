use crate::keypair::{
    ConvertBigInt, KeyPair, PublicKey, SecretKey, XCoor, CURVE_ORDER, G, HALF_CURVE_ORDER, SECP,
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
    fn test_own_sign() {
        let x = KeyPair::new_random();
        let message_hash = b"hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh";
        let _message_hash = &Message::from_slice(message_hash).unwrap();

        let signature = sign(&x, message_hash);

        // let signature = SECP.sign(message_hash, &x.secret_key).unwrap();

        assert!(SECP
            .verify(_message_hash, &signature.into(), &x.public_key)
            .is_ok())
    }

    #[test]
    fn test_own_verify() {
        let x = KeyPair::new_random();
        let message_hash = b"hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh";

        let signature = sign(&x, message_hash);

        assert!(verify(&x.public_key, message_hash, &signature))
    }
}
