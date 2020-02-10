use gmp::mpz::Mpz;
use rand::Rng;
pub use secp256k1zkp::key::{PublicKey, SecretKey};
use secp256k1zkp::{pedersen, ContextFlag, Message, Secp256k1, Signature};
use std::borrow::Borrow;

lazy_static::lazy_static! {
    pub static ref SECP: Secp256k1 = Secp256k1::with_caps(ContextFlag::Commit);
    pub static ref CURVE_ORDER: Mpz = Mpz::from(&secp256k1zkp::constants::CURVE_ORDER[..]);
    pub static ref HALF_CURVE_ORDER: Mpz = CURVE_ORDER.div_floor(&Mpz::from(2));
    pub static ref G: PublicKey = {
        let mut vec = vec![4u8];
        vec.extend(&secp256k1zkp::constants::GENERATOR_G[..]);
        PublicKey::from_slice(&*SECP, &vec).unwrap()
    };
    pub static ref H: PublicKey = {
        let mut vec = vec![4u8];
        vec.extend(&secp256k1zkp::constants::GENERATOR_H[..]);
        PublicKey::from_slice(&*SECP, &vec).unwrap()
    };
    pub static ref MINUS_ONE: SecretKey = {
        let mut one = secp256k1zkp::key::ONE_KEY;
        one.neg_assign(&*SECP).unwrap();
        one
    };
}

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

impl KeyPair {
    pub fn new(secret_key: SecretKey) -> Self {
        let public_key = PublicKey::from_secret_key(&*SECP, &secret_key)
            .expect("could not derive public key from secret key");
        KeyPair {
            secret_key,
            public_key,
        }
    }

    pub fn from_slice(data: &[u8; 32]) -> KeyPair {
        let secret_key =
            SecretKey::from_slice(&*SECP, data).expect("could not derive secret key from slice");

        KeyPair::new(secret_key)
    }

    pub fn new_random() -> Self {
        KeyPair::new(random_secret_key())
    }

    pub fn sign_ecdsa(&self, message: &Message) -> Signature {
        SECP.sign(message, &self.secret_key).expect("cannot fail")
    }
}

pub fn verify_ecdsa(msg: &Message, sig: &Signature, pk: &PublicKey) -> bool {
    SECP.verify(msg, sig, pk).is_ok()
}

pub trait XCoor {
    fn x_coor(&self) -> [u8; 32];
    fn x_coor_mod_q(&self) -> SecretKey {
        let x_coor = Mpz::from(&self.x_coor()[..]).mod_floor(&*CURVE_ORDER);
        SecretKey::from_bigint(&x_coor).unwrap()
    }
}

impl XCoor for PublicKey {
    fn x_coor(&self) -> [u8; 32] {
        let serialized_pk = self.serialize_vec(&*SECP, false);

        let mut x_coor = [0u8; 32];
        x_coor.copy_from_slice(&serialized_pk[1..serialized_pk.len() / 2 + 1]);
        x_coor
    }
}

pub trait Negate {
    fn negate(&self) -> Self;
}

impl Negate for PublicKey {
    fn negate(&self) -> Self {
        let mut negated = self.clone();
        negated.mul_assign(&*SECP, &*MINUS_ONE).unwrap();
        negated
    }
}

impl Negate for SecretKey {
    fn negate(&self) -> Self {
        let mut negated = self.clone();
        negated.neg_assign(&*SECP).unwrap();
        negated
    }
}

impl Negate for KeyPair {
    fn negate(&self) -> Self {
        KeyPair {
            secret_key: self.secret_key.negate(),
            public_key: self.public_key.negate(),
        }
    }
}

pub trait ConvertBigInt: Sized {
    fn to_bigint(&self) -> Mpz;
    fn from_bigint(from: &Mpz) -> Option<Self>;
}

impl ConvertBigInt for SecretKey {
    fn to_bigint(&self) -> Mpz {
        Mpz::from(&self.0[..])
    }

    fn from_bigint(from: &Mpz) -> Option<Self> {
        let vec: Vec<u8> = from.borrow().into();
        SecretKey::from_slice(&*SECP, &vec).ok()
    }
}

pub fn random_secret_key() -> SecretKey {
    SecretKey::from_slice(&*SECP, &rand::thread_rng().gen::<[u8; 32]>()).unwrap()
}

pub fn build_commitment(pk: &PublicKey) -> pedersen::Commitment {
    let mut buffer = [0u8; 33];

    // Reverse first 32 bytes of pubkey
    let mut commit = [0u8; 32];
    commit.copy_from_slice(&pk.0[0..32]);
    commit.reverse();
    buffer[1..33].copy_from_slice(&commit);

    // First byte equal to 0x08 or 0x09 50% of the time
    // TODO: Determine actual value of first byte
    buffer[0] = 0x08;
    // buffer[0] = 0x09;

    pedersen::Commitment::from_vec(buffer.to_vec())
}

#[cfg(test)]
mod test {
    use super::*;
    // Works everytime 50% of the time
    #[test]
    fn to_commitment_roundtrip() {
        let x = KeyPair::new_random();
        let commit = build_commitment(&x.public_key);

        let theirs = commit.to_pubkey(&*SECP).unwrap();
        let ours = x.public_key;

        assert_eq!(theirs, ours);
    }
    // Works everytime 50% of the time
    #[test]
    fn to_commitment_vs_commit() {
        let x = KeyPair::new_random();
        let ours = build_commitment(&x.public_key);
        let theirs = SECP.commit(0, x.secret_key).unwrap();

        assert_eq!(theirs, ours);
    }
}
