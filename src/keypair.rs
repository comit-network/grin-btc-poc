use rand::Rng;
pub use secp256k1zkp::key::{PublicKey, SecretKey, ZERO_KEY};
use secp256k1zkp::{pedersen, ContextFlag, Message, Secp256k1, Signature};
use crate::bitcoin::{BitcoinPublicKey,Address, Network};

lazy_static::lazy_static! {
    pub static ref SECP: Secp256k1 = Secp256k1::with_caps(ContextFlag::Commit);
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

    pub fn to_bitcoin_address(&self) -> Address {
        Address::p2wpkh(&BitcoinPublicKey { key: self.public_key, compressed: true }, Network::Regtest)
    }
}

pub fn verify_ecdsa(msg: &Message, sig: &Signature, pk: &PublicKey) -> bool {
    SECP.verify(msg, sig, pk).is_ok()
}

pub trait XCoor {
    fn x_coor(&self) -> [u8; 32];
}

impl XCoor for PublicKey {
    fn x_coor(&self) -> [u8; 32] {
        let serialized_pk = self.serialize_vec(&*SECP, true);

        let mut x_coor = [0u8; 32];
        // there's a random byte at the front of the uncompressed serialized pk
        x_coor.copy_from_slice(&serialized_pk[1..33]);
        x_coor
    }
}

pub trait YCoor {
    fn y_coor(&self) -> [u8; 32];
}

impl YCoor for PublicKey {
    fn y_coor(&self) -> [u8; 32] {
        let serialized_pk = self.serialize_vec(&*SECP, false);

        let mut y_coor = [0u8; 32];
        y_coor.copy_from_slice(&serialized_pk[33..65]);
        y_coor
    }
}

pub trait Negate {
    fn negate(&self) -> Self;
}

impl Negate for PublicKey {
    fn negate(&self) -> Self {
        let mut negated = *self;
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

    let mut pk_y = purerust_secp256k1::curve::Field::default();
    assert!(pk_y.set_b32(&pk.y_coor()));

    if !pk_y.is_quad_var() {
        buffer[0] = 0x09;
    } else {
        buffer[0] = 0x08;
    }

    pedersen::Commitment::from_vec(buffer.to_vec())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn to_commitment_roundtrip() {
        let x = KeyPair::new_random();
        let commit = build_commitment(&x.public_key);

        let theirs = commit.to_pubkey(&*SECP).unwrap();
        let ours = x.public_key;

        assert_eq!(theirs, ours);
    }

    #[test]
    fn to_commitment_vs_commit() {
        let x = KeyPair::new_random();
        let ours = build_commitment(&x.public_key);
        let theirs = SECP.commit(0, x.secret_key).unwrap();

        assert_eq!(theirs, ours);
    }
}
