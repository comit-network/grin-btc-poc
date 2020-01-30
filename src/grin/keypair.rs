use secp256k1zkp::{ContextFlag, Secp256k1};

pub use secp256k1zkp::key::{PublicKey, SecretKey};

lazy_static::lazy_static! {
    pub static ref SECP: Secp256k1 = Secp256k1::with_caps(ContextFlag::Commit);
}

#[derive(Clone)]
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
}
