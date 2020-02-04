use gmp::mpz::Mpz;
use rand::Rng;
pub use secp256k1zkp::key::{PublicKey, SecretKey};
use secp256k1zkp::{ContextFlag, Message, Secp256k1, Signature};

lazy_static::lazy_static! {
    pub static ref SECP: Secp256k1 = Secp256k1::with_caps(ContextFlag::Commit);
    pub static ref CURVE_ORDER: Mpz = Mpz::from(&secp256k1zkp::constants::CURVE_ORDER[..]);
    pub static ref HALF_CURVE_ORDER: Mpz = CURVE_ORDER.div_floor(&Mpz::from(2));
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
        KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>())
    }

    pub fn sign_ecdsa(&self, message: &Message) -> Signature {
        SECP.sign(message, &self.secret_key).expect("cannot fail")
    }
}

pub fn verify_ecdsa(msg: &Message, sig: &Signature, pk: &PublicKey) -> bool {
    SECP.verify(msg, sig, pk).is_ok()
}

pub trait XCoor {
    fn x_coor(&self) -> Mpz;
}

impl XCoor for PublicKey {
    fn x_coor(&self) -> Mpz {
        let serialized_pk = self.serialize_vec(&*SECP, false);
        let x = &serialized_pk[1..serialized_pk.len() / 2 + 1];
        let x_vec = x.to_vec();

        Mpz::from(&x_vec[..])
    }
}

pub trait ToBigInt {
    fn to_bigint(&self) -> Mpz;
}

impl ToBigInt for SecretKey {
    fn to_bigint(&self) -> Mpz {
        Mpz::from(&self.0[..])
    }
}
