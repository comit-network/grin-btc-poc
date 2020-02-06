use crate::keypair::{PublicKey, SecretKey, XCoor, SECP};
use secp256k1zkp::Signature;

pub type PartialEncryptedSignature = PartialSignature;

#[derive(Debug, Clone)]
pub struct PartialSignature(SecretKey);

impl From<&Signature> for PartialSignature {
    fn from(from: &Signature) -> PartialSignature {
        let mut s = [0u8; 32];
        s.copy_from_slice(&from.as_ref()[32..64]);
        hex::encode(s);

        PartialSignature(SecretKey::from_slice(&*SECP, &s).unwrap())
    }
}

impl PartialSignature {
    pub fn to_signature(&self, R: &PublicKey) -> Signature {
        let mut sig = [0u8; 64];
        sig[0..32].copy_from_slice(&R.x_coor()[..]);
        sig[32..64].copy_from_slice(&(self.0).0[..]);
        Signature::from_raw_data(&sig).unwrap()
    }
}
