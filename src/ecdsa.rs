use crate::{
    dleq,
    keypair::{random_secret_key, KeyPair, Negate, PublicKey, SecretKey, XCoor, G, SECP},
};

#[derive(Debug, PartialEq, Clone)]
pub struct Signature {
    s: SecretKey,
    R_x: SecretKey,
}

#[derive(Debug)]
pub struct EncryptedSignature {
    R: PublicKey,
    R_hat: PublicKey,
    s_hat: SecretKey,
    proof: dleq::Proof,
}

pub fn encsign(x: &KeyPair, Y: &PublicKey, message_hash: &[u8]) -> EncryptedSignature {
    let r = random_secret_key();
    let mut R_hat = *G;
    R_hat.mul_assign(&*SECP, &r).unwrap();

    let mut R = *Y;
    R.mul_assign(&*SECP, &r).unwrap();

    let proof = dleq::prove(&G, &R_hat, &Y, &R, &r);

    let s_hat = {
        let R_x = SecretKey::from_slice(&*SECP, &R.x_coor()).unwrap();

        let mut s_hat = R_x;
        s_hat.mul_assign(&*SECP, &x.secret_key).unwrap();
        s_hat
            .add_assign(
                &*SECP,
                &SecretKey::from_slice(&*SECP, &message_hash).unwrap(),
            )
            .unwrap();

        let mut r_inv = r;
        r_inv.inv_assign(&*SECP).unwrap();

        s_hat.mul_assign(&*SECP, &r_inv).unwrap();

        s_hat
    };

    EncryptedSignature {
        R,
        R_hat,
        s_hat,
        proof,
    }
}

#[derive(Debug, Clone)]
pub enum EncVerifyError {
    InvalidProof,
    Invalid,
}

pub fn encverify(
    X: &PublicKey,
    Y: &PublicKey,
    message_hash: &[u8],
    EncryptedSignature {
        R,
        R_hat,
        s_hat,
        proof,
    }: &EncryptedSignature,
) -> Result<(), EncVerifyError> {
    if !dleq::verify(&*G, R_hat, Y, R, proof) {
        return Err(EncVerifyError::InvalidProof);
    }

    let R_x = SecretKey::from_slice(&*SECP, &R.x_coor()).unwrap();

    let message_hash = SecretKey::from_slice(&*SECP, message_hash).unwrap();

    let mut s_hat_inv = s_hat.clone();
    s_hat_inv.inv_assign(&*SECP).unwrap();

    let U0 = {
        let mut u0 = message_hash;
        u0.mul_assign(&*SECP, &s_hat_inv).unwrap();
        let mut U0 = *G;
        U0.mul_assign(&*SECP, &u0).unwrap();
        U0
    };

    let U1 = {
        let mut u1 = R_x;
        u1.mul_assign(&*SECP, &s_hat_inv).unwrap();
        let mut U1 = *X;
        U1.mul_assign(&*SECP, &u1).unwrap();
        U1
    };

    let R_hat_candidate = PublicKey::from_combination(&*SECP, vec![&U0, &U1]).unwrap();

    if &R_hat_candidate == R_hat {
        Ok(())
    } else {
        Err(EncVerifyError::Invalid)
    }
}

pub fn decsig(y: &KeyPair, EncryptedSignature { R, s_hat, .. }: &EncryptedSignature) -> Signature {
    let s = {
        let mut y_inv = y.secret_key.clone();
        y_inv.inv_assign(&*SECP).unwrap();

        let mut s = s_hat.clone();
        s.mul_assign(&*SECP, &y_inv).unwrap();
        s
    };

    let R_x = R.x_coor();

    Signature {
        s,
        R_x: SecretKey::from_slice(&*SECP, &R_x).unwrap(),
    }
}

#[derive(Debug, Clone)]
pub struct RecoveryKey {
    Y: PublicKey,
    s_hat: SecretKey,
}

pub fn reckey(
    &Y: &PublicKey,
    EncryptedSignature { s_hat, .. }: &EncryptedSignature,
) -> RecoveryKey {
    RecoveryKey {
        Y,
        s_hat: s_hat.clone(),
    }
}

pub fn recover(
    Signature { s, .. }: &Signature,
    RecoveryKey { Y, s_hat }: &RecoveryKey,
) -> anyhow::Result<KeyPair> {
    let y_macron = {
        let mut s_inv = s.clone();
        s_inv.inv_assign(&*SECP)?;

        let mut y_macron = s_hat.clone();
        y_macron.mul_assign(&*SECP, &s_inv)?;
        y_macron
    };

    let mut Gy_macron = *G;
    Gy_macron.mul_assign(&*SECP, &y_macron)?;

    if Gy_macron == *Y {
        Ok(KeyPair::new(y_macron))
    } else if Gy_macron == Y.negate() {
        Ok(KeyPair::new(y_macron.negate()))
    } else {
        unreachable!("cannot be triggered")
    }
}

impl From<Signature> for secp256k1zkp::Signature {
    fn from(from: Signature) -> Self {
        let mut buffer = [0u8; 64];

        buffer[0..32].copy_from_slice(&from.R_x[..]);
        buffer[32..64].copy_from_slice(&from.s[..]);

        let mut sig = secp256k1zkp::Signature::from_compact(&*SECP, &buffer).unwrap();
        sig.normalize_s(&*SECP);
        sig
    }
}

impl From<secp256k1zkp::Signature> for Signature {
    fn from(from: secp256k1zkp::Signature) -> Self {
        let mut sig = from;
        sig.normalize_s(&*SECP);
        let bytes = sig.serialize_compact(&*SECP);
        let mut R_x = [0u8; 32];
        let mut s = [0u8; 32];
        R_x.copy_from_slice(&bytes[0..32]);
        s.copy_from_slice(&bytes[32..64]);

        Self {
            R_x: SecretKey::from_slice(&*SECP, &R_x).unwrap(),
            s: SecretKey::from_slice(&*SECP, &s).unwrap(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use secp256k1zkp::Message;

    #[test]
    fn encsign_and_encverify() {
        let x = KeyPair::new_random();
        let y = KeyPair::new_random();
        let message_hash = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

        let enc_signature = encsign(&x, &y.public_key, message_hash);

        encverify(&x.public_key, &y.public_key, message_hash, &enc_signature).unwrap();
    }

    #[test]
    fn ecdsa_encsign_and_decsig() {
        let x = KeyPair::new_random();
        let y = KeyPair::new_random();

        let message_hash = b"mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";
        let _message_hash = &Message::from_slice(message_hash).expect("message hash");

        let encsig = encsign(&x, &y.public_key, message_hash);

        let sig = decsig(&y, &encsig);

        assert!(SECP
            .verify(_message_hash, &sig.into(), &x.public_key)
            .is_ok())
    }

    #[test]
    fn recover_key_from_decrypted_signature() {
        let x = KeyPair::new_random();
        let y = KeyPair::new_random();

        let message_hash = b"mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";

        let encsig = encsign(&x, &y.public_key, message_hash);
        let sig = decsig(&y, &encsig);

        let rec_key = reckey(&y.public_key, &encsig);
        let y_tag = recover(&sig, &rec_key).unwrap();

        assert_eq!(y.secret_key, y_tag.secret_key);
    }
}
