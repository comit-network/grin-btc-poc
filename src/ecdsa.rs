use crate::{
    dleq,
    keypair::{
        random_secret_key, ConvertBigInt, KeyPair, PublicKey, SecretKey, XCoor, CURVE_ORDER, G,
        HALF_CURVE_ORDER, SECP,
    },
};

pub struct Signature {
    s: SecretKey,
    R_x: SecretKey,
}

#[allow(dead_code)]
fn sign(x: &KeyPair, message_hash: &[u8]) -> Signature {
    let r = KeyPair::new_random();

    let R_x = r.public_key.x_coor_mod_q();

    let mut r_inv = r.secret_key.clone();
    r_inv.inv_assign(&*SECP).unwrap();

    let message_hash = SecretKey::from_slice(&*SECP, message_hash).unwrap();

    let mut s = x.secret_key.clone();
    s.mul_assign(&*SECP, &R_x).unwrap();
    s.add_assign(&*SECP, &message_hash).unwrap();
    s.mul_assign(&*SECP, &r_inv).unwrap();

    // TODO: we don't actually need bigint for this, we can just compare the bytes
    let s = s.to_bigint();
    let s = if s > *HALF_CURVE_ORDER {
        s - &*CURVE_ORDER
    } else {
        s
    };
    let s = SecretKey::from_bigint(&s).unwrap();

    Signature { s, R_x }
}

pub struct EncryptedSignature {
    R: PublicKey,
    R_hat: PublicKey,
    s_hat: SecretKey,
    proof: dleq::Proof,
}

pub fn encsign(x: &KeyPair, Y: &PublicKey, message_hash: &[u8]) -> EncryptedSignature {
    let r = random_secret_key();
    let mut R_hat = G.clone();
    R_hat.mul_assign(&*SECP, &r).unwrap();

    let mut R = Y.clone();
    R.mul_assign(&*SECP, &r).unwrap();

    let proof = dleq::prove(&G, &R_hat, &Y, &R, &r);

    let s_hat = {
        let R_x = R.x_coor_mod_q();

        let mut s_hat = R_x.clone();
        s_hat.mul_assign(&*SECP, &x.secret_key).unwrap();
        s_hat
            .add_assign(
                &*SECP,
                &SecretKey::from_slice(&*SECP, &message_hash)
                    .expect("TODO: mod q the message hash"),
            )
            .unwrap();

        let mut r_inv = r.clone();
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

/// ECDSA verification
/// Does not check low s
#[allow(dead_code)]
fn verify(X: &PublicKey, message_hash: &[u8], signature: &Signature) -> bool {
    let message_hash = SecretKey::from_slice(&*SECP, message_hash).unwrap();

    let mut s_inv = signature.s.clone();
    s_inv.inv_assign(&*SECP).unwrap();

    let U0 = {
        let mut u0 = message_hash;
        u0.mul_assign(&*SECP, &s_inv).unwrap();
        let mut U0 = G.clone();
        U0.mul_assign(&*SECP, &u0).unwrap();
        U0
    };

    let U1 = {
        let mut u1 = signature.R_x.clone();
        u1.mul_assign(&*SECP, &s_inv).unwrap();
        let mut U1 = X.clone();
        U1.mul_assign(&*SECP, &u1).unwrap();
        U1
    };

    let R = PublicKey::from_combination(&*SECP, vec![&U0, &U1]).unwrap();

    R.x_coor_mod_q() == signature.R_x
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

    let R_x = R.x_coor_mod_q();

    let message_hash = SecretKey::from_slice(&*SECP, message_hash).unwrap();

    let mut s_hat_inv = s_hat.clone();
    s_hat_inv.inv_assign(&*SECP).unwrap();

    let U0 = {
        let mut u0 = message_hash;
        u0.mul_assign(&*SECP, &s_hat_inv).unwrap();
        let mut U0 = G.clone();
        U0.mul_assign(&*SECP, &u0).unwrap();
        U0
    };

    let U1 = {
        let mut u1 = R_x.clone();
        u1.mul_assign(&*SECP, &s_hat_inv).unwrap();
        let mut U1 = X.clone();
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

impl From<Signature> for secp256k1zkp::Signature {
    fn from(from: Signature) -> Self {
        let mut buffer = [0u8; 64];

        buffer[0..32].copy_from_slice(&from.R_x[..]);
        buffer[32..64].copy_from_slice(&from.s[..]);

        secp256k1zkp::Signature::from_compact(&*SECP, &buffer[..]).unwrap()
    }
}

#[cfg(test)]
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

    #[test]
    fn encsign_and_encverify() {
        let x = KeyPair::new_random();
        let y = KeyPair::new_random();
        let message_hash = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

        let enc_signature = encsign(&x, &y.public_key, message_hash);

        encverify(&x.public_key, &y.public_key, message_hash, &enc_signature).unwrap();
    }
}
