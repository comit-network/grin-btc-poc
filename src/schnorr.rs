use crate::{
    grin,
    keypair::{KeyPair, PublicKey, SecretKey, XCoor, SECP},
};
use secp256k1zkp::{aggsig, Message, Signature};

pub type EncryptedSignature = Signature;
pub type PartialEncryptedSignature = PartialSignature;

#[derive(Debug, Clone)]
pub struct PartialSignature(pub SecretKey);

pub fn sign_2p_0(
    x0: &KeyPair,
    r0: &KeyPair,
    X1: &PublicKey,
    R1: &PublicKey,
    message: &Message,
) -> PartialSignature {
    let R = PublicKey::from_combination(&*SECP, vec![&r0.public_key, &R1]).unwrap();
    let X = PublicKey::from_combination(&*SECP, vec![&x0.public_key, &X1]).unwrap();

    grin::calculate_partial_sig(
        &*SECP,
        &x0.secret_key,
        &r0.secret_key,
        &R,
        Some(&X),
        &message,
    )
    .unwrap()
    .into()
}

pub fn sign_2p_1(
    x1: &KeyPair,
    r1: &KeyPair,
    X0: &PublicKey,
    R0: &PublicKey,
    message: &Message,
    partial_sig_0: &PartialSignature,
) -> Result<EncryptedSignature, ()> {
    let R = PublicKey::from_combination(&*SECP, vec![&r1.public_key, &R0]).unwrap();
    let X = PublicKey::from_combination(&*SECP, vec![&x1.public_key, &X0]).unwrap();

    let partial_sig_1 = PartialSignature::from(
        grin::calculate_partial_sig(
            &*SECP,
            &x1.secret_key,
            &r1.secret_key,
            &R,
            Some(&X),
            message,
        )
        .unwrap(),
    );

    let sig = {
        let mut sig = partial_sig_0.0.clone();
        sig.add_assign(&*SECP, &partial_sig_1.0).unwrap();

        PartialSignature(sig).to_signature(&R)
    };

    if !aggsig::verify_single(&*SECP, &sig, message, None, &X, Some(&X), None, false) {
        return Err(());
    }

    Ok(sig)
}

pub fn encsign_2p_0(
    x0: &KeyPair,
    r0: &KeyPair,
    X1: &PublicKey,
    R1: &PublicKey,
    Y: &PublicKey,
    message: &Message,
) -> PartialEncryptedSignature {
    let R = PublicKey::from_combination(&*SECP, vec![&r0.public_key, &R1, &Y]).unwrap();

    let X = PublicKey::from_combination(&*SECP, vec![&x0.public_key, &X1]).unwrap();

    grin::calculate_partial_sig(
        &*SECP,
        &x0.secret_key,
        &r0.secret_key,
        &R,
        Some(&X),
        &message,
    )
    .unwrap()
    .into()
}

pub fn encsign_2p_1(
    x1: &KeyPair,
    r1: &KeyPair,
    X0: &PublicKey,
    R0: &PublicKey,
    Y: &PublicKey,
    message: &Message,
    partial_encsig_0: &PartialEncryptedSignature,
) -> Result<EncryptedSignature, ()> {
    let R_hat = PublicKey::from_combination(&*SECP, vec![&r1.public_key, &R0]).unwrap();
    let R = PublicKey::from_combination(&*SECP, vec![&R_hat, &Y]).unwrap();

    let X = PublicKey::from_combination(&*SECP, vec![&x1.public_key, &X0]).unwrap();

    let partial_encsig_1 = PartialEncryptedSignature::from(
        grin::calculate_partial_sig(
            &*SECP,
            &x1.secret_key,
            &r1.secret_key,
            &R,
            Some(&X),
            message,
        )
        .unwrap(),
    );

    let encsig = {
        let mut sig = partial_encsig_0.0.clone();
        sig.add_assign(&*SECP, &partial_encsig_1.0).unwrap();

        PartialSignature(sig).to_signature(&R_hat)
    };

    if !aggsig::verify_single(&*SECP, &encsig, message, Some(&R), &X, Some(&X), None, true) {
        return Err(());
    }

    Ok(encsig)
}

impl From<Signature> for PartialSignature {
    fn from(from: Signature) -> PartialSignature {
        let mut s = [0u8; 32];
        s.copy_from_slice(&from.as_ref()[32..64]);

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

#[derive(Debug, Clone)]
pub struct RecoveryKey(pub SecretKey);

impl From<EncryptedSignature> for RecoveryKey {
    fn from(from: EncryptedSignature) -> Self {
        RecoveryKey(SecretKey::from_slice(&*SECP, &from.as_ref()[32..64]).unwrap())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let x0 = KeyPair::new_random();
        let x1 = KeyPair::new_random();
        let r0 = KeyPair::new_random();
        let r1 = KeyPair::new_random();

        let message = Message::from_slice(b"mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm").unwrap();

        let partial_sig = sign_2p_0(&x0, &r0, &x1.public_key, &r1.public_key, &message);

        assert!(sign_2p_1(
            &x1,
            &r1,
            &x0.public_key,
            &r0.public_key,
            &message,
            &partial_sig,
        )
        .is_ok());
    }

    #[test]
    fn encsign_and_encverify() {
        let x0 = KeyPair::new_random();
        let x1 = KeyPair::new_random();
        let r0 = KeyPair::new_random();
        let r1 = KeyPair::new_random();

        let y = KeyPair::new_random();

        let message = Message::from_slice(b"mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm").unwrap();

        let partial_encsig = encsign_2p_0(
            &x0,
            &r0,
            &x1.public_key,
            &r1.public_key,
            &y.public_key,
            &message,
        );

        assert!(encsign_2p_1(
            &x1,
            &r1,
            &x0.public_key,
            &r0.public_key,
            &y.public_key,
            &message,
            &partial_encsig,
        )
        .is_ok());
    }
}
