use crate::{
    grin,
    keypair::{KeyPair, Negate, PublicKey, SecretKey, XCoor, YCoor, SECP},
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
) -> Result<(Signature, PublicKey), ()> {
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

    Ok((sig, X))
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

// TODO: Should be able to get R_hat from encsig
pub fn decsig(y: &KeyPair, encsig: &EncryptedSignature, R_hat: &PublicKey) -> Signature {
    // let mut R_hat_x = [0u8; 32];
    // R_hat_x.copy_from_slice(&encsig.as_ref()[0..32]);
    let R = PublicKey::from_combination(&*SECP, vec![&R_hat, &y.public_key]).unwrap();

    let mut s_hat = [0u8; 32];
    s_hat.copy_from_slice(&encsig.as_ref()[32..64]);
    let mut s = SecretKey::from_slice(&*SECP, &s_hat).unwrap();
    s.add_assign(&*SECP, &y.secret_key).unwrap();

    let mut buffer = [0u8; 64];
    buffer[0..32].copy_from_slice(&R.x_coor()[..]);
    buffer[32..64].copy_from_slice(&s.0[..]);
    Signature::from_raw_data(&buffer).unwrap()
}

pub fn recover(sig: &Signature, recovery_key: &RecoveryKey) -> SecretKey {
    let s = SecretKey::from_slice(&*SECP, &sig.as_ref()[32..64]).unwrap();
    let s_hat = &recovery_key.0;

    let mut y = s.clone();
    y.add_assign(&*SECP, &s_hat.negate()).unwrap();
    y
}

#[derive(Debug, Clone)]
pub struct RecoveryKey(pub SecretKey);

impl From<EncryptedSignature> for RecoveryKey {
    fn from(from: EncryptedSignature) -> Self {
        RecoveryKey(SecretKey::from_slice(&*SECP, &from.as_ref()[32..64]).unwrap())
    }
}

pub fn normalize_keypairs(r0: KeyPair, r1: KeyPair, y: KeyPair) -> (KeyPair, KeyPair, KeyPair) {
    let R =
        PublicKey::from_combination(&*SECP, vec![&r0.public_key, &r1.public_key, &y.public_key])
            .unwrap();
    let mut R_y = purerust_secp256k1::curve::Field::default();
    assert!(R_y.set_b32(&R.y_coor()));

    if !R_y.is_quad_var() {
        (r0.negate(), r1.negate(), y.negate())
    } else {
        (r0, r1, y)
    }
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

    #[test]
    fn encsign_and_decsig() {
        let x0 = KeyPair::new_random();
        let x1 = KeyPair::new_random();
        let r0 = KeyPair::new_random();
        let r1 = KeyPair::new_random();

        let y = KeyPair::new_random();

        let (r0, r1, y) = normalize_keypairs(r0, r1, y);

        let message = Message::from_slice(b"mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm").unwrap();

        let partial_encsig = encsign_2p_0(
            &x0,
            &r0,
            &x1.public_key,
            &r1.public_key,
            &y.public_key,
            &message,
        );

        let encsig = encsign_2p_1(
            &x1,
            &r1,
            &x0.public_key,
            &r0.public_key,
            &y.public_key,
            &message,
            &partial_encsig,
        )
        .unwrap();

        let R_hat =
            PublicKey::from_combination(&*SECP, vec![&r0.public_key, &r1.public_key]).unwrap();
        let sig = decsig(&y, &encsig, &R_hat);

        let X = PublicKey::from_combination(&*SECP, vec![&x0.public_key, &x1.public_key]).unwrap();

        assert!(aggsig::verify_single(
            &*SECP,
            &sig,
            &message,
            None,
            &X,
            Some(&X),
            None,
            false
        ));
    }

    #[test]
    fn recover_key_from_decrypted_signature() {
        let x0 = KeyPair::new_random();
        let x1 = KeyPair::new_random();
        let r0 = KeyPair::new_random();
        let r1 = KeyPair::new_random();

        let y = KeyPair::new_random();

        let (r0, r1, y) = normalize_keypairs(r0, r1, y);

        let message = Message::from_slice(b"mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm").unwrap();

        let partial_encsig = encsign_2p_0(
            &x0,
            &r0,
            &x1.public_key,
            &r1.public_key,
            &y.public_key,
            &message,
        );

        let encsig = encsign_2p_1(
            &x1,
            &r1,
            &x0.public_key,
            &r0.public_key,
            &y.public_key,
            &message,
            &partial_encsig,
        )
        .unwrap();

        let R_hat =
            PublicKey::from_combination(&*SECP, vec![&r0.public_key, &r1.public_key]).unwrap();
        let sig = decsig(&y, &encsig, &R_hat);

        let rec_key = RecoveryKey::from(encsig.clone());
        let y_tag = recover(&sig, &rec_key);

        assert_eq!(y.secret_key, y_tag);
    }
}
