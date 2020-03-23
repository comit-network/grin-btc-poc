use crate::keypair::{build_commitment, random_secret_key, PublicKey, SecretKey, SECP};
use secp256k1zkp::pedersen::RangeProof;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct CommonNonce(SecretKey);

impl CommonNonce {
    pub fn derive(pk: &PublicKey) -> anyhow::Result<Self> {
        let mut hasher = Sha256::new();
        hasher.input(pk.0);
        let sk = SecretKey::from_slice(&*SECP, &hasher.result())?;
        Ok(Self(sk))
    }
}

#[derive(Debug, Clone)]
pub struct Round1 {
    pub T_1: PublicKey,
    pub T_2: PublicKey,
}

impl Round1 {
    /// To generate T_1 and T_2 for each party we hash their x_fund
    pub fn new(private_nonce_salt: &SecretKey) -> anyhow::Result<Self> {
        // They're not used in Round 1 ¯\_(ツ)_/¯
        let value = 0;
        let blind = random_secret_key();
        let common_nonce = random_secret_key();
        let commit = SECP.commit_value(0)?;

        let mut hasher = Sha256::new();
        hasher.input(private_nonce_salt);
        let private_nonce = SecretKey::from_slice(&*SECP, &hasher.result())?;

        let mut T_1 = PublicKey::new();
        let mut T_2 = PublicKey::new();
        let _ = SECP.bullet_proof_multisig(
            value,
            blind,
            common_nonce,
            None,
            None,
            None,
            Some(&mut T_1),
            Some(&mut T_2),
            vec![commit], // What about an empty vector?
            Some(&private_nonce),
            1,
        );

        Ok(Round1 { T_1, T_2 })
    }
}

pub struct Round2 {
    tau_x: SecretKey,
}

impl Round2 {
    pub fn new(
        private_nonce_salt: &SecretKey,
        x_j: &SecretKey,
        X: &PublicKey,
        value: u64,
        common_nonce: &CommonNonce,
        Round1 {
            T_1: T_1_R,
            T_2: T_2_R,
        }: &Round1,
        Round1 {
            T_1: T_1_F,
            T_2: T_2_F,
        }: &Round1,
    ) -> anyhow::Result<Self> {
        let mut T_one = PublicKey::from_combination(&*SECP, vec![&T_1_R, &T_1_F])?;
        let mut T_two = PublicKey::from_combination(&*SECP, vec![&T_2_R, &T_2_F])?;

        let commit = {
            let commit_blind = build_commitment(&X);
            let commit_value = SECP.commit_value(value)?;
            SECP.commit_sum(vec![commit_blind, commit_value], Vec::new())?
        };

        let mut hasher = Sha256::new();
        hasher.input(private_nonce_salt.clone());
        let private_nonce = SecretKey::from_slice(&*SECP, &hasher.result())?;

        let mut tau_x = SecretKey([0; 32]);
        SECP.bullet_proof_multisig(
            value,
            x_j.clone(),
            common_nonce.0.clone(),
            None,
            None,
            Some(&mut tau_x),
            Some(&mut T_one),
            Some(&mut T_two),
            vec![commit],
            Some(&private_nonce),
            2,
        );

        Ok(Round2 { tau_x })
    }
}

pub struct Round3 {
    pub bulletproof: RangeProof,
}

impl Round3 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        private_nonce_salt: &SecretKey,
        x_j: &SecretKey,
        X: &PublicKey,
        value: u64,
        common_nonce: &CommonNonce,
        Round1 {
            T_1: T_1_R,
            T_2: T_2_R,
        }: &Round1,
        Round1 {
            T_1: T_1_F,
            T_2: T_2_F,
        }: &Round1,
        Round2 { tau_x: tau_x_R }: &Round2,
        Round2 { tau_x: tau_x_F }: &Round2,
    ) -> anyhow::Result<Self> {
        let mut T_one = PublicKey::from_combination(&*SECP, vec![&T_1_R, &T_1_F])?;
        let mut T_two = PublicKey::from_combination(&*SECP, vec![&T_2_R, &T_2_F])?;

        let commit = {
            let commit_blind = build_commitment(&X);
            let commit_value = SECP.commit_value(value)?;
            SECP.commit_sum(vec![commit_blind, commit_value], Vec::new())?
        };

        let mut hasher = Sha256::new();
        hasher.input(private_nonce_salt.clone());
        let private_nonce = SecretKey::from_slice(&*SECP, &hasher.result())?;

        let mut tau_x = {
            let mut tau_x = tau_x_R.clone();
            tau_x.add_assign(&*SECP, &tau_x_F)?;
            tau_x
        };

        let bulletproof = SECP
            .bullet_proof_multisig(
                value,
                x_j.clone(),
                common_nonce.0.clone(),
                None,
                None,
                Some(&mut tau_x),
                Some(&mut T_one),
                Some(&mut T_two),
                vec![commit],
                Some(&private_nonce),
                0,
            )
            .ok_or_else(|| anyhow::anyhow!("failed to generate bulletproof"))?;

        SECP.verify_bullet_proof(commit, bulletproof, None)?;

        Ok(Round3 { bulletproof })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::keypair::{KeyPair, Negate};

    #[test]
    fn can_generate_multiparty_bulletproof() -> anyhow::Result<()> {
        let value = 1_000_000;

        let x_input = KeyPair::new_random();

        let x_alice = KeyPair::new_random();
        let common_nonce = CommonNonce::derive(&x_alice.public_key)?;

        let x_bob = KeyPair::new_random();

        let X = PublicKey::from_combination(&*SECP, vec![
            &x_alice.public_key,
            &x_bob.public_key,
            &x_input.public_key.negate(),
        ])?;

        let mut x_bob_prime = x_bob.secret_key;
        x_bob_prime.add_assign(&*SECP, &x_input.secret_key.negate())?;

        let round1_alice = Round1::new(&x_alice.secret_key)?;
        let round1_bob = Round1::new(&x_bob_prime)?;

        let round2_alice = Round2::new(
            &x_alice.secret_key,
            &x_alice.secret_key,
            &X,
            value,
            &common_nonce,
            &round1_alice,
            &round1_bob,
        )?;

        let round2_bob = Round2::new(
            &x_bob_prime,
            &x_bob_prime,
            &X,
            value,
            &common_nonce,
            &round1_alice,
            &round1_bob,
        )?;

        assert!(Round3::new(
            &x_alice.secret_key,
            &x_alice.secret_key,
            &X,
            value,
            &common_nonce,
            &round1_alice,
            &round1_bob,
            &round2_alice,
            &round2_bob,
        )
        .is_ok());
        Ok(())
    }
}
