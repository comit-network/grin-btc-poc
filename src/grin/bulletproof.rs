use crate::keypair::{build_commitment, random_secret_key, PublicKey, SecretKey, SECP};
use secp256k1zkp::pedersen::RangeProof;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct Round1 {
    pub T_1: PublicKey,
    pub T_2: PublicKey,
}

impl Round1 {
    /// To generate T_1 and T_2 for each party we hash their x_fund
    pub fn new(x_j: &SecretKey) -> Self {
        // They're not used in Round 1 ¯\_(ツ)_/¯
        let value = 0; // I think it's not used
        let common_nonce = random_secret_key();
        let commit = SECP.commit_value(0).unwrap();

        let mut hasher = Sha256::new();
        hasher.input(x_j);
        let private_nonce = SecretKey::from_slice(&*SECP, &hasher.result()).unwrap();

        let mut T_1 = PublicKey::new();
        let mut T_2 = PublicKey::new();
        let _ = SECP.bullet_proof_multisig(
            value,
            x_j.clone(),
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

        Round1 { T_1, T_2 }
    }
}

pub struct Round2 {
    tau_x: SecretKey,
}

impl Round2 {
    pub fn new(
        x_j: &SecretKey,
        X: &PublicKey,
        value: u64,
        common_nonce: &SecretKey,
        Round1 {
            T_1: T_1_R,
            T_2: T_2_R,
        }: &Round1,
        Round1 {
            T_1: T_1_F,
            T_2: T_2_F,
        }: &Round1,
    ) -> Self {
        let mut T_one = PublicKey::from_combination(&*SECP, vec![&T_1_R, &T_1_F]).unwrap();
        let mut T_two = PublicKey::from_combination(&*SECP, vec![&T_2_R, &T_2_F]).unwrap();

        let commit = {
            let commit_blind = build_commitment(&X);
            let commit_value = SECP.commit_value(value).unwrap();
            SECP.commit_sum(vec![commit_blind, commit_value], Vec::new())
                .unwrap()
        };

        let mut hasher = Sha256::new();
        hasher.input(x_j.clone());
        let private_nonce = SecretKey::from_slice(&*SECP, &hasher.result()).unwrap();

        let mut tau_x = SecretKey([0; 32]);
        SECP.bullet_proof_multisig(
            value,
            x_j.clone(),
            common_nonce.clone(),
            None,
            None,
            Some(&mut tau_x),
            Some(&mut T_one),
            Some(&mut T_two),
            vec![commit],
            Some(&private_nonce),
            2,
        );

        Round2 { tau_x }
    }
}

pub struct Round3 {
    pub bulletproof: RangeProof,
}

impl Round3 {
    pub fn new(
        x_j: &SecretKey,
        X: &PublicKey,
        value: u64,
        common_nonce: &SecretKey,
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
    ) -> Self {
        let mut T_one = PublicKey::from_combination(&*SECP, vec![&T_1_R, &T_1_F]).unwrap();
        let mut T_two = PublicKey::from_combination(&*SECP, vec![&T_2_R, &T_2_F]).unwrap();

        let commit = {
            let commit_blind = build_commitment(&X);
            let commit_value = SECP.commit_value(value).unwrap();
            SECP.commit_sum(vec![commit_blind, commit_value], Vec::new())
                .unwrap()
        };

        let mut hasher = Sha256::new();
        hasher.input(x_j.clone());
        let private_nonce = SecretKey::from_slice(&*SECP, &hasher.result()).unwrap();

        let mut tau_x = {
            let mut tau_x = tau_x_R.clone();
            tau_x.add_assign(&*SECP, &tau_x_F).unwrap();
            tau_x
        };

        let bulletproof = SECP
            .bullet_proof_multisig(
                value,
                x_j.clone(),
                common_nonce.clone(),
                None,
                None,
                Some(&mut tau_x),
                Some(&mut T_one),
                Some(&mut T_two),
                vec![commit],
                Some(&private_nonce),
                0,
            )
            .unwrap();

        Round3 { bulletproof }
    }
}
