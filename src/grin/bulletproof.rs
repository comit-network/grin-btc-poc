use crate::keypair::{random_secret_key, PublicKey, SecretKey, SECP};
use secp256k1zkp::pedersen;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct Round1 {
    pub T_1: PublicKey,
    pub T_2: PublicKey,
}

impl Round1 {
    /// To generate T_1 and T_2 for each party we hash their x_fund
    pub fn new(x: &SecretKey) -> Self {
        let mut T_1 = PublicKey::new();
        let mut T_2 = PublicKey::new();

        // They're not used in Round 1 ¯\_(ツ)_/¯
        let value = 0; // I think it's not used
        let common_nonce = random_secret_key();
        let commit = SECP.commit_value(0).unwrap();

        let mut hasher = Sha256::new();

        hasher.input(x);
        let private_nonce = SecretKey::from_slice(&*SECP, &hasher.result()).unwrap();

        SECP.bullet_proof_multisig(
            value,
            x.clone(),
            common_nonce,
            None,
            None,
            None,
            Some(&mut T_1),
            Some(&mut T_2),
            vec![commit], // What about an empty vector?
            Some(&private_nonce),
            1,
        )
        .unwrap();

        Round1 { T_1, T_2 }
    }
}

}
