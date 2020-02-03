use rand::Rng;

pub mod keypair;

pub use keypair::{KeyPair, PublicKey, SecretKey};

#[derive(Debug, Clone)]
pub struct SKs {
    pub x: KeyPair,
    pub r_fund: KeyPair,
    pub r_redeem: KeyPair,
    pub r_refund: KeyPair,
}

impl SKs {
    pub fn keygen() -> SKs {
        let x = KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>());

        let r_fund = KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>());
        let r_redeem = KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>());
        let r_refund = KeyPair::from_slice(&rand::thread_rng().gen::<[u8; 32]>());

        SKs {
            x,
            r_fund,
            r_redeem,
            r_refund,
        }
    }

    pub fn public(&self) -> PKs {
        PKs {
            X: self.x.public_key.clone(),
            R_fund: self.r_fund.public_key.clone(),
            R_redeem: self.r_redeem.public_key.clone(),
            R_refund: self.r_refund.public_key.clone(),
        }
    }
}

pub struct PKs {
    pub X: PublicKey,
    pub R_fund: PublicKey,
    pub R_redeem: PublicKey,
    pub R_refund: PublicKey,
}
