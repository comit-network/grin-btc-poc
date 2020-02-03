use crate::{bitcoin, grin};
use blake2::{Blake2b, Digest};

pub struct Commitment([u8; 64]);

pub struct Opening {
    PKs_grin: grin::PKs,
    PKs_bitcoin: bitcoin::PKs,
}

impl Commitment {
    pub fn commit(PKs_grin: &grin::PKs, PKs_bitcoin: &bitcoin::PKs) -> Commitment {
        let mut hasher = Blake2b::new();

        hasher.input(PKs_grin.X.0);
        hasher.input(PKs_grin.R_fund.0);
        hasher.input(PKs_grin.R_redeem.0);
        hasher.input(PKs_grin.R_refund.0);
        hasher.input(PKs_bitcoin.X.0);

        let mut commitment = [0u8; 64];
        commitment.copy_from_slice(&hasher.result());

        Commitment(commitment)
    }
}

impl Opening {
    pub fn new(PKs_grin: grin::PKs, PKs_bitcoin: bitcoin::PKs) -> Self {
        Opening {
            PKs_grin,
            PKs_bitcoin,
        }
    }

    pub fn open(self, commitment: Commitment) -> Result<(grin::PKs, bitcoin::PKs), ()> {
        let self_commitment = Commitment::commit(&self.PKs_grin, &self.PKs_bitcoin);

        if &commitment.0[..] == &self_commitment.0[..] {
            Ok((self.PKs_grin, self.PKs_bitcoin))
        } else {
            Err(())
        }
    }
}