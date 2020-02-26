use crate::{
    grin::{compute_excess_pk, compute_offset, PKs},
    keypair::build_commitment,
    setup_parameters,
};
use secp256k1zkp::pedersen::Commitment;

pub struct Redeem {
    pub excess: Commitment,
}

impl Redeem {
    pub fn new(
        init: &setup_parameters::Grin,
        redeemer_PKs: &PKs,
        funder_PKs: &PKs,
    ) -> anyhow::Result<Self> {
        let offset = compute_offset(&funder_PKs.R_redeem, &redeemer_PKs.R_redeem)?;

        let excess_pk = compute_excess_pk(
            vec![&redeemer_PKs.X, &funder_PKs.X],
            vec![&init.redeem_output_key],
            Some(&offset),
        )?;

        Ok(Self {
            excess: build_commitment(&excess_pk),
        })
    }
}
