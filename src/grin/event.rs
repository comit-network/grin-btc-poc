use crate::grin::{
    compute_excess_pk, compute_offset, public_key_to_pedersen_commitment, PKs, SpecialOutputs,
};
use secp256k1zkp::pedersen::Commitment;

pub struct Redeem {
    pub excess: Commitment,
}

impl Redeem {
    pub fn new(
        special_outputs: &SpecialOutputs,
        redeemer_PKs: &PKs,
        funder_PKs: &PKs,
    ) -> anyhow::Result<Self> {
        let offset = compute_offset(&funder_PKs.R_redeem, &redeemer_PKs.R_redeem)?;

        let excess_pk = compute_excess_pk(
            vec![&redeemer_PKs.X, &funder_PKs.X],
            vec![&special_outputs.redeem_output_key],
            Some(&offset),
        )?;

        Ok(Self {
            excess: public_key_to_pedersen_commitment(&excess_pk),
        })
    }
}
