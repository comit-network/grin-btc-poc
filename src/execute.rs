pub trait Execute {
    type Wallet;

    fn execute(self, wallet: &Self::Wallet) -> anyhow::Result<()>;
}
