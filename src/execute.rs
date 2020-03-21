pub trait Execute {
    type Wallet;
    type Return;

    fn execute(self, wallet: &Self::Wallet) -> anyhow::Result<Self::Return>;
}
