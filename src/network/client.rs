use arti_client::TorClient;
use tor_rtcompat::PreferredRuntime;

pub struct P2PClient {
    pub tor_client: TorClient<PreferredRuntime>,
}
