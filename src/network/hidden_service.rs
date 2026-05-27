use arti_client::TorClient;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_rtcompat::PreferredRuntime;
use anyhow::Result;

pub async fn launch_hidden_service(
    tor_client: &TorClient<PreferredRuntime>, 
    nickname_str: &str
) -> Result<(std::sync::Arc<tor_hsservice::RunningOnionService>, impl futures::Stream<Item = tor_hsservice::RendRequest>)> {
    
    let config = OnionServiceConfigBuilder::default()
        .nickname(nickname_str.to_owned().try_into()?)
        .build()?;
        
    // Extract the Result with `?`, then handle the Option
    let (service, rend_requests) = tor_client.launch_onion_service(config)?
        .ok_or_else(|| anyhow::anyhow!("Onion service already running or stream initialization failed"))?;
    
    Ok((service, rend_requests))
}
