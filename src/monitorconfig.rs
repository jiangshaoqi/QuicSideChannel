use anyhow::Result;
use config::Config;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct MonitorConfig {
    pub interface: &'static str,
    pub pcap_filter_expression: &'static str,
}

impl MonitorConfig {
    pub fn from_file(path: &str) -> Result<Self> {
        let cfg = Config::builder()
            .add_source(config::File::with_name(path))
            .build()?;
        cfg.try_deserialize().map_err(|e| {
            anyhow::anyhow!("Failed to deserialize MonitorConfig from file {}: {}", path, e)
        })
    }
}

