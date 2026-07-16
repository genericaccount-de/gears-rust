//! `CredStore` gear.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use credstore_sdk::CredStoreClientV1;
use toolkit::contracts::SystemCapability;
use toolkit::{Gear, GearCtx};
use tracing::info;

use crate::config::CredStoreConfig;
use crate::domain::{CredStoreLocalClient, Service};

/// `CredStore` gateway gear.
///
/// This gear:
/// 1. Discovers plugin instances via types-registry (lazy, first-use)
/// 2. Routes secret operations through the selected plugin
/// 3. Registers `Arc<dyn CredStoreClientV1>` in `ClientHub` for consumers
///
/// The `CredStorePluginSpecV1` schema itself reaches `types-registry`
/// automatically via the `toolkit-gts` link-time inventory — no per-init
/// registration is needed.
#[toolkit::gear(
    name = "credstore",
    deps = [types_registry],
    capabilities = [system]
)]
pub struct CredStoreGear {
    service: OnceLock<Arc<Service>>,
}

impl Default for CredStoreGear {
    fn default() -> Self {
        Self {
            service: OnceLock::new(),
        }
    }
}

#[async_trait]
impl Gear for CredStoreGear {
    #[tracing::instrument(skip_all, fields(vendor))]
    async fn init(&self, ctx: &GearCtx) -> anyhow::Result<()> {
        let cfg: CredStoreConfig = ctx.config_or_default()?;
        tracing::Span::current().record("vendor", cfg.vendor.as_str());
        info!(vendor = %cfg.vendor);

        // Create domain service
        let hub = ctx.client_hub();
        let svc = Arc::new(Service::new(hub, cfg.vendor));
        self.service
            .set(svc.clone())
            .map_err(|_| anyhow::anyhow!("{} gear already initialized", Self::MODULE_NAME))?;

        // Register local client in ClientHub
        let api: Arc<dyn CredStoreClientV1> = Arc::new(CredStoreLocalClient::new(svc));
        ctx.client_hub().register::<dyn CredStoreClientV1>(api);

        Ok(())
    }
}

#[async_trait]
impl SystemCapability for CredStoreGear {}
