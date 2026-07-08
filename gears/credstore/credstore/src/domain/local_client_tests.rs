// Created: 2026-04-07 by Constructor Tech
use std::sync::Arc;

use credstore_sdk::{
    CredStorePluginClientV1, CredStorePluginSpecV1, OwnerId, SecretMetadata, SecretValue,
    SharingMode, TenantId,
};
use toolkit::client_hub::{ClientHub, ClientScope};
use types_registry_sdk::TypesRegistryClient;
use types_registry_sdk::testing::{MockTypesRegistryClient, make_test_instance};

use super::*;
use crate::domain::Service;
use crate::domain::test_support::{MockPlugin, test_ctx};

fn make_client() -> CredStoreLocalClient {
    let hub = Arc::new(ClientHub::default());
    let svc = Arc::new(Service::new(hub, "constructorfabric".into()));
    CredStoreLocalClient::new(svc)
}

fn make_wired_client(plugin: Arc<dyn CredStorePluginClientV1>) -> CredStoreLocalClient {
    let instance_id = format!(
        "{}test.credstore.mock.local_client.v1",
        CredStorePluginSpecV1::gts_type_id()
    );
    let hub = Arc::new(ClientHub::default());

    let instance = make_test_instance(
        &instance_id,
        serde_json::json!({
            "id": instance_id,
            "vendor": "constructorfabric",
            "priority": 0,
            "properties": {}
        }),
    );
    let reg: Arc<dyn TypesRegistryClient> =
        Arc::new(MockTypesRegistryClient::new().with_instances([instance]));
    hub.register::<dyn TypesRegistryClient>(reg);
    hub.register_scoped::<dyn CredStorePluginClientV1>(ClientScope::gts_id(&instance_id), plugin);

    let svc = Arc::new(Service::new(hub, "constructorfabric".into()));
    CredStoreLocalClient::new(svc)
}

// ── CredStoreClientV1::get — error path ──────────────────────────────────

#[tokio::test]
async fn get_trait_impl_propagates_service_error() {
    let client = make_client();
    let key = SecretRef::new("test-key").unwrap();
    // Hub is empty → TypesRegistryUnavailable → CredStoreError::Internal
    let result = client.get(&test_ctx(), &key).await;
    assert!(matches!(result.unwrap_err(), CredStoreError::Internal(_)));
}

#[tokio::test]
async fn get_trait_impl_converts_not_found_from_plugin() {
    let client = make_wired_client(MockPlugin::errors_not_found());
    let key = SecretRef::new("missing-key").unwrap();
    let result = client.get(&test_ctx(), &key).await;
    assert!(
        matches!(result.unwrap_err(), CredStoreError::NotFound),
        "DomainError::NotFound must map to CredStoreError::NotFound"
    );
}

// ── CredStoreClientV1::get — happy paths ─────────────────────────────────

#[tokio::test]
async fn get_trait_impl_returns_some_on_success() {
    let meta = SecretMetadata {
        value: SecretValue::from("val"),
        owner_id: OwnerId::nil(),
        sharing: SharingMode::Tenant,
        owner_tenant_id: TenantId::nil(),
    };
    let client = make_wired_client(MockPlugin::returns(Some(&meta)));
    let key = SecretRef::new("key").unwrap();
    let resp = client.get(&test_ctx(), &key).await.unwrap();
    let resp = resp.expect("expected Some");
    assert_eq!(resp.value.as_bytes(), b"val");
    assert!(!resp.is_inherited);
}

#[tokio::test]
async fn get_trait_impl_returns_none_when_plugin_returns_none() {
    let client = make_wired_client(MockPlugin::returns(None));
    let key = SecretRef::new("missing").unwrap();
    let resp = client.get(&test_ctx(), &key).await.unwrap();
    assert!(resp.is_none());
}

// ── CredStoreClientV1::put / delete ──────────────────────────────────────

#[tokio::test]
async fn put_trait_impl_delegates_to_plugin() {
    let client = make_wired_client(MockPlugin::returns(None));
    let key = SecretRef::new("tok").unwrap();
    let result = client
        .put(&test_ctx(), &key, SecretValue::from("v"), SharingMode::Private)
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn delete_trait_impl_delegates_to_plugin() {
    let client = make_wired_client(MockPlugin::returns(None));
    let key = SecretRef::new("tok").unwrap();
    assert!(client.delete(&test_ctx(), &key).await.is_ok());
}

#[tokio::test]
async fn put_trait_impl_maps_plugin_write_error() {
    let client = make_wired_client(MockPlugin::write_errors_internal("boom"));
    let key = SecretRef::new("tok").unwrap();
    let err = client
        .put(&test_ctx(), &key, SecretValue::from("v"), SharingMode::Private)
        .await
        .unwrap_err();
    assert!(matches!(err, CredStoreError::Internal(_)));
}

#[tokio::test]
async fn put_trait_impl_propagates_service_error_when_unwired() {
    let client = make_client();
    let key = SecretRef::new("tok").unwrap();
    // Empty hub → TypesRegistryUnavailable → CredStoreError::Internal
    let err = client
        .put(&test_ctx(), &key, SecretValue::from("v"), SharingMode::Private)
        .await
        .unwrap_err();
    assert!(matches!(err, CredStoreError::Internal(_)));
}
