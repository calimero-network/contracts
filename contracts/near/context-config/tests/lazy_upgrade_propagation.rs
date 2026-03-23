#![allow(unused_crate_dependencies)]

//! Contract-level tests for the lazy upgrade propagation fixes.
//!
//! These tests verify that:
//! - Fix A: `migration_method` is stored on-chain by `set_group_target` and
//!   returned by the `group()` query, enabling peer nodes to recover it during
//!   group sync.
//! - Fix C is a node-side change (not testable at contract level).
//! - Fix B is a node-side change (P2P blob sharing, not testable at contract level).

use calimero_context_config::repr::{Repr, ReprTransmute};
use calimero_context_config::types::{
    AppKey, Application, ContextGroupId, ContextId, ContextIdentity, Signed, SignerId,
};
use calimero_context_config::{
    ContextRequest, ContextRequestKind, GroupRequest, GroupRequestKind, Request, RequestKind,
};
use ed25519_dalek::{Signer, SigningKey};
use near_workspaces::types::NearToken;
use near_workspaces::{network::Sandbox, Contract, Worker};
use rand::Rng;
use serde_json::json;
use tokio::fs;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

async fn setup() -> eyre::Result<(Worker<Sandbox>, Contract)> {
    let worker = near_workspaces::sandbox().await?;
    let wasm = fs::read("res/calimero_context_config_near.wasm").await?;
    let contract = worker.dev_deploy(&wasm).await?;

    let context_proxy_blob =
        fs::read("../context-proxy/res/calimero_context_proxy_near.wasm").await?;

    let _ignored = contract
        .call("set_proxy_code")
        .args(context_proxy_blob)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    Ok((worker, contract))
}

fn make_group_request<'a>(
    signer_sk: &'a SigningKey,
    group_id: Repr<ContextGroupId>,
    kind: GroupRequestKind<'a>,
    nonce: u64,
) -> eyre::Result<Signed<Request<'a>>> {
    let signer_id: SignerId = signer_sk.verifying_key().to_bytes().rt()?;

    Ok(Signed::new(
        &{
            let kind = RequestKind::Group(GroupRequest::new(group_id, kind));
            Request::new(signer_id, kind, nonce)
        },
        |p| signer_sk.sign(p),
    )?)
}

fn make_context_request<'a>(
    signer_sk: &'a SigningKey,
    context_id: Repr<ContextId>,
    kind: ContextRequestKind<'a>,
    nonce: u64,
) -> eyre::Result<Signed<Request<'a>>> {
    let signer_id: SignerId = signer_sk.verifying_key().to_bytes().rt()?;

    Ok(Signed::new(
        &{
            let kind = RequestKind::Context(ContextRequest::new(context_id, kind));
            Request::new(signer_id, kind, nonce)
        },
        |p| signer_sk.sign(p),
    )?)
}

struct TestContext {
    context_id: Repr<ContextId>,
    _context_sk: SigningKey,
    _author_id: Repr<ContextIdentity>,
    _author_sk: SigningKey,
}

async fn create_test_context(
    node: &near_workspaces::Account,
    contract: &Contract,
    rng: &mut impl Rng,
) -> eyre::Result<TestContext> {
    let context_sk = SigningKey::from_bytes(&rng.gen());
    let context_id: Repr<ContextId> = context_sk.verifying_key().to_bytes().rt()?;

    let author_sk = SigningKey::from_bytes(&rng.gen());
    let author_id: Repr<ContextIdentity> = author_sk.verifying_key().to_bytes().rt()?;

    let application_id = rng.gen::<[_; 32]>().rt()?;
    let blob_id = rng.gen::<[_; 32]>().rt()?;

    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_context_request(
            &context_sk,
            context_id,
            ContextRequestKind::Add {
                author_id,
                application: Application::new(
                    application_id,
                    blob_id,
                    0,
                    Default::default(),
                    Default::default(),
                ),
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    Ok(TestContext {
        context_id,
        _context_sk: context_sk,
        _author_id: author_id,
        _author_sk: author_sk,
    })
}

/// Simple nonce tracker. Dispenses the current nonce and auto-increments.
struct Nonce(u64);

impl Nonce {
    fn new(start: u64) -> Self {
        Self(start)
    }
    fn next(&mut self) -> u64 {
        let n = self.0;
        self.0 += 1;
        n
    }
}

/// Creates a group. Returns (admin_sk, group_id, nonce_tracker).
///
/// The contract's `Create` request skips the nonce check (group doesn't exist
/// yet), so the admin nonce starts at 0 after creation.
async fn create_group(
    node: &near_workspaces::Account,
    contract: &Contract,
    rng: &mut impl Rng,
) -> eyre::Result<(SigningKey, Repr<ContextGroupId>, Nonce)> {
    let admin_sk = SigningKey::from_bytes(&rng.gen());
    let group_id: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let app_key: Repr<AppKey> = rng.gen::<[_; 32]>().rt()?;
    let application_id = rng.gen::<[_; 32]>().rt()?;
    let blob_id = rng.gen::<[_; 32]>().rt()?;

    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::Create {
                app_key,
                target_application: Application::new(
                    application_id,
                    blob_id,
                    0,
                    Default::default(),
                    Default::default(),
                ),
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Create skips nonce check; admin nonce in contract starts at 0.
    Ok((admin_sk, group_id, Nonce::new(0)))
}

// ---------------------------------------------------------------------------
// Fix A tests: migration_method stored & returned on-chain
// ---------------------------------------------------------------------------

/// A newly created group has `migration_method: null` in the query response.
#[tokio::test]
async fn test_new_group_has_null_migration_method() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root = worker.root_account()?;
    let node = root
        .create_subaccount("n1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let (_admin_sk, group_id, _nonce) = create_group(&node, &contract, &mut rng).await?;

    let info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;

    assert!(
        info["migration_method"].is_null(),
        "new group should have null migration_method, got: {:?}",
        info["migration_method"]
    );

    Ok(())
}

/// `set_group_target` with a migration method stores it on-chain, and the
/// `group()` query returns it. This is the core of Fix A — peer nodes can
/// now recover the migration method during `sync_group_state_from_contract`.
#[tokio::test]
async fn test_set_group_target_stores_migration_method() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root = worker.root_account()?;
    let node = root
        .create_subaccount("n1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let (admin_sk, group_id, mut nonce) = create_group(&node, &contract, &mut rng).await?;

    let new_app_id = rng.gen::<[_; 32]>().rt()?;
    let new_blob_id = rng.gen::<[_; 32]>().rt()?;

    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::SetTargetApplication {
                migration_method: Some("migrate_v1_to_v2".to_owned()),
                target_application: Application::new(
                    new_app_id,
                    new_blob_id,
                    2048,
                    Default::default(),
                    Default::default(),
                ),
            },
            nonce.next(),
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;

    assert_eq!(
        info["migration_method"], "migrate_v1_to_v2",
        "group query should return the stored migration_method"
    );
    assert_eq!(
        info["target_application"]["id"],
        serde_json::to_value(new_app_id)?,
        "target application should be updated"
    );
    assert_eq!(
        info["target_application"]["size"], 2048,
        "target application size should be updated"
    );

    Ok(())
}

/// `set_group_target` with `migration_method: None` clears any previously
/// stored migration method.
#[tokio::test]
async fn test_set_group_target_clears_migration_method() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root = worker.root_account()?;
    let node = root
        .create_subaccount("n1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let (admin_sk, group_id, mut nonce) = create_group(&node, &contract, &mut rng).await?;

    // Step 1: Set with migration method.
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::SetTargetApplication {
                migration_method: Some("migrate_v1_to_v2".to_owned()),
                target_application: Application::new(
                    rng.gen::<[_; 32]>().rt()?,
                    rng.gen::<[_; 32]>().rt()?,
                    0,
                    Default::default(),
                    Default::default(),
                ),
            },
            nonce.next(),
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;
    assert_eq!(info["migration_method"], "migrate_v1_to_v2");

    // Step 2: Set again WITHOUT migration method — should clear it.
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::SetTargetApplication {
                migration_method: None,
                target_application: Application::new(
                    rng.gen::<[_; 32]>().rt()?,
                    rng.gen::<[_; 32]>().rt()?,
                    0,
                    Default::default(),
                    Default::default(),
                ),
            },
            nonce.next(),
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;
    assert!(
        info["migration_method"].is_null(),
        "migration_method should be cleared after set_group_target with None, got: {:?}",
        info["migration_method"]
    );

    Ok(())
}

/// Full lifecycle: create group → register context → add member →
/// set_group_target with migration → verify the complete group info response
/// contains all expected fields for a peer node to perform a lazy upgrade.
///
/// This simulates what a peer node's `sync_group_state_from_contract` would
/// see after the admin triggers an upgrade.
#[tokio::test]
async fn test_peer_sync_sees_migration_method_and_target_app() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root = worker.root_account()?;
    let admin_node = root
        .create_subaccount("admin")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let (admin_sk, group_id, mut nonce) = create_group(&admin_node, &contract, &mut rng).await?;

    let ctx = create_test_context(&admin_node, &contract, &mut rng).await?;

    // Register context in group.
    let _res = admin_node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::RegisterContext {
                context_id: ctx.context_id,
            },
            nonce.next(),
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Add a member (simulates Node B).
    let member_sk = SigningKey::from_bytes(&rng.gen());
    let member_id: Repr<SignerId> = member_sk.verifying_key().to_bytes().rt()?;

    let _res = admin_node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::AddMembers {
                members: vec![member_id].into(),
            },
            nonce.next(),
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // --- Trigger upgrade: set new target with migration method ---
    let new_app_id = rng.gen::<[_; 32]>().rt()?;
    let new_blob_id = rng.gen::<[_; 32]>().rt()?;

    let _res = admin_node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::SetTargetApplication {
                migration_method: Some("migrate_v1_to_v2".to_owned()),
                target_application: Application::new(
                    new_app_id,
                    new_blob_id,
                    4096,
                    Default::default(),
                    Default::default(),
                ),
            },
            nonce.next(),
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // --- Simulate peer sync: query group info ---
    let info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;

    assert_eq!(
        info["migration_method"], "migrate_v1_to_v2",
        "peer should see migration_method from on-chain state"
    );
    assert_eq!(
        info["target_application"]["id"],
        serde_json::to_value(new_app_id)?,
        "peer should see the new target application id"
    );
    assert_eq!(
        info["target_application"]["blob"],
        serde_json::to_value(new_blob_id)?,
        "peer should see the new target application blob id"
    );
    assert_eq!(
        info["target_application"]["size"], 4096,
        "peer should see the target application size"
    );
    assert_eq!(
        info["member_count"], 2,
        "group should have 2 members (admin + added member)"
    );
    assert_eq!(
        info["context_count"], 1,
        "group should have 1 registered context"
    );

    // Verify context is queryable via group_contexts.
    let contexts: Vec<serde_json::Value> = contract
        .view("group_contexts")
        .args_json(json!({ "group_id": group_id, "offset": 0, "length": 10 }))
        .await?
        .json()?;
    assert_eq!(
        contexts.len(),
        1,
        "group should have 1 context for peer to sync"
    );

    Ok(())
}

/// Member joins a context via group, then admin upgrades the group target.
/// Verify the contract state is correct for a peer-side lazy upgrade to work.
#[tokio::test]
async fn test_join_via_group_then_upgrade_preserves_membership() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root = worker.root_account()?;
    let node = root
        .create_subaccount("n1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let (admin_sk, group_id, mut nonce) = create_group(&node, &contract, &mut rng).await?;

    // Create and register a context.
    let ctx = create_test_context(&node, &contract, &mut rng).await?;

    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::RegisterContext {
                context_id: ctx.context_id,
            },
            nonce.next(),
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Add a member.
    let member_sk = SigningKey::from_bytes(&rng.gen());
    let member_id: Repr<SignerId> = member_sk.verifying_key().to_bytes().rt()?;

    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::AddMembers {
                members: vec![member_id].into(),
            },
            nonce.next(),
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Member joins context via group.
    let new_member_context_sk = SigningKey::from_bytes(&rng.gen());
    let new_member_context_id: Repr<ContextIdentity> =
        new_member_context_sk.verifying_key().to_bytes().rt()?;

    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &member_sk,
            group_id,
            GroupRequestKind::JoinContextViaGroup {
                context_id: ctx.context_id,
                new_member: new_member_context_id,
            },
            0, // JoinContextViaGroup skips nonce
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Verify member is in the context.
    let has_member: bool = contract
        .view("has_member")
        .args_json(json!({
            "context_id": ctx.context_id,
            "identity": new_member_context_id,
        }))
        .await?
        .json()?;
    assert!(
        has_member,
        "member should be in context after join_via_group"
    );

    // Admin upgrades group target with migration.
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::SetTargetApplication {
                migration_method: Some("migrate_v1_to_v2".to_owned()),
                target_application: Application::new(
                    rng.gen::<[_; 32]>().rt()?,
                    rng.gen::<[_; 32]>().rt()?,
                    0,
                    Default::default(),
                    Default::default(),
                ),
            },
            nonce.next(),
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Member is still in the context (upgrade didn't break membership).
    let has_member: bool = contract
        .view("has_member")
        .args_json(json!({
            "context_id": ctx.context_id,
            "identity": new_member_context_id,
        }))
        .await?
        .json()?;
    assert!(
        has_member,
        "member should still be in context after group target upgrade"
    );

    // migration_method is set.
    let info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;
    assert_eq!(info["migration_method"], "migrate_v1_to_v2");

    Ok(())
}

/// Multiple sequential upgrades: each `set_group_target` call replaces the
/// previous migration_method. Peer nodes always see the latest.
#[tokio::test]
async fn test_sequential_upgrades_replace_migration_method() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root = worker.root_account()?;
    let node = root
        .create_subaccount("n1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let (admin_sk, group_id, mut nonce) = create_group(&node, &contract, &mut rng).await?;

    // Upgrade 1: with migrate_v1_to_v2.
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::SetTargetApplication {
                migration_method: Some("migrate_v1_to_v2".to_owned()),
                target_application: Application::new(
                    rng.gen::<[_; 32]>().rt()?,
                    rng.gen::<[_; 32]>().rt()?,
                    0,
                    Default::default(),
                    Default::default(),
                ),
            },
            nonce.next(),
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;
    assert_eq!(info["migration_method"], "migrate_v1_to_v2");

    // Upgrade 2: with migrate_v2_to_v3.
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::SetTargetApplication {
                migration_method: Some("migrate_v2_to_v3".to_owned()),
                target_application: Application::new(
                    rng.gen::<[_; 32]>().rt()?,
                    rng.gen::<[_; 32]>().rt()?,
                    0,
                    Default::default(),
                    Default::default(),
                ),
            },
            nonce.next(),
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;
    assert_eq!(
        info["migration_method"], "migrate_v2_to_v3",
        "should see latest migration_method, not the previous one"
    );

    // Upgrade 3: without migration.
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::SetTargetApplication {
                migration_method: None,
                target_application: Application::new(
                    rng.gen::<[_; 32]>().rt()?,
                    rng.gen::<[_; 32]>().rt()?,
                    0,
                    Default::default(),
                    Default::default(),
                ),
            },
            nonce.next(),
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;
    assert!(
        info["migration_method"].is_null(),
        "migration_method should be cleared after upgrade without migration"
    );

    Ok(())
}
