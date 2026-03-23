#![allow(unused_crate_dependencies)]

use calimero_context_config::repr::{Repr, ReprTransmute};
use calimero_context_config::types::{
    AppKey, Application, ContextGroupId, ContextId, ContextIdentity, Signed, SignerId,
};
use calimero_context_config::{
    ContextRequest, ContextRequestKind, GroupRequest, GroupRequestKind, MemberCapabilities,
    Request, RequestKind, VisibilityMode,
};
use ed25519_dalek::{Signer, SigningKey};
use near_workspaces::types::NearToken;
use near_workspaces::{network::Sandbox, Contract, Worker};
use rand::Rng;
use serde_json::json;
use tokio::fs;

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

#[tokio::test]
async fn test_create_and_query_group() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root_account = worker.root_account()?;
    let node1 = root_account
        .create_subaccount("node1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let admin_sk = SigningKey::from_bytes(&rng.gen());
    let admin_signer_id: Repr<SignerId> = admin_sk.verifying_key().to_bytes().rt()?;
    let group_id: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let app_key: Repr<AppKey> = rng.gen::<[_; 32]>().rt()?;
    let application_id = rng.gen::<[_; 32]>().rt()?;
    let blob_id = rng.gen::<[_; 32]>().rt()?;

    let res = node1
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

    let expected_log = format!("Group `{}` created", group_id);
    assert!(
        res.logs().iter().any(|log| log == &expected_log),
        "Expected log: {}, got: {:?}",
        expected_log,
        res.logs()
    );

    let group_info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;

    assert_eq!(group_info["member_count"], 1);
    assert_eq!(group_info["context_count"], 0);

    let is_admin: bool = contract
        .view("is_group_admin")
        .args_json(json!({
            "group_id": group_id,
            "identity": admin_signer_id,
        }))
        .await?
        .json()?;

    assert!(is_admin, "creator should be a group admin");

    let non_admin_sk = SigningKey::from_bytes(&rng.gen());
    let non_admin_id: Repr<SignerId> = non_admin_sk.verifying_key().to_bytes().rt()?;

    let is_admin: bool = contract
        .view("is_group_admin")
        .args_json(json!({
            "group_id": group_id,
            "identity": non_admin_id,
        }))
        .await?
        .json()?;

    assert!(!is_admin, "random identity should not be a group admin");

    Ok(())
}

#[tokio::test]
async fn test_create_duplicate_group_fails() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root_account = worker.root_account()?;
    let node1 = root_account
        .create_subaccount("node1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let admin_sk = SigningKey::from_bytes(&rng.gen());
    let group_id: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let app_key: Repr<AppKey> = rng.gen::<[_; 32]>().rt()?;
    let application_id = rng.gen::<[_; 32]>().rt()?;
    let blob_id = rng.gen::<[_; 32]>().rt()?;

    let create_kind = GroupRequestKind::Create {
        app_key,
        target_application: Application::new(
            application_id,
            blob_id,
            0,
            Default::default(),
            Default::default(),
        ),
    };

    let _res = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(&admin_sk, group_id, create_kind, 0)?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let create_kind2 = GroupRequestKind::Create {
        app_key,
        target_application: Application::new(
            application_id,
            blob_id,
            0,
            Default::default(),
            Default::default(),
        ),
    };

    let err = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(&admin_sk, group_id, create_kind2, 0)?)
        .max_gas()
        .transact()
        .await?
        .raw_bytes()
        .expect_err("duplicate group creation should fail");

    let err_str = err.to_string();
    assert!(
        err_str.contains("group already exists"),
        "Expected 'group already exists', got: {}",
        err_str
    );

    Ok(())
}

#[tokio::test]
async fn test_add_remove_group_members() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root_account = worker.root_account()?;
    let node1 = root_account
        .create_subaccount("node1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let admin_sk = SigningKey::from_bytes(&rng.gen());
    let group_id: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let app_key: Repr<AppKey> = rng.gen::<[_; 32]>().rt()?;
    let application_id = rng.gen::<[_; 32]>().rt()?;
    let blob_id = rng.gen::<[_; 32]>().rt()?;

    let _res = node1
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

    let member1: Repr<SignerId> = rng.gen::<[_; 32]>().rt()?;
    let member2: Repr<SignerId> = rng.gen::<[_; 32]>().rt()?;

    let res = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::AddMembers {
                members: vec![member1, member2].into(),
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    assert_eq!(
        res.logs().len(),
        2,
        "Expected 2 log entries for adding 2 members"
    );

    let group_info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;

    assert_eq!(
        group_info["member_count"], 3,
        "member_count should be 3 (1 creator + 2 added)"
    );

    let res = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::RemoveMembers {
                members: vec![member1].into(),
            },
            1,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    assert_eq!(
        res.logs().len(),
        1,
        "Expected 1 log entry for removing 1 member"
    );

    let group_info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;

    assert_eq!(
        group_info["member_count"], 2,
        "member_count should be 2 after removing 1"
    );

    Ok(())
}

#[tokio::test]
async fn test_add_member_idempotent() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root_account = worker.root_account()?;
    let node1 = root_account
        .create_subaccount("node1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let admin_sk = SigningKey::from_bytes(&rng.gen());
    let group_id: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let app_key: Repr<AppKey> = rng.gen::<[_; 32]>().rt()?;
    let application_id = rng.gen::<[_; 32]>().rt()?;
    let blob_id = rng.gen::<[_; 32]>().rt()?;

    let _res = node1
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

    let member1: Repr<SignerId> = rng.gen::<[_; 32]>().rt()?;

    // Add member1 the first time.
    let _res = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::AddMembers {
                members: vec![member1].into(),
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let group_info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;
    assert_eq!(
        group_info["member_count"], 2,
        "member_count should be 2 after first add"
    );

    // Adding member1 again must be a no-op — count must not change.
    let res = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::AddMembers {
                members: vec![member1].into(),
            },
            1,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    assert_eq!(
        res.logs().len(),
        0,
        "duplicate add should produce no log entries"
    );

    let group_info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;
    assert_eq!(
        group_info["member_count"], 2,
        "member_count must remain 2 after duplicate add"
    );

    Ok(())
}

#[tokio::test]
async fn test_remove_nonexistent_member_rejected() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root_account = worker.root_account()?;
    let node1 = root_account
        .create_subaccount("node1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let admin_sk = SigningKey::from_bytes(&rng.gen());
    let group_id: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let app_key: Repr<AppKey> = rng.gen::<[_; 32]>().rt()?;
    let application_id = rng.gen::<[_; 32]>().rt()?;
    let blob_id = rng.gen::<[_; 32]>().rt()?;

    let _res = node1
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

    let never_added: Repr<SignerId> = rng.gen::<[_; 32]>().rt()?;

    let err = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::RemoveMembers {
                members: vec![never_added].into(),
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .raw_bytes()
        .expect_err("removing a non-member should fail");

    let err_str = err.to_string();
    assert!(
        err_str.contains("member not in group"),
        "Expected 'member not in group', got: {}",
        err_str
    );

    Ok(())
}

#[tokio::test]
async fn test_non_admin_operations_rejected() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root_account = worker.root_account()?;
    let node1 = root_account
        .create_subaccount("node1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let admin_sk = SigningKey::from_bytes(&rng.gen());
    let non_admin_sk = SigningKey::from_bytes(&rng.gen());
    let group_id: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let app_key: Repr<AppKey> = rng.gen::<[_; 32]>().rt()?;
    let application_id = rng.gen::<[_; 32]>().rt()?;
    let blob_id = rng.gen::<[_; 32]>().rt()?;

    let _res = node1
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

    let member: Repr<SignerId> = rng.gen::<[_; 32]>().rt()?;

    let err = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &non_admin_sk,
            group_id,
            GroupRequestKind::AddMembers {
                members: vec![member].into(),
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .raw_bytes()
        .expect_err("non-admin add members should fail");

    let err_str = err.to_string();
    assert!(
        err_str.contains("only group admins can add members"),
        "Expected 'only group admins can add members', got: {}",
        err_str
    );

    let err = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &non_admin_sk,
            group_id,
            GroupRequestKind::RemoveMembers {
                members: vec![member].into(),
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .raw_bytes()
        .expect_err("non-admin remove members should fail");

    let err_str = err.to_string();
    assert!(
        err_str.contains("only group admins can remove members"),
        "Expected 'only group admins can remove members', got: {}",
        err_str
    );

    let err = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &non_admin_sk,
            group_id,
            GroupRequestKind::Delete,
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .raw_bytes()
        .expect_err("non-admin delete should fail");

    let err_str = err.to_string();
    assert!(
        err_str.contains("only group admins can delete a group"),
        "Expected 'only group admins can delete a group', got: {}",
        err_str
    );

    Ok(())
}

#[tokio::test]
async fn test_delete_group() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root_account = worker.root_account()?;
    let node1 = root_account
        .create_subaccount("node1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let admin_sk = SigningKey::from_bytes(&rng.gen());
    let group_id: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let app_key: Repr<AppKey> = rng.gen::<[_; 32]>().rt()?;
    let application_id = rng.gen::<[_; 32]>().rt()?;
    let blob_id = rng.gen::<[_; 32]>().rt()?;

    let _res = node1
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

    let group_info: Option<serde_json::Value> = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;

    assert!(group_info.is_some(), "group should exist before deletion");

    let res = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::Delete,
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let expected_log = format!("Group `{}` deleted", group_id);
    assert!(
        res.logs().iter().any(|log| log == &expected_log),
        "Expected log: {}, got: {:?}",
        expected_log,
        res.logs()
    );

    let group_info: Option<serde_json::Value> = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;

    assert!(
        group_info.is_none(),
        "group should not exist after deletion"
    );

    Ok(())
}

#[tokio::test]
async fn test_query_nonexistent_group() -> eyre::Result<()> {
    let (_worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let group_id: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;

    let group_info: Option<serde_json::Value> = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;

    assert!(group_info.is_none(), "nonexistent group should return None");

    let is_admin: bool = contract
        .view("is_group_admin")
        .args_json(json!({
            "group_id": group_id,
            "identity": group_id,
        }))
        .await?
        .json()?;

    assert!(
        !is_admin,
        "is_group_admin on nonexistent group should be false"
    );

    Ok(())
}

// --- Phase 3: Context-Group Integration Tests ---

#[tokio::test]
async fn test_register_context_in_group() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root_account = worker.root_account()?;
    let node1 = root_account
        .create_subaccount("node1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let admin_sk = SigningKey::from_bytes(&rng.gen());
    let group_id: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let app_key: Repr<AppKey> = rng.gen::<[_; 32]>().rt()?;
    let application_id = rng.gen::<[_; 32]>().rt()?;
    let blob_id = rng.gen::<[_; 32]>().rt()?;

    let _res = node1
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

    let ctx = create_test_context(&node1, &contract, &mut rng).await?;

    let res = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::RegisterContext {
                context_id: ctx.context_id,
                visibility_mode: None,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let expected_log = format!(
        "Context `{}` registered in group `{}`",
        ctx.context_id, group_id
    );
    assert!(
        res.logs().iter().any(|log| log == &expected_log),
        "Expected log: {}, got: {:?}",
        expected_log,
        res.logs()
    );

    let group_info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;
    assert_eq!(group_info["context_count"], 1);

    let ctx_group: Option<Repr<ContextGroupId>> = contract
        .view("context_group")
        .args_json(json!({ "context_id": ctx.context_id }))
        .await?
        .json()?;
    assert_eq!(
        ctx_group,
        Some(group_id),
        "reverse lookup should return group_id"
    );

    let contexts: Vec<Repr<ContextId>> = contract
        .view("group_contexts")
        .args_json(json!({ "group_id": group_id, "offset": 0, "length": 10 }))
        .await?
        .json()?;
    assert_eq!(contexts, vec![ctx.context_id]);

    Ok(())
}

#[tokio::test]
async fn test_double_register_rejected() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root_account = worker.root_account()?;
    let node1 = root_account
        .create_subaccount("node1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let admin_sk = SigningKey::from_bytes(&rng.gen());
    let group_id: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let app_key: Repr<AppKey> = rng.gen::<[_; 32]>().rt()?;
    let application_id = rng.gen::<[_; 32]>().rt()?;
    let blob_id = rng.gen::<[_; 32]>().rt()?;

    let _res = node1
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

    let ctx = create_test_context(&node1, &contract, &mut rng).await?;

    let _res = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::RegisterContext {
                context_id: ctx.context_id,
                visibility_mode: None,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let err = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::RegisterContext {
                context_id: ctx.context_id,
                visibility_mode: None,
            },
            1,
        )?)
        .max_gas()
        .transact()
        .await?
        .raw_bytes()
        .expect_err("double registration should fail");

    let err_str = err.to_string();
    assert!(
        err_str.contains("context already belongs to a group"),
        "Expected 'context already belongs to a group', got: {}",
        err_str
    );

    Ok(())
}

#[tokio::test]
async fn test_unregister_context_from_group() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root_account = worker.root_account()?;
    let node1 = root_account
        .create_subaccount("node1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let admin_sk = SigningKey::from_bytes(&rng.gen());
    let group_id: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let app_key: Repr<AppKey> = rng.gen::<[_; 32]>().rt()?;
    let application_id = rng.gen::<[_; 32]>().rt()?;
    let blob_id = rng.gen::<[_; 32]>().rt()?;

    let _res = node1
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

    let ctx = create_test_context(&node1, &contract, &mut rng).await?;

    let _res = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::RegisterContext {
                context_id: ctx.context_id,
                visibility_mode: None,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let res = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::UnregisterContext {
                context_id: ctx.context_id,
            },
            1,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let expected_log = format!(
        "Context `{}` unregistered from group `{}`",
        ctx.context_id, group_id
    );
    assert!(
        res.logs().iter().any(|log| log == &expected_log),
        "Expected log: {}, got: {:?}",
        expected_log,
        res.logs()
    );

    let group_info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;
    assert_eq!(
        group_info["context_count"], 0,
        "context_count should be 0 after unregistration"
    );

    let ctx_group: Option<Repr<ContextGroupId>> = contract
        .view("context_group")
        .args_json(json!({ "context_id": ctx.context_id }))
        .await?
        .json()?;
    assert!(
        ctx_group.is_none(),
        "reverse lookup should return None after unregistration"
    );

    let contexts: Vec<Repr<ContextId>> = contract
        .view("group_contexts")
        .args_json(json!({ "group_id": group_id, "offset": 0, "length": 10 }))
        .await?
        .json()?;
    assert!(
        contexts.is_empty(),
        "group_contexts should be empty after unregistration"
    );

    Ok(())
}

#[tokio::test]
async fn test_non_admin_register_rejected() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root_account = worker.root_account()?;
    let node1 = root_account
        .create_subaccount("node1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let admin_sk = SigningKey::from_bytes(&rng.gen());
    let non_admin_sk = SigningKey::from_bytes(&rng.gen());
    let group_id: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let app_key: Repr<AppKey> = rng.gen::<[_; 32]>().rt()?;
    let application_id = rng.gen::<[_; 32]>().rt()?;
    let blob_id = rng.gen::<[_; 32]>().rt()?;

    let _res = node1
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

    let ctx = create_test_context(&node1, &contract, &mut rng).await?;

    let err = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &non_admin_sk,
            group_id,
            GroupRequestKind::RegisterContext {
                context_id: ctx.context_id,
                visibility_mode: None,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .raw_bytes()
        .expect_err("non-admin register should fail");

    let err_str = err.to_string();
    assert!(
        err_str.contains("insufficient capabilities to create context"),
        "Expected 'insufficient capabilities to create context', got: {}",
        err_str
    );

    let err = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &non_admin_sk,
            group_id,
            GroupRequestKind::UnregisterContext {
                context_id: ctx.context_id,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .raw_bytes()
        .expect_err("non-admin unregister should fail");

    let err_str = err.to_string();
    assert!(
        err_str.contains("only group admins can unregister contexts"),
        "Expected 'only group admins can unregister contexts', got: {}",
        err_str
    );

    Ok(())
}

#[tokio::test]
async fn test_group_contexts_pagination() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root_account = worker.root_account()?;
    let node1 = root_account
        .create_subaccount("node1")
        .initial_balance(NearToken::from_near(50))
        .transact()
        .await?
        .into_result()?;

    let admin_sk = SigningKey::from_bytes(&rng.gen());
    let group_id: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let app_key: Repr<AppKey> = rng.gen::<[_; 32]>().rt()?;
    let application_id = rng.gen::<[_; 32]>().rt()?;
    let blob_id = rng.gen::<[_; 32]>().rt()?;

    let _res = node1
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

    let mut context_ids = Vec::new();
    let mut group_nonce = 0u64;
    for _ in 0..3 {
        let ctx = create_test_context(&node1, &contract, &mut rng).await?;

        let _res = node1
            .call(contract.id(), "mutate")
            .args_json(make_group_request(
                &admin_sk,
                group_id,
                GroupRequestKind::RegisterContext {
                    context_id: ctx.context_id,
                    visibility_mode: None,
                },
                group_nonce,
            )?)
            .max_gas()
            .transact()
            .await?
            .into_result()?;

        group_nonce += 1;
        context_ids.push(ctx.context_id);
    }

    let all_contexts: Vec<Repr<ContextId>> = contract
        .view("group_contexts")
        .args_json(json!({ "group_id": group_id, "offset": 0, "length": 10 }))
        .await?
        .json()?;
    assert_eq!(all_contexts.len(), 3, "should have 3 contexts in group");

    let page1: Vec<Repr<ContextId>> = contract
        .view("group_contexts")
        .args_json(json!({ "group_id": group_id, "offset": 0, "length": 2 }))
        .await?
        .json()?;
    assert_eq!(page1.len(), 2, "first page should have 2 contexts");

    let page2: Vec<Repr<ContextId>> = contract
        .view("group_contexts")
        .args_json(json!({ "group_id": group_id, "offset": 2, "length": 2 }))
        .await?
        .json()?;
    assert_eq!(page2.len(), 1, "second page should have 1 context");

    assert!(
        !page1.iter().any(|c| page2.contains(c)),
        "pages should not overlap"
    );

    let group_info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;
    assert_eq!(group_info["context_count"], 3);

    Ok(())
}

#[tokio::test]
async fn test_delete_group_with_contexts_rejected() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root_account = worker.root_account()?;
    let node1 = root_account
        .create_subaccount("node1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let admin_sk = SigningKey::from_bytes(&rng.gen());
    let group_id: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let app_key: Repr<AppKey> = rng.gen::<[_; 32]>().rt()?;
    let application_id = rng.gen::<[_; 32]>().rt()?;
    let blob_id = rng.gen::<[_; 32]>().rt()?;

    let _res = node1
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

    let ctx = create_test_context(&node1, &contract, &mut rng).await?;

    let _res = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::RegisterContext {
                context_id: ctx.context_id,
                visibility_mode: None,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let err = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::Delete,
            1,
        )?)
        .max_gas()
        .transact()
        .await?
        .raw_bytes()
        .expect_err("deleting group with contexts should fail");

    let err_str = err.to_string();
    assert!(
        err_str.contains("cannot delete group with registered contexts"),
        "Expected 'cannot delete group with registered contexts', got: {}",
        err_str
    );

    Ok(())
}

#[tokio::test]
async fn test_unregister_wrong_group_rejected() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root_account = worker.root_account()?;
    let node1 = root_account
        .create_subaccount("node1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let admin_sk = SigningKey::from_bytes(&rng.gen());
    let group_id1: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let group_id2: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let app_key: Repr<AppKey> = rng.gen::<[_; 32]>().rt()?;
    let application_id = rng.gen::<[_; 32]>().rt()?;
    let blob_id = rng.gen::<[_; 32]>().rt()?;

    for gid in [group_id1, group_id2] {
        let _res = node1
            .call(contract.id(), "mutate")
            .args_json(make_group_request(
                &admin_sk,
                gid,
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
    }

    let ctx = create_test_context(&node1, &contract, &mut rng).await?;

    let _res = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id1,
            GroupRequestKind::RegisterContext {
                context_id: ctx.context_id,
                visibility_mode: None,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let err = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id2,
            GroupRequestKind::UnregisterContext {
                context_id: ctx.context_id,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .raw_bytes()
        .expect_err("unregistering from wrong group should fail");

    let err_str = err.to_string();
    assert!(
        err_str.contains("context does not belong to this group"),
        "Expected 'context does not belong to this group', got: {}",
        err_str
    );

    Ok(())
}

#[tokio::test]
async fn test_context_group_returns_none_for_ungrouped() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root_account = worker.root_account()?;
    let node1 = root_account
        .create_subaccount("node1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let ctx = create_test_context(&node1, &contract, &mut rng).await?;

    let ctx_group: Option<Repr<ContextGroupId>> = contract
        .view("context_group")
        .args_json(json!({ "context_id": ctx.context_id }))
        .await?
        .json()?;

    assert!(
        ctx_group.is_none(),
        "ungrouped context should return None for context_group query"
    );

    Ok(())
}

// --- Phase 4: Target Application Management Tests ---

#[tokio::test]
async fn test_set_group_target_application() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root_account = worker.root_account()?;
    let node1 = root_account
        .create_subaccount("node1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let admin_sk = SigningKey::from_bytes(&rng.gen());
    let group_id: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let app_key: Repr<AppKey> = rng.gen::<[_; 32]>().rt()?;
    let original_app_id = rng.gen::<[_; 32]>().rt()?;
    let original_blob_id = rng.gen::<[_; 32]>().rt()?;

    let _res = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::Create {
                app_key,
                target_application: Application::new(
                    original_app_id,
                    original_blob_id,
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

    let group_info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;
    assert_eq!(
        group_info["target_application"]["id"],
        serde_json::to_value(original_app_id)?,
        "initial target app should match"
    );

    let new_app_id = rng.gen::<[_; 32]>().rt()?;
    let new_blob_id = rng.gen::<[_; 32]>().rt()?;

    let res = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::SetTargetApplication {
                migration_method: None,
                target_application: Application::new(
                    new_app_id,
                    new_blob_id,
                    1024,
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

    assert!(
        res.logs()
            .iter()
            .any(|log| log.contains("Updated target application for group")),
        "Expected update log, got: {:?}",
        res.logs()
    );

    let group_info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;
    assert_eq!(
        group_info["target_application"]["id"],
        serde_json::to_value(new_app_id)?,
        "target app should be updated"
    );
    assert_eq!(
        group_info["target_application"]["size"], 1024,
        "target app size should be updated"
    );

    Ok(())
}

#[tokio::test]
async fn test_set_group_target_non_admin_rejected() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root_account = worker.root_account()?;
    let node1 = root_account
        .create_subaccount("node1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let admin_sk = SigningKey::from_bytes(&rng.gen());
    let non_admin_sk = SigningKey::from_bytes(&rng.gen());
    let group_id: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let app_key: Repr<AppKey> = rng.gen::<[_; 32]>().rt()?;
    let application_id = rng.gen::<[_; 32]>().rt()?;
    let blob_id = rng.gen::<[_; 32]>().rt()?;

    let _res = node1
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

    let new_app_id = rng.gen::<[_; 32]>().rt()?;
    let new_blob_id = rng.gen::<[_; 32]>().rt()?;

    let err = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &non_admin_sk,
            group_id,
            GroupRequestKind::SetTargetApplication {
                migration_method: None,
                target_application: Application::new(
                    new_app_id,
                    new_blob_id,
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
        .raw_bytes()
        .expect_err("non-admin set target should fail");

    let err_str = err.to_string();
    assert!(
        err_str.contains("only group admins can set the target application"),
        "Expected 'only group admins can set the target application', got: {}",
        err_str
    );

    let group_info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;
    assert_eq!(
        group_info["target_application"]["id"],
        serde_json::to_value(application_id)?,
        "target app should remain unchanged after rejected update"
    );

    Ok(())
}

#[tokio::test]
async fn test_set_group_target_nonexistent_group() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root_account = worker.root_account()?;
    let node1 = root_account
        .create_subaccount("node1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let admin_sk = SigningKey::from_bytes(&rng.gen());
    let group_id: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let new_app_id = rng.gen::<[_; 32]>().rt()?;
    let new_blob_id = rng.gen::<[_; 32]>().rt()?;

    let err = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::SetTargetApplication {
                migration_method: None,
                target_application: Application::new(
                    new_app_id,
                    new_blob_id,
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
        .raw_bytes()
        .expect_err("set target on nonexistent group should fail");

    let err_str = err.to_string();
    assert!(
        err_str.contains("group does not exist"),
        "Expected 'group does not exist', got: {}",
        err_str
    );

    Ok(())
}

// --- Phase 5 proxy authorization tests ---

#[tokio::test]
async fn test_approve_context_registration() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root_account = worker.root_account()?;
    let node1 = root_account
        .create_subaccount("node1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let admin_sk = SigningKey::from_bytes(&rng.gen());
    let group_id: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let app_key: Repr<AppKey> = rng.gen::<[_; 32]>().rt()?;
    let application_id = rng.gen::<[_; 32]>().rt()?;
    let blob_id = rng.gen::<[_; 32]>().rt()?;

    let _res = node1
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

    let ctx = create_test_context(&node1, &contract, &mut rng).await?;

    let res = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::ApproveContextRegistration {
                context_id: ctx.context_id,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let expected_log = format!(
        "Context `{}` approved for registration in group `{}`",
        ctx.context_id, group_id
    );
    assert!(
        res.logs().iter().any(|log| log == &expected_log),
        "Expected approval log: {}, got: {:?}",
        expected_log,
        res.logs()
    );

    Ok(())
}

#[tokio::test]
async fn test_non_admin_approve_context_registration_rejected() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let root_account = worker.root_account()?;
    let node1 = root_account
        .create_subaccount("node1")
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

    let admin_sk = SigningKey::from_bytes(&rng.gen());
    let non_admin_sk = SigningKey::from_bytes(&rng.gen());
    let group_id: Repr<ContextGroupId> = rng.gen::<[_; 32]>().rt()?;
    let app_key: Repr<AppKey> = rng.gen::<[_; 32]>().rt()?;
    let application_id = rng.gen::<[_; 32]>().rt()?;
    let blob_id = rng.gen::<[_; 32]>().rt()?;

    let _res = node1
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

    let ctx = create_test_context(&node1, &contract, &mut rng).await?;

    let err = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &non_admin_sk,
            group_id,
            GroupRequestKind::ApproveContextRegistration {
                context_id: ctx.context_id,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .raw_bytes()
        .expect_err("non-admin approve should fail");

    let err_str = err.to_string();
    assert!(
        err_str.contains("only group admins can approve context registrations"),
        "Expected 'only group admins can approve context registrations', got: {}",
        err_str
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Permission / Capability Tests
// ---------------------------------------------------------------------------

/// Helper: create a group with an admin, return (node, admin_sk, group_id).
async fn setup_group(
    worker: &Worker<Sandbox>,
    contract: &Contract,
    rng: &mut impl Rng,
) -> eyre::Result<(near_workspaces::Account, SigningKey, Repr<ContextGroupId>)> {
    let root_account = worker.root_account()?;
    let node = root_account
        .create_subaccount(&format!("n{}", rng.gen::<u32>()))
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?;

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

    Ok((node, admin_sk, group_id))
}

/// Helper: add a member to a group and return their signing key.
async fn add_member(
    node: &near_workspaces::Account,
    contract: &Contract,
    admin_sk: &SigningKey,
    group_id: Repr<ContextGroupId>,
    rng: &mut impl Rng,
    nonce: u64,
) -> eyre::Result<SigningKey> {
    let member_sk = SigningKey::from_bytes(&rng.gen());
    let member_id: Repr<SignerId> = member_sk.verifying_key().to_bytes().rt()?;

    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            admin_sk,
            group_id,
            GroupRequestKind::AddMembers {
                members: vec![member_id].into(),
            },
            nonce,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    Ok(member_sk)
}

#[tokio::test]
async fn test_member_with_can_create_context_registers_context() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let (node, admin_sk, group_id) = setup_group(&worker, &contract, &mut rng).await?;

    // Add member Bob
    let bob_sk = add_member(&node, &contract, &admin_sk, group_id, &mut rng, 0).await?;
    let bob_id: Repr<SignerId> = bob_sk.verifying_key().to_bytes().rt()?;

    // Grant Bob CAN_CREATE_CONTEXT
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::SetMemberCapabilities {
                member: bob_id,
                capabilities: MemberCapabilities::CAN_CREATE_CONTEXT,
            },
            1,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Create a context first (needed to register it in the group)
    let ctx = create_test_context(&node, &contract, &mut rng).await?;

    // Bob registers the context in the group — should succeed
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &bob_sk,
            group_id,
            GroupRequestKind::RegisterContext {
                context_id: ctx.context_id,
                visibility_mode: None,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Verify context is registered
    let group_info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;
    assert_eq!(group_info["context_count"], 1);

    Ok(())
}

#[tokio::test]
async fn test_member_without_can_create_context_rejected() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let (node, admin_sk, group_id) = setup_group(&worker, &contract, &mut rng).await?;

    // Add member Bob (gets default capabilities: CAN_JOIN_OPEN_CONTEXTS only)
    let bob_sk = add_member(&node, &contract, &admin_sk, group_id, &mut rng, 0).await?;

    // Create context
    let ctx = create_test_context(&node, &contract, &mut rng).await?;

    // Bob tries to register context — should fail (no CAN_CREATE_CONTEXT)
    let err = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &bob_sk,
            group_id,
            GroupRequestKind::RegisterContext {
                context_id: ctx.context_id,
                visibility_mode: None,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .raw_bytes()
        .expect_err("member without CAN_CREATE_CONTEXT should fail");

    let err_str = err.to_string();
    assert!(
        err_str.contains("insufficient capabilities to create context"),
        "Expected 'insufficient capabilities to create context', got: {}",
        err_str
    );

    Ok(())
}

#[tokio::test]
async fn test_admin_bypasses_capability_check_for_register_context() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let (node, admin_sk, group_id) = setup_group(&worker, &contract, &mut rng).await?;

    let ctx = create_test_context(&node, &contract, &mut rng).await?;

    // Admin registers context — always works regardless of capabilities
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::RegisterContext {
                context_id: ctx.context_id,
                visibility_mode: None,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let group_info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;
    assert_eq!(group_info["context_count"], 1);

    Ok(())
}

#[tokio::test]
async fn test_creator_auto_added_to_allowlist_on_restricted_context() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let (node, admin_sk, group_id) = setup_group(&worker, &contract, &mut rng).await?;

    let ctx = create_test_context(&node, &contract, &mut rng).await?;

    // Register context as Restricted
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::RegisterContext {
                context_id: ctx.context_id,
                visibility_mode: Some(VisibilityMode::Restricted),
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Check visibility
    let vis: serde_json::Value = contract
        .view("context_visibility")
        .args_json(json!({
            "group_id": group_id,
            "context_id": ctx.context_id,
        }))
        .await?
        .json()?;

    assert_eq!(vis["mode"], "Restricted");
    assert_eq!(
        vis["allowlist_count"], 1,
        "creator should be auto-added to allowlist"
    );

    // Check the creator is on the allowlist
    let admin_id: Repr<SignerId> = admin_sk.verifying_key().to_bytes().rt()?;
    let allowlist: Vec<serde_json::Value> = contract
        .view("context_allowlist")
        .args_json(json!({
            "group_id": group_id,
            "context_id": ctx.context_id,
            "offset": 0,
            "length": 10,
        }))
        .await?
        .json()?;

    assert_eq!(allowlist.len(), 1);
    assert_eq!(allowlist[0], json!(admin_id));

    Ok(())
}

#[tokio::test]
async fn test_join_open_context_blocked_without_capability() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let (node, admin_sk, group_id) = setup_group(&worker, &contract, &mut rng).await?;

    let ctx = create_test_context(&node, &contract, &mut rng).await?;

    // nonce 0: RegisterContext
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::RegisterContext {
                context_id: ctx.context_id,
                visibility_mode: Some(VisibilityMode::Open),
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // nonce 1: AddMembers (Dave)
    let dave_sk = add_member(&node, &contract, &admin_sk, group_id, &mut rng, 1).await?;
    let dave_id: Repr<SignerId> = dave_sk.verifying_key().to_bytes().rt()?;

    // nonce 2: SetMemberCapabilities — set Dave's capabilities to 0
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::SetMemberCapabilities {
                member: dave_id,
                capabilities: 0,
            },
            2,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Dave tries to join — JoinContextViaGroup skips nonce check
    let new_member_id: Repr<ContextIdentity> = dave_sk.verifying_key().to_bytes().rt()?;
    let err = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &dave_sk,
            group_id,
            GroupRequestKind::JoinContextViaGroup {
                context_id: ctx.context_id,
                new_member: new_member_id,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .raw_bytes()
        .expect_err("member without CAN_JOIN_OPEN_CONTEXTS should fail");

    let err_str = err.to_string();
    assert!(
        err_str.contains("insufficient capabilities to join open context"),
        "Expected 'insufficient capabilities to join open context', got: {}",
        err_str
    );

    Ok(())
}

#[tokio::test]
async fn test_join_restricted_context_blocked_for_non_allowlist() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let (node, admin_sk, group_id) = setup_group(&worker, &contract, &mut rng).await?;

    let ctx = create_test_context(&node, &contract, &mut rng).await?;

    // nonce 0: RegisterContext as Restricted
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::RegisterContext {
                context_id: ctx.context_id,
                visibility_mode: Some(VisibilityMode::Restricted),
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // nonce 1: AddMembers (Dave)
    let dave_sk = add_member(&node, &contract, &admin_sk, group_id, &mut rng, 1).await?;
    let dave_member: Repr<ContextIdentity> = dave_sk.verifying_key().to_bytes().rt()?;

    // Dave tries to join — nonce skipped for JoinContextViaGroup
    let err = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &dave_sk,
            group_id,
            GroupRequestKind::JoinContextViaGroup {
                context_id: ctx.context_id,
                new_member: dave_member,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .raw_bytes()
        .expect_err("non-allowlist member should fail to join restricted context");

    let err_str = err.to_string();
    assert!(
        err_str.contains("not on allowlist for this restricted context"),
        "Expected 'not on allowlist for this restricted context', got: {}",
        err_str
    );

    Ok(())
}

#[tokio::test]
async fn test_allowlist_member_can_join_restricted_context() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let (node, admin_sk, group_id) = setup_group(&worker, &contract, &mut rng).await?;

    let ctx = create_test_context(&node, &contract, &mut rng).await?;

    // nonce 0: RegisterContext as Restricted
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::RegisterContext {
                context_id: ctx.context_id,
                visibility_mode: Some(VisibilityMode::Restricted),
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // nonce 1: AddMembers (Carol)
    let carol_sk = add_member(&node, &contract, &admin_sk, group_id, &mut rng, 1).await?;
    let carol_id: Repr<SignerId> = carol_sk.verifying_key().to_bytes().rt()?;

    // nonce 2: ManageContextAllowlist — add Carol
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::ManageContextAllowlist {
                context_id: ctx.context_id,
                add: vec![carol_id],
                remove: vec![],
            },
            2,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Carol joins — nonce skipped for JoinContextViaGroup
    let carol_member: Repr<ContextIdentity> = carol_sk.verifying_key().to_bytes().rt()?;
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &carol_sk,
            group_id,
            GroupRequestKind::JoinContextViaGroup {
                context_id: ctx.context_id,
                new_member: carol_member,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    Ok(())
}

#[tokio::test]
async fn test_new_members_get_default_capabilities() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let (node, admin_sk, group_id) = setup_group(&worker, &contract, &mut rng).await?;

    // Verify default capabilities are CAN_JOIN_OPEN_CONTEXTS
    let group_info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;
    assert_eq!(
        group_info["default_member_capabilities"],
        MemberCapabilities::CAN_JOIN_OPEN_CONTEXTS as u64,
        "default should be CAN_JOIN_OPEN_CONTEXTS"
    );

    // nonce 0: AddMembers (Bob)
    let bob_sk = add_member(&node, &contract, &admin_sk, group_id, &mut rng, 0).await?;
    let bob_id: Repr<SignerId> = bob_sk.verifying_key().to_bytes().rt()?;

    // Query group members to check Bob's capabilities
    let members: Vec<serde_json::Value> = contract
        .view("group_members")
        .args_json(json!({
            "group_id": group_id,
            "offset": 0,
            "length": 10,
        }))
        .await?
        .json()?;

    let bob_entry = members
        .iter()
        .find(|m| m["identity"] == json!(bob_id))
        .expect("Bob should be in member list");
    assert_eq!(
        bob_entry["capabilities"],
        MemberCapabilities::CAN_JOIN_OPEN_CONTEXTS as u64,
        "Bob should have default CAN_JOIN_OPEN_CONTEXTS"
    );

    Ok(())
}

#[tokio::test]
async fn test_set_member_capabilities_rejected_for_non_admin() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let (node, admin_sk, group_id) = setup_group(&worker, &contract, &mut rng).await?;

    // nonce 0: AddMembers (Bob)
    let bob_sk = add_member(&node, &contract, &admin_sk, group_id, &mut rng, 0).await?;
    // nonce 1: AddMembers (Carol)
    let carol_sk = add_member(&node, &contract, &admin_sk, group_id, &mut rng, 1).await?;
    let carol_id: Repr<SignerId> = carol_sk.verifying_key().to_bytes().rt()?;

    // Bob (non-admin) tries to set Carol's capabilities — nonce check skipped (not admin)
    let err = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &bob_sk,
            group_id,
            GroupRequestKind::SetMemberCapabilities {
                member: carol_id,
                capabilities: MemberCapabilities::CAN_CREATE_CONTEXT,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .raw_bytes()
        .expect_err("non-admin should not be able to set capabilities");

    let err_str = err.to_string();
    assert!(
        err_str.contains("only group admins"),
        "Expected admin-only error, got: {}",
        err_str
    );

    Ok(())
}

#[tokio::test]
async fn test_set_default_capabilities_lockdown_mode() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let (node, admin_sk, group_id) = setup_group(&worker, &contract, &mut rng).await?;

    // nonce 0: SetDefaultCapabilities to 0 (lockdown mode)
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::SetDefaultCapabilities {
                default_capabilities: 0,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // nonce 1: AddMembers (Dave)
    let dave_sk = add_member(&node, &contract, &admin_sk, group_id, &mut rng, 1).await?;
    let dave_id: Repr<SignerId> = dave_sk.verifying_key().to_bytes().rt()?;

    // Verify Dave has 0 capabilities
    let members: Vec<serde_json::Value> = contract
        .view("group_members")
        .args_json(json!({
            "group_id": group_id,
            "offset": 0,
            "length": 10,
        }))
        .await?
        .json()?;

    let dave_entry = members
        .iter()
        .find(|m| m["identity"] == json!(dave_id))
        .expect("Dave should be in member list");
    assert_eq!(
        dave_entry["capabilities"], 0,
        "Dave should have 0 capabilities in lockdown mode"
    );

    // Dave should not be able to join an open context
    let ctx = create_test_context(&node, &contract, &mut rng).await?;

    // nonce 2: RegisterContext as Open
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::RegisterContext {
                context_id: ctx.context_id,
                visibility_mode: Some(VisibilityMode::Open),
            },
            2,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Dave tries to join — nonce skipped for JoinContextViaGroup
    let dave_member: Repr<ContextIdentity> = dave_sk.verifying_key().to_bytes().rt()?;
    let err = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &dave_sk,
            group_id,
            GroupRequestKind::JoinContextViaGroup {
                context_id: ctx.context_id,
                new_member: dave_member,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .raw_bytes()
        .expect_err("lockdown member should not join open context");

    let err_str = err.to_string();
    assert!(
        err_str.contains("insufficient capabilities to join open context"),
        "Expected capability error, got: {}",
        err_str
    );

    Ok(())
}

#[tokio::test]
async fn test_set_default_visibility_restricted() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let (node, admin_sk, group_id) = setup_group(&worker, &contract, &mut rng).await?;

    // nonce 0: SetDefaultVisibility to Restricted
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::SetDefaultVisibility {
                default_visibility: VisibilityMode::Restricted,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Verify group info
    let group_info: serde_json::Value = contract
        .view("group")
        .args_json(json!({ "group_id": group_id }))
        .await?
        .json()?;
    assert_eq!(group_info["default_context_visibility"], "Restricted");

    // Register a context with None visibility (should inherit Restricted)
    let ctx = create_test_context(&node, &contract, &mut rng).await?;

    // nonce 1: RegisterContext with None (inherits Restricted)
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::RegisterContext {
                context_id: ctx.context_id,
                visibility_mode: None,
            },
            1,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Verify the context inherited Restricted visibility
    let vis: serde_json::Value = contract
        .view("context_visibility")
        .args_json(json!({
            "group_id": group_id,
            "context_id": ctx.context_id,
        }))
        .await?
        .json()?;

    assert_eq!(vis["mode"], "Restricted");
    assert_eq!(vis["allowlist_count"], 1, "creator auto-added to allowlist");

    Ok(())
}

#[tokio::test]
async fn test_set_context_visibility_by_non_creator_non_admin_rejected() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let (node, admin_sk, group_id) = setup_group(&worker, &contract, &mut rng).await?;

    let ctx = create_test_context(&node, &contract, &mut rng).await?;

    // nonce 0: RegisterContext as Open (admin is the creator)
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::RegisterContext {
                context_id: ctx.context_id,
                visibility_mode: Some(VisibilityMode::Open),
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // nonce 1: AddMembers (Bob)
    let bob_sk = add_member(&node, &contract, &admin_sk, group_id, &mut rng, 1).await?;

    // Bob (non-creator, non-admin) tries to change visibility — nonce check skipped
    let err = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &bob_sk,
            group_id,
            GroupRequestKind::SetContextVisibility {
                context_id: ctx.context_id,
                mode: VisibilityMode::Restricted,
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .raw_bytes()
        .expect_err("non-creator non-admin should not change visibility");

    let err_str = err.to_string();
    assert!(
        err_str.contains("only the context creator or a group admin"),
        "Expected creator/admin error, got: {}",
        err_str
    );

    Ok(())
}

#[tokio::test]
async fn test_manage_allowlist_add_and_remove() -> eyre::Result<()> {
    let (worker, contract) = setup().await?;
    let mut rng = rand::thread_rng();

    let (node, admin_sk, group_id) = setup_group(&worker, &contract, &mut rng).await?;

    let ctx = create_test_context(&node, &contract, &mut rng).await?;

    // nonce 0: RegisterContext as Restricted
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::RegisterContext {
                context_id: ctx.context_id,
                visibility_mode: Some(VisibilityMode::Restricted),
            },
            0,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // nonce 1: AddMembers (Carol)
    let carol_sk = add_member(&node, &contract, &admin_sk, group_id, &mut rng, 1).await?;
    let carol_id: Repr<SignerId> = carol_sk.verifying_key().to_bytes().rt()?;
    // nonce 2: AddMembers (Dave)
    let dave_sk = add_member(&node, &contract, &admin_sk, group_id, &mut rng, 2).await?;
    let dave_id: Repr<SignerId> = dave_sk.verifying_key().to_bytes().rt()?;

    // nonce 3: ManageContextAllowlist — add Carol and Dave
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::ManageContextAllowlist {
                context_id: ctx.context_id,
                add: vec![carol_id, dave_id],
                remove: vec![],
            },
            3,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Check allowlist has 3 (admin auto-added + Carol + Dave)
    let allowlist: Vec<serde_json::Value> = contract
        .view("context_allowlist")
        .args_json(json!({
            "group_id": group_id,
            "context_id": ctx.context_id,
            "offset": 0,
            "length": 10,
        }))
        .await?
        .json()?;
    assert_eq!(allowlist.len(), 3, "should have 3 on allowlist");

    // nonce 4: ManageContextAllowlist — remove Dave
    let _res = node
        .call(contract.id(), "mutate")
        .args_json(make_group_request(
            &admin_sk,
            group_id,
            GroupRequestKind::ManageContextAllowlist {
                context_id: ctx.context_id,
                add: vec![],
                remove: vec![dave_id],
            },
            4,
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    // Check allowlist has 2
    let allowlist: Vec<serde_json::Value> = contract
        .view("context_allowlist")
        .args_json(json!({
            "group_id": group_id,
            "context_id": ctx.context_id,
            "offset": 0,
            "length": 10,
        }))
        .await?
        .json()?;
    assert_eq!(allowlist.len(), 2, "should have 2 after removing Dave");

    Ok(())
}
