#![allow(unused_crate_dependencies)]

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

fn make_group_request(
    signer_sk: &SigningKey,
    group_id: Repr<ContextGroupId>,
    kind: GroupRequestKind<'_>,
) -> eyre::Result<Signed<Request<'_>>> {
    let signer_id: SignerId = signer_sk.verifying_key().to_bytes().rt()?;

    Ok(Signed::new(
        &{
            let kind = RequestKind::Group(GroupRequest::new(group_id, kind));
            Request::new(signer_id, kind, 0)
        },
        |p| signer_sk.sign(p),
    )?)
}

fn make_context_request(
    signer_sk: &SigningKey,
    context_id: Repr<ContextId>,
    kind: ContextRequestKind<'_>,
    nonce: u64,
) -> eyre::Result<Signed<Request<'_>>> {
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
    context_sk: SigningKey,
    author_id: Repr<ContextIdentity>,
    author_sk: SigningKey,
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
        context_sk,
        author_id,
        author_sk,
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
        .args_json(make_group_request(&admin_sk, group_id, create_kind)?)
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
        .args_json(make_group_request(&admin_sk, group_id, create_kind2)?)
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
        .args_json(make_group_request(&admin_sk, group_id, GroupRequestKind::Delete)?)
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

    assert!(group_info.is_none(), "group should not exist after deletion");

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
            },
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
    assert_eq!(ctx_group, Some(group_id), "reverse lookup should return group_id");

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
            },
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
            },
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
            },
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
    assert_eq!(group_info["context_count"], 0, "context_count should be 0 after unregistration");

    let ctx_group: Option<Repr<ContextGroupId>> = contract
        .view("context_group")
        .args_json(json!({ "context_id": ctx.context_id }))
        .await?
        .json()?;
    assert!(ctx_group.is_none(), "reverse lookup should return None after unregistration");

    let contexts: Vec<Repr<ContextId>> = contract
        .view("group_contexts")
        .args_json(json!({ "group_id": group_id, "offset": 0, "length": 10 }))
        .await?
        .json()?;
    assert!(contexts.is_empty(), "group_contexts should be empty after unregistration");

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
            },
        )?)
        .max_gas()
        .transact()
        .await?
        .raw_bytes()
        .expect_err("non-admin register should fail");

    let err_str = err.to_string();
    assert!(
        err_str.contains("only group admins can register contexts"),
        "Expected 'only group admins can register contexts', got: {}",
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
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let mut context_ids = Vec::new();
    for _ in 0..3 {
        let ctx = create_test_context(&node1, &contract, &mut rng).await?;

        let _res = node1
            .call(contract.id(), "mutate")
            .args_json(make_group_request(
                &admin_sk,
                group_id,
                GroupRequestKind::RegisterContext {
                    context_id: ctx.context_id,
                },
            )?)
            .max_gas()
            .transact()
            .await?
            .into_result()?;

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
            },
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let err = node1
        .call(contract.id(), "mutate")
        .args_json(make_group_request(&admin_sk, group_id, GroupRequestKind::Delete)?)
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
            },
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
                target_application: Application::new(
                    new_app_id,
                    new_blob_id,
                    1024,
                    "https://example.com/app.wasm".into(),
                    "v2 upgrade".into(),
                ),
            },
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    assert!(
        res.logs().iter().any(|log| log.contains("Updated target application for group")),
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
                target_application: Application::new(
                    new_app_id,
                    new_blob_id,
                    0,
                    Default::default(),
                    Default::default(),
                ),
            },
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
                target_application: Application::new(
                    new_app_id,
                    new_blob_id,
                    0,
                    Default::default(),
                    Default::default(),
                ),
            },
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
