#![allow(unused_crate_dependencies)]

use calimero_context_config::repr::{Repr, ReprTransmute};
use calimero_context_config::types::{
    AppKey, Application, ContextGroupId, Signed, SignerId,
};
use calimero_context_config::{GroupRequest, GroupRequestKind, Request, RequestKind};
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
