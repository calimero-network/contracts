use calimero_context_config::repr::{Repr, ReprTransmute};
use calimero_context_config::types::{
    Application, Capability, ContextId, ContextIdentity, Signed, SignerId,
};
use calimero_context_config::{
    ContextRequest, ContextRequestKind, Request, RequestKind,
    types::{
        InvitationFromMember, RevealPayloadData, SignedOpenInvitation, SignedRevealPayload,
    }
};
use calimero_context_config_near::invitation::NEAR_PROTOCOL_TESTNET_ID;

use near_sdk::{
    NearToken, borsh::{self}
};
use near_workspaces::{
    Account, Contract, Worker,
    network::Sandbox,
};

use ed25519_dalek::{Signer, SigningKey};
use rand::Rng;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::str::FromStr;

use tokio::fs;

/// Helper to sign a payload with a given secret key.
fn sign_payload(payload: &RevealPayloadData, account: &Account) -> String {
    let secret_key_near = get_near_secret_key_from_account(account);
    let signer = near_crypto::InMemorySigner::from_secret_key(account.id().clone(), secret_key_near);

    let bytes = borsh::to_vec(payload).unwrap();
    let hash = Sha256::digest(&bytes);
    let signature = signer.sign(&hash);
    // Get signature from the second byte, because the first one contains the signature type
    // (Ed25519)
    hex::encode(&borsh::to_vec(&signature).unwrap()[1..])
}

/// Helper to sign an invitation with a given secret key.
fn sign_invitation(invitation: &InvitationFromMember, account: &Account) -> String {
    let secret_key_near = get_near_secret_key_from_account(account);
    let signer = near_crypto::InMemorySigner::from_secret_key(account.id().clone(), secret_key_near);

    let bytes = borsh::to_vec(invitation).unwrap();
    let hash = Sha256::digest(&bytes);
    let signature = signer.sign(&hash);
    // Get signature from the second byte, because the first one contains the signature type
    // (Ed25519)
    hex::encode(&borsh::to_vec(&signature).unwrap()[1..])
}

fn get_near_secret_key_from_account(account: &Account) -> near_crypto::SecretKey {
    near_crypto::SecretKey::from_str(
        account.secret_key().to_string().as_str()
    )
        .expect("Conversion to NEAR sk failed")
}

fn get_public_key_data_from_account(account: &Account) -> [u8; 32] {
    let public_key: near_crypto::PublicKey = account.secret_key().public_key().into();

    let key_slice = public_key.key_data();

    let key_data: [u8; 32] = key_slice
        .try_into()
        .expect("key is not 32 bytes long");
    key_data
}

fn create_account_with_new_key(worker: &Worker<Sandbox>, new_account_id: &str) -> Account {
    let secret_key = near_workspaces::types::SecretKey::from_random(near_workspaces::types::KeyType::ED25519);
    Account::from_secret_key(new_account_id.parse().unwrap(), secret_key, worker)
}

async fn create_subaccount_with_new_key_from(account: &Account, new_account_id: &str) -> eyre::Result<Account> {
    Ok(account
        .create_subaccount(new_account_id)
        .initial_balance(NearToken::from_near(30))
        .transact()
        .await?
        .into_result()?
    )
}

/// Boilerplate setup for tests.
async fn setup() -> eyre::Result<(Worker<Sandbox>, Contract, Account, Account, Repr<ContextId>)> {
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


    //
    // Create identities and accounts
    //
    // ============================================================
    let alice = create_account_with_new_key(&worker, "alice");
    //let alice = worker.dev_create_account().await?;
    let alice_cx_id = get_public_key_data_from_account(&alice).rt()?;

    let mut rng = rand::thread_rng();
    let context_secret = SigningKey::from_bytes(&rng.gen());
    let context_public = context_secret.verifying_key();
    let context_id = context_public.to_bytes().rt()?;

    let application_id = rng.gen::<[_; 32]>().rt()?;
    let blob_id = rng.gen::<[_; 32]>().rt()?;

    let relayer = worker.dev_create_account().await?;
    // ============================================================

    // Create a context and add Alice as a member there
    // ============================================================
    let res = relayer
        .call(contract.id(), "mutate")
        .args_json(Signed::new(
            &{
                let kind = RequestKind::Context(ContextRequest::new(
                    context_id,
                    ContextRequestKind::Add {
                        author_id: alice_cx_id,
                        application: Application::new(
                            application_id,
                            blob_id,
                            0,
                            Default::default(),
                            Default::default(),
                        ),
                    },
                ));

                Request::new(context_id.rt()?, kind, 0)
            },
            |p| context_secret.sign(p),
        )?)
        .max_gas()
        .transact()
        .await?
        .into_result()?;
    // ============================================================

    // Assert context creation
    let expected_log = format!("Context `{}` added", context_id);
    assert!(res.logs().iter().any(|log| log == &expected_log));

    // Verify Alice has priveleges to invite members
    // ============================================================
    let res: BTreeMap<Repr<SignerId>, Vec<Capability>> = contract
        .view("privileges")
        .args_json(json!({
            "context_id": context_id,
            "identities": [],
        }))
        .await?
        .json()?;

    assert_eq!(res.len(), 1);

    let alice_capabilities = res
        .get(&alice_cx_id.rt()?)
        .expect("alice should have capabilities");

    assert_eq!(
        alice_capabilities,
        &[Capability::ManageApplication, Capability::ManageMembers]
    );
    // ============================================================

    // Verify Alice is a member of the context and the only member
    // ============================================================
    let res: Vec<Repr<ContextIdentity>> = contract
        .view("members")
        .args_json(json!({
            "context_id": context_id,
            "offset": 0,
            "length": 10,
        }))
        .await?
        .json()?;

    assert_eq!(res, [alice_cx_id]);
    // ============================================================

    Ok((worker, contract, relayer, alice, context_id))
}

#[tokio::test]
async fn test_happy_path_self_reveal() -> eyre::Result<()> {
    let (worker, contract, relayer, alice, context_id) = setup().await?;

    let alice_cx_id = get_public_key_data_from_account(&alice).rt()?;

    let bob = create_account_with_new_key(&worker, "bob");
    //let bob = worker.dev_create_account().await?;
    let bob_cx_id = get_public_key_data_from_account(&bob).rt()?;

    assert_ne!(alice_cx_id, bob_cx_id, "Alice and Bob should have different identities");

    let mut rng = rand::thread_rng();

    // 1. ARRANGE: Alice creates and signs an invitation.
    let current_height = worker.view_block().await?.height();
    let random_salt: [u8; 32] = rng.gen::<[_; 32]>();
    let invitation = InvitationFromMember {
        inviter_identity: alice_cx_id, //ContextIdentity(alice.public_key().as_bytes()[1..].try_into()?),
        context_id: *context_id.clone(),
        expiration_height: current_height + 1000,
        secret_salt: random_salt,
        protocol: NEAR_PROTOCOL_TESTNET_ID,
    };
    let inviter_signature = sign_invitation(&invitation, &alice);

    // 2. ARRANGE: Bob creates the reveal payload data.
    let reveal_data = RevealPayloadData {
        signed_open_invitation: SignedOpenInvitation {
            invitation,
            inviter_signature,
        },
        new_member_identity: bob_cx_id, //ContextIdentity(bob.public_key().as_bytes()[1..].try_into()?),
    };

    // 3. ACT: Bob signs the data and creates a commitment hash.
    let bob_signature = sign_payload(&reveal_data, &bob);
    println!("Bob signature: {:?}", bob_signature);
    let signed_payload = SignedRevealPayload {
        data: reveal_data,
        invitee_signature: bob_signature,
    };

    let commitment_hash = hex::encode(Sha256::digest(&borsh::to_vec(&signed_payload.data)?));

    // 4. ACT: Bob commits to the hash.
    let commit_res = relayer
        .call(contract.id(), "commit_invitation")
        .args_json(serde_json::json!({
            "context_id": context_id,
            "commitment_hash": commitment_hash,
            "expiration_block_height": signed_payload.data.signed_open_invitation.invitation.expiration_height,
        }))
        .transact()
        .await?;
    println!("{:?}", commit_res.logs());
    assert!(commit_res.is_success());

    let reveal_res = relayer
        .call(contract.id(), "reveal_invitation")
        .args_borsh(signed_payload)
        .max_gas()
        .transact()
        .await?;

    // 5. ASSERT: The reveal was successful.
    println!("{:?}", reveal_res.logs());
    println!("{:?}", reveal_res.clone().into_result());
    assert!(reveal_res.is_success());
    assert!(reveal_res.logs().iter().any(|log| log.contains("successfully joined context")));

    Ok(())
}
