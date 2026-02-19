use core::mem;

use calimero_context_config::repr::{Repr, ReprBytes, ReprTransmute};
use calimero_context_config::types::{
    AppKey, Application, Capability, ContextGroupId, ContextId, ContextIdentity, Signed, SignerId,
};
use calimero_context_config::{
    ContextRequest, ContextRequestKind, GroupRequest, GroupRequestKind, Request, RequestKind,
};
use near_sdk::serde_json::{self, json};
use near_sdk::store::{IterableMap, IterableSet};
use near_sdk::{env, near, require, AccountId, Gas, NearToken, Promise, PromiseError};

use super::{
    parse_input, Context, ContextConfigs, ContextConfigsExt, ContextPrivilegeScope, Guard,
    OnChainGroupMeta, Prefix, PrivilegeScope,
};

#[near]
impl ContextConfigs {
    pub fn mutate(&mut self) {
        parse_input!(request: Signed<Request<'_>>);

        let request = request
            .parse(|i| *i.signer_id)
            .expect("failed to parse input");

        let (context_id, kind) = match request.kind {
            RequestKind::Context(ContextRequest {
                context_id, kind, ..
            }) => (context_id, kind),
            RequestKind::Group(group_request) => {
                self.handle_group_request(&request.signer_id, group_request);
                return;
            }
        };

        self.check_and_increment_nonce(
            *context_id,
            request.signer_id.rt().expect("infallible conversion"),
            request.nonce,
        );

        match kind {
            ContextRequestKind::Add {
                author_id,
                application,
            } => {
                let _is_sent_on_drop =
                    self.add_context(&request.signer_id, context_id, author_id, application);
            }
            ContextRequestKind::UpdateApplication { application } => {
                self.update_application(&request.signer_id, context_id, application);
            }
            ContextRequestKind::AddMembers { members } => {
                self.add_members(&request.signer_id, context_id, members.into_owned());
            }
            ContextRequestKind::RemoveMembers { members } => {
                self.remove_members(&request.signer_id, context_id, members.into_owned())
            }
            ContextRequestKind::Grant { capabilities } => {
                self.grant(&request.signer_id, context_id, capabilities.into_owned());
            }
            ContextRequestKind::Revoke { capabilities } => {
                self.revoke(&request.signer_id, context_id, capabilities.into_owned());
            }
            ContextRequestKind::UpdateProxyContract => {
                let _is_sent_on_drop = self.update_proxy_contract(&request.signer_id, context_id);
            }
            ContextRequestKind::CommitOpenInvitation {
                commitment_hash,
                expiration_block_height,
            } => {
                self.commit_invitation(context_id, commitment_hash, expiration_block_height);
            }
            ContextRequestKind::RevealOpenInvitation { payload } => {
                self.reveal_invitation(payload);
            }
        }
    }
}

impl ContextConfigs {
    fn check_and_increment_nonce(
        &mut self,
        context_id: ContextId,
        member_id: ContextIdentity,
        nonce: u64,
    ) {
        let Some(context) = self.contexts.get_mut(&context_id) else {
            return;
        };

        let Some(current_nonce) = context.member_nonces.get_mut(&member_id) else {
            return;
        };

        require!(*current_nonce == nonce, "invalid nonce");

        *current_nonce += 1;
    }

    fn add_context(
        &mut self,
        signer_id: &SignerId,
        context_id: Repr<ContextId>,
        author_id: Repr<ContextIdentity>,
        application: Application<'_>,
    ) -> Promise {
        require!(
            signer_id.as_bytes() == context_id.as_bytes(),
            "context addition must be signed by the context itself"
        );

        let mut members = IterableSet::new(Prefix::Members(*context_id));
        let _ignored = members.insert(*author_id);

        let mut member_nonces = IterableMap::new(Prefix::MemberNonces(*context_id));
        let _ignored = member_nonces.insert(*author_id, 0);

        let used_open_invitations = IterableSet::new(Prefix::UsedOpenInvitations(*context_id));
        let open_invitation_commitments =
            IterableMap::new(Prefix::CommitmentsOpenInvitations(*context_id));

        // Create incremental account ID
        let account_id: AccountId = format!("{}.{}", self.next_proxy_id, env::current_account_id())
            .parse()
            .expect("invalid account ID");

        self.next_proxy_id += 1;

        let mut context = Context {
            application: Guard::new(
                Prefix::Privileges(PrivilegeScope::Context(
                    *context_id,
                    ContextPrivilegeScope::Application,
                )),
                author_id.rt().expect("infallible conversion"),
                Application::new(
                    application.id,
                    application.blob,
                    application.size,
                    application.source.to_owned(),
                    application.metadata.to_owned(),
                ),
            ),
            members: Guard::new(
                Prefix::Privileges(PrivilegeScope::Context(
                    *context_id,
                    ContextPrivilegeScope::MemberList,
                )),
                author_id.rt().expect("infallible conversion"),
                members,
            ),
            member_nonces,
            proxy: Guard::new(
                Prefix::Privileges(PrivilegeScope::Context(
                    *context_id,
                    ContextPrivilegeScope::Proxy,
                )),
                author_id.rt().expect("infallible conversion"),
                account_id.clone(),
            ),
            used_open_invitations: Guard::new(
                Prefix::Privileges(PrivilegeScope::Context(
                    *context_id,
                    ContextPrivilegeScope::MemberList,
                )),
                author_id.rt().expect("invallible conversion"),
                used_open_invitations,
            ),
            commitments_open_invitations: open_invitation_commitments,
            group_id: None,
        };

        let _ignored = context.member_nonces.insert(*author_id, 0);

        if self.contexts.insert(*context_id, context).is_some() {
            env::panic_str("context already exists");
        }

        env::log_str(&format!("Context `{}` added", context_id));

        self.init_proxy_contract(context_id, account_id)
    }

    fn update_application(
        &mut self,
        signer_id: &SignerId,
        context_id: Repr<ContextId>,
        application: Application<'_>,
    ) {
        let context = self
            .contexts
            .get_mut(&context_id)
            .expect("context does not exist");

        let new_application_id = application.id;

        let old_application = mem::replace(
            &mut *context
                .application
                .get(signer_id)
                .expect("unable to update application")
                .get_mut(),
            Application::new(
                application.id,
                application.blob,
                application.size,
                application.source.to_owned(),
                application.metadata.to_owned(),
            ),
        );

        env::log_str(&format!(
            "Updated application for context `{}` from `{}` to `{}`",
            context_id, old_application.id, new_application_id
        ));
    }

    fn add_members(
        &mut self,
        signer_id: &SignerId,
        context_id: Repr<ContextId>,
        members: Vec<Repr<ContextIdentity>>,
    ) {
        let context = self
            .contexts
            .get_mut(&context_id)
            .expect("context does not exist");

        let mut ctx_members = context
            .members
            .get(signer_id)
            .expect("unable to update member list")
            .get_mut();

        for member in members {
            env::log_str(&format!("Added `{member}` as a member of `{context_id}`"));

            let _ignored = context.member_nonces.entry(*member).or_default();

            let _ignored = ctx_members.insert(*member);
        }
    }

    fn remove_members(
        &mut self,
        signer_id: &SignerId,
        context_id: Repr<ContextId>,
        members: Vec<Repr<ContextIdentity>>,
    ) {
        let context = self
            .contexts
            .get_mut(&context_id)
            .expect("context does not exist");

        let mut ctx_members = context
            .members
            .get(signer_id)
            .expect("unable to update member list")
            .get_mut();

        for member in members {
            let _ignored = ctx_members.remove(&member);

            let _ignored = context.member_nonces.remove(&member);

            let member = member.rt().expect("infallible conversion");

            env::log_str(&format!(
                "Removed `{}` from being a member of `{}`",
                Repr::new(member),
                context_id
            ));

            ctx_members.priviledges().revoke(&member);
            context.application.priviledges().revoke(&member);
        }
    }

    fn grant(
        &mut self,
        signer_id: &SignerId,
        context_id: Repr<ContextId>,
        capabilities: Vec<(Repr<ContextIdentity>, Capability)>,
    ) {
        let context = self
            .contexts
            .get_mut(&context_id)
            .expect("context does not exist");

        for (identity, capability) in capabilities {
            require!(
                context.members.contains(&*identity),
                "unable to grant privileges to non-member"
            );

            let identity = identity.rt().expect("infallible conversion");

            match capability {
                Capability::ManageApplication => context
                    .application
                    .get(signer_id)
                    .expect("unable to update application")
                    .priviledges()
                    .grant(identity),
                Capability::ManageMembers => context
                    .members
                    .get(signer_id)
                    .expect("unable to update member list")
                    .priviledges()
                    .grant(identity),
                Capability::Proxy => context
                    .proxy
                    .get(signer_id)
                    .expect("unable to update proxy")
                    .priviledges()
                    .grant(identity),
            };

            env::log_str(&format!(
                "Granted `{:?}` to `{}` in `{}`",
                capability,
                Repr::new(identity),
                context_id
            ));
        }
    }

    fn revoke(
        &mut self,
        signer_id: &SignerId,
        context_id: Repr<ContextId>,
        capabilities: Vec<(Repr<ContextIdentity>, Capability)>,
    ) {
        let context = self
            .contexts
            .get_mut(&context_id)
            .expect("context does not exist");

        for (identity, capability) in capabilities {
            let identity = identity.rt().expect("infallible conversion");

            match capability {
                Capability::ManageApplication => context
                    .application
                    .get(signer_id)
                    .expect("unable to update application")
                    .priviledges()
                    .revoke(&identity),
                Capability::ManageMembers => context
                    .members
                    .get(signer_id)
                    .expect("unable to update member list")
                    .priviledges()
                    .revoke(&identity),
                Capability::Proxy => context
                    .proxy
                    .get(signer_id)
                    .expect("unable to update proxy")
                    .priviledges()
                    .revoke(&identity),
            };

            env::log_str(&format!(
                "Revoked `{:?}` from `{}` in `{}`",
                capability,
                Repr::new(identity),
                context_id
            ));
        }
    }

    // take the proxy code from LazyOption's cache
    // without it assuming we're removing the value
    fn get_proxy_code(&self) -> Vec<u8> {
        let code_ref = self.proxy_code.get();

        let code_ptr = std::ptr::from_ref(code_ref) as usize + 0;

        let code_mut = unsafe { &mut *(code_ptr as *mut Option<Vec<u8>>) };

        code_mut.take().expect("proxy code not set")
    }

    fn init_proxy_contract(
        &mut self,
        context_id: Repr<ContextId>,
        account_id: AccountId,
    ) -> Promise {
        // Known constants from NEAR protocol
        const ACCOUNT_CREATION_COST: NearToken = NearToken::from_millinear(1); // 0.001 NEAR
        const MIN_ACCOUNT_BALANCE: NearToken = NearToken::from_millinear(35).saturating_div(10); // 0.0035 NEAR
        const STORAGE_TIP: NearToken = NearToken::from_near(1).saturating_div(10); // 0.1 NEAR

        let contract_bytes = self.get_proxy_code();
        let storage_cost = env::storage_byte_cost().saturating_mul(contract_bytes.len() as u128);

        let required_deposit = ACCOUNT_CREATION_COST
            .saturating_add(MIN_ACCOUNT_BALANCE)
            .saturating_add(STORAGE_TIP)
            .saturating_add(storage_cost);

        require!(
            env::account_balance() >= required_deposit,
            "Insufficient contract balance for deployment"
        );

        let init_args = serde_json::to_vec(&json!({ "context_id": context_id })).unwrap();

        Promise::new(account_id.clone())
            .create_account()
            .transfer(required_deposit)
            .deploy_contract(contract_bytes)
            .function_call(
                "init".to_owned(),
                init_args,
                NearToken::default(),
                Gas::from_tgas(1),
            )
            .then(Self::ext(env::current_account_id()).proxy_contract_callback())
    }

    fn update_proxy_contract(
        &mut self,
        signer_id: &SignerId,
        context_id: Repr<ContextId>,
    ) -> Promise {
        let context = self
            .contexts
            .get_mut(&context_id)
            .expect("context does not exist");

        let proxy_account_id = context
            .proxy
            .get(signer_id)
            .expect("unable to update contract")
            .get_mut()
            .clone();

        let contract_bytes = self.get_proxy_code();
        let storage_cost = env::storage_byte_cost().saturating_mul(contract_bytes.len() as u128);

        require!(
            env::account_balance() >= storage_cost,
            "Insufficient contract balance for deployment"
        );

        Promise::new(proxy_account_id)
            .function_call(
                "update_contract".to_owned(),
                contract_bytes,
                storage_cost,
                Gas::from_tgas(100),
            )
            .then(Self::ext(env::current_account_id()).proxy_contract_callback())
    }
}

impl ContextConfigs {
    fn handle_group_request(&mut self, signer_id: &SignerId, request: GroupRequest<'_>) {
        let group_id = request.group_id;

        match request.kind {
            GroupRequestKind::Create {
                app_key,
                target_application,
            } => {
                self.create_group(signer_id, group_id, *app_key, target_application);
            }
            GroupRequestKind::Delete => {
                self.delete_group(signer_id, group_id);
            }
            GroupRequestKind::AddMembers { members } => {
                self.add_group_members(signer_id, group_id, members.into_owned());
            }
            GroupRequestKind::RemoveMembers { members } => {
                self.remove_group_members(signer_id, group_id, members.into_owned());
            }
            GroupRequestKind::RegisterContext { context_id } => {
                self.register_context_in_group(signer_id, group_id, context_id);
            }
            GroupRequestKind::UnregisterContext { context_id } => {
                self.unregister_context_from_group(signer_id, group_id, context_id);
            }
            GroupRequestKind::SetTargetApplication {
                target_application,
            } => {
                self.set_group_target(signer_id, group_id, target_application);
            }
        }
    }

    fn create_group(
        &mut self,
        signer_id: &SignerId,
        group_id: Repr<ContextGroupId>,
        app_key: AppKey,
        target_application: Application<'_>,
    ) {
        require!(
            !self.groups.contains_key(&group_id),
            "group already exists"
        );

        let mut admins = IterableSet::new(Prefix::GroupAdmins(*group_id));
        let _ignored = admins.insert(*signer_id);

        let meta = OnChainGroupMeta {
            app_key,
            target_application: Application::new(
                target_application.id,
                target_application.blob,
                target_application.size,
                target_application.source.to_owned(),
                target_application.metadata.to_owned(),
            ),
            admins,
            member_count: 1,
            context_count: 0,
        };

        let _ignored = self.groups.insert(*group_id, meta);

        env::log_str(&format!("Group `{}` created", group_id));
    }

    fn delete_group(&mut self, signer_id: &SignerId, group_id: Repr<ContextGroupId>) {
        {
            let group = self.groups.get(&group_id).expect("group does not exist");

            require!(
                group.admins.contains(signer_id),
                "only group admins can delete a group"
            );

            require!(
                group.context_count == 0,
                "cannot delete group with registered contexts"
            );
        }

        let mut removed = self.groups.remove(&group_id).expect("group does not exist");
        removed.admins.clear();

        env::log_str(&format!("Group `{}` deleted", group_id));
    }

    fn add_group_members(
        &mut self,
        signer_id: &SignerId,
        group_id: Repr<ContextGroupId>,
        members: Vec<Repr<SignerId>>,
    ) {
        let group = self
            .groups
            .get_mut(&group_id)
            .expect("group does not exist");

        require!(
            group.admins.contains(signer_id),
            "only group admins can add members"
        );

        for member in &members {
            group.member_count += 1;
            env::log_str(&format!("Added `{}` to group `{}`", member, group_id));
        }
    }

    fn remove_group_members(
        &mut self,
        signer_id: &SignerId,
        group_id: Repr<ContextGroupId>,
        members: Vec<Repr<SignerId>>,
    ) {
        let group = self
            .groups
            .get_mut(&group_id)
            .expect("group does not exist");

        require!(
            group.admins.contains(signer_id),
            "only group admins can remove members"
        );

        for member in &members {
            require!(group.member_count > 0, "member count underflow");
            group.member_count -= 1;
            env::log_str(&format!("Removed `{}` from group `{}`", member, group_id));
        }
    }

    fn register_context_in_group(
        &mut self,
        signer_id: &SignerId,
        group_id: Repr<ContextGroupId>,
        context_id: Repr<ContextId>,
    ) {
        let group = self
            .groups
            .get_mut(&group_id)
            .expect("group does not exist");

        require!(
            group.admins.contains(signer_id),
            "only group admins can register contexts"
        );

        let context = self
            .contexts
            .get_mut(&context_id)
            .expect("context does not exist");

        require!(
            context.group_id.is_none(),
            "context already belongs to a group"
        );

        context.group_id = Some(*group_id);

        let group = self
            .groups
            .get_mut(&group_id)
            .expect("group does not exist");
        group.context_count += 1;

        let _ignored = self.context_group_refs.insert(*context_id, *group_id);

        env::log_str(&format!(
            "Context `{}` registered in group `{}`",
            context_id, group_id
        ));
    }

    fn unregister_context_from_group(
        &mut self,
        signer_id: &SignerId,
        group_id: Repr<ContextGroupId>,
        context_id: Repr<ContextId>,
    ) {
        let group = self
            .groups
            .get_mut(&group_id)
            .expect("group does not exist");

        require!(
            group.admins.contains(signer_id),
            "only group admins can unregister contexts"
        );

        let context = self
            .contexts
            .get_mut(&context_id)
            .expect("context does not exist");

        require!(
            context.group_id.as_ref() == Some(&*group_id),
            "context does not belong to this group"
        );

        context.group_id = None;

        let group = self
            .groups
            .get_mut(&group_id)
            .expect("group does not exist");
        require!(group.context_count > 0, "context count underflow");
        group.context_count -= 1;

        let _ignored = self.context_group_refs.remove(&context_id);

        env::log_str(&format!(
            "Context `{}` unregistered from group `{}`",
            context_id, group_id
        ));
    }

    fn set_group_target(
        &mut self,
        signer_id: &SignerId,
        group_id: Repr<ContextGroupId>,
        target_application: Application<'_>,
    ) {
        let group = self
            .groups
            .get_mut(&group_id)
            .expect("group does not exist");

        require!(
            group.admins.contains(signer_id),
            "only group admins can set the target application"
        );

        let old_application_id = group.target_application.id;

        group.target_application = Application::new(
            target_application.id,
            target_application.blob,
            target_application.size,
            target_application.source.to_owned(),
            target_application.metadata.to_owned(),
        );

        env::log_str(&format!(
            "Updated target application for group `{}` from `{}` to `{}`",
            group_id, old_application_id, target_application.id
        ));
    }
}

#[near]
impl ContextConfigs {
    #[private]
    pub fn proxy_contract_callback(
        &mut self,
        #[callback_result] call_result: Result<(), PromiseError>,
    ) {
        call_result.expect("Failed to update proxy contract");

        env::log_str("Successfully deployed proxy contract");
    }

    pub fn proxy_register_in_group(
        &mut self,
        context_id: Repr<ContextId>,
        group_id: Repr<ContextGroupId>,
    ) {
        {
            let context = self
                .contexts
                .get(&context_id)
                .expect("context does not exist");
            let proxy_account: &AccountId = &context.proxy;
            require!(
                env::predecessor_account_id() == *proxy_account,
                "only the context proxy can call this method"
            );
        }

        require!(
            self.groups.contains_key(&group_id),
            "group does not exist"
        );

        let context = self
            .contexts
            .get_mut(&context_id)
            .expect("context does not exist");
        require!(
            context.group_id.is_none(),
            "context already belongs to a group"
        );
        context.group_id = Some(*group_id);

        let group = self
            .groups
            .get_mut(&group_id)
            .expect("group does not exist");
        group.context_count += 1;

        let _ignored = self.context_group_refs.insert(*context_id, *group_id);

        env::log_str(&format!(
            "Context `{}` registered in group `{}` (via proxy)",
            context_id, group_id
        ));
    }

    pub fn proxy_unregister_from_group(&mut self, context_id: Repr<ContextId>) {
        let group_id = {
            let context = self
                .contexts
                .get(&context_id)
                .expect("context does not exist");
            let proxy_account: &AccountId = &context.proxy;
            require!(
                env::predecessor_account_id() == *proxy_account,
                "only the context proxy can call this method"
            );
            context.group_id.expect("context does not belong to a group")
        };

        let context = self
            .contexts
            .get_mut(&context_id)
            .expect("context does not exist");
        context.group_id = None;

        let group = self.groups.get_mut(&group_id).expect("group does not exist");
        require!(group.context_count > 0, "context count underflow");
        group.context_count -= 1;

        let _ignored = self.context_group_refs.remove(&context_id);

        env::log_str(&format!(
            "Context `{}` unregistered from group (via proxy)",
            context_id
        ));
    }
}
