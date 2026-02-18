use std::collections::BTreeMap;

use calimero_context_config::repr::{Repr, ReprTransmute};
use calimero_context_config::types::{
    AppKey, Application, Capability, ContextGroupId, ContextId, ContextIdentity, Revision,
    SignerId,
};
use near_sdk::serde::Serialize;
use near_sdk::{near, AccountId};

use super::{ContextConfigs, ContextConfigsExt};

#[derive(Debug, Serialize)]
#[serde(crate = "near_sdk::serde")]
pub struct GroupInfoResponse {
    pub app_key: Repr<AppKey>,
    pub target_application: Application<'static>,
    pub member_count: u64,
    pub context_count: u64,
}

#[near]
impl ContextConfigs {
    pub fn application(&self, context_id: Repr<ContextId>) -> &Application<'_> {
        let context = self
            .contexts
            .get(&context_id)
            .expect("context does not exist");

        &context.application
    }

    pub fn application_revision(&self, context_id: Repr<ContextId>) -> Revision {
        let context = self
            .contexts
            .get(&context_id)
            .expect("context does not exist");

        context.application.revision()
    }

    pub fn proxy_contract(&self, context_id: Repr<ContextId>) -> &AccountId {
        let context = self
            .contexts
            .get(&context_id)
            .expect("context does not exist");

        &context.proxy
    }

    pub fn members(
        &self,
        context_id: Repr<ContextId>,
        offset: usize,
        length: usize,
    ) -> Vec<Repr<ContextIdentity>> {
        let context = self
            .contexts
            .get(&context_id)
            .expect("context does not exist");

        let mut members = Vec::with_capacity(length);

        for member in context.members.iter().skip(offset).take(length) {
            members.push(Repr::new(*member));
        }

        members
    }

    pub fn has_member(&self, context_id: Repr<ContextId>, identity: Repr<ContextIdentity>) -> bool {
        let context = self
            .contexts
            .get(&context_id)
            .expect("context does not exist");

        context.members.contains(&identity)
    }

    pub fn members_revision(&self, context_id: Repr<ContextId>) -> Revision {
        let context = self
            .contexts
            .get(&context_id)
            .expect("context does not exist");

        context.members.revision()
    }

    pub fn privileges(
        &self,
        context_id: Repr<ContextId>,
        identities: Vec<Repr<ContextIdentity>>,
    ) -> BTreeMap<Repr<SignerId>, Vec<Capability>> {
        let context = self
            .contexts
            .get(&context_id)
            .expect("context does not exist");

        let mut privileges = BTreeMap::<_, Vec<_>>::new();

        let application_privileges = context.application.priviledged();
        let member_privileges = context.members.priviledged();

        if identities.is_empty() {
            for signer_id in application_privileges {
                privileges
                    .entry(Repr::new(*signer_id))
                    .or_default()
                    .push(Capability::ManageApplication);
            }

            for signer_id in member_privileges {
                privileges
                    .entry(Repr::new(*signer_id))
                    .or_default()
                    .push(Capability::ManageMembers);
            }
        } else {
            for identity in identities {
                let signer_id = identity.rt().expect("infallible conversion");

                let entry = privileges.entry(signer_id).or_default();

                if application_privileges.contains(&signer_id) {
                    entry.push(Capability::ManageApplication);
                }

                if member_privileges.contains(&signer_id) {
                    entry.push(Capability::ManageMembers);
                }
            }
        }

        privileges
    }

    pub fn fetch_nonce(
        &self,
        context_id: Repr<ContextId>,
        member_id: Repr<ContextIdentity>,
    ) -> Option<&u64> {
        self.contexts
            .get(&context_id)?
            .member_nonces
            .get(&member_id)
    }

    pub fn group(&self, group_id: Repr<ContextGroupId>) -> Option<GroupInfoResponse> {
        let group = self.groups.get(&group_id)?;

        Some(GroupInfoResponse {
            app_key: Repr::new(group.app_key),
            target_application: Application::new(
                group.target_application.id,
                group.target_application.blob,
                group.target_application.size,
                group.target_application.source.clone(),
                group.target_application.metadata.clone(),
            ),
            member_count: group.member_count,
            context_count: group.context_count,
        })
    }

    pub fn is_group_admin(
        &self,
        group_id: Repr<ContextGroupId>,
        identity: Repr<SignerId>,
    ) -> bool {
        self.groups
            .get(&group_id)
            .map_or(false, |group| group.admins.contains(&identity))
    }
}
