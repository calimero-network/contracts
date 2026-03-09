use calimero_context_config::repr::Repr;
use calimero_context_config::types::{
    AppKey, Application, ContextGroupId, ContextId, ContextIdentity, SignerId,
};
use near_sdk::store::{IterableMap, IterableSet, LazyOption};
use near_sdk::{env, near, AccountId, BlockHeight, CryptoHash};

use crate::guard::Guard;
use crate::{MemberCapabilities, Prefix, VisibilityInfo, VisibilityMode};

#[derive(Debug)]
#[near(serializers = [borsh])]
pub struct OldContextConfigs {
    contexts: IterableMap<ContextId, OldContext>,
    config: OldConfig,
    proxy_code: LazyOption<Vec<u8>>,
    proxy_code_hash: LazyOption<CryptoHash>,
    next_proxy_id: u64,
    groups: IterableMap<ContextGroupId, OldOnChainGroupMeta>,
    context_group_refs: IterableMap<ContextId, ContextGroupId>,
}

#[derive(Debug)]
#[near(serializers = [borsh])]
struct OldConfig {
    validity_threshold_ms: u64,
}

#[derive(Debug)]
#[near(serializers = [borsh])]
struct OldContext {
    pub application: Guard<Application<'static>>,
    pub members: Guard<IterableSet<ContextIdentity>>,
    pub member_nonces: IterableMap<ContextIdentity, u64>,
    pub proxy: Guard<AccountId>,
    pub used_open_invitations: Guard<IterableSet<CryptoHash>>,
    pub commitments_open_invitations: IterableMap<CryptoHash, BlockHeight>,
    pub group_id: Option<ContextGroupId>,
}

/// Pre-migration group meta without permission fields.
#[derive(Debug)]
#[near(serializers = [borsh])]
struct OldOnChainGroupMeta {
    pub app_key: AppKey,
    pub target_application: Application<'static>,
    pub admins: IterableSet<SignerId>,
    pub admin_nonces: IterableMap<SignerId, u64>,
    pub members: IterableSet<SignerId>,
    pub approved_registrations: IterableSet<ContextId>,
    pub context_ids: IterableSet<ContextId>,
    pub context_count: u64,
    pub invitation_commitments: IterableMap<CryptoHash, BlockHeight>,
    pub used_invitations: IterableSet<CryptoHash>,
    pub member_contexts: IterableMap<(SignerId, ContextId), ContextIdentity>,
    pub migration_method: Option<String>,
}

pub fn migrate() {
    let state = env::state_read::<OldContextConfigs>().expect("failed to read state");

    // Collect group IDs and their members so we can initialize capabilities
    // after re-writing state (borsh will default the new Option/map tails).
    let groups_members: Vec<(ContextGroupId, Vec<SignerId>)> = state
        .groups
        .iter()
        .map(|(gid, group)| {
            let members: Vec<SignerId> = group.members.iter().copied().collect();
            (*gid, members)
        })
        .collect();

    // Re-write state. The new fields at the end of OnChainGroupMeta will be
    // default-initialized by borsh: IterableMaps empty, u32 = 0,
    // VisibilityMode = Open (default variant).
    env::state_write(&state);

    // Now populate the member_capabilities map for each group.
    // We need to read the state back as the new type so we can insert into
    // the new IterableMap fields.
    let mut new_state =
        env::state_read::<crate::ContextConfigs>().expect("failed to re-read state");

    for (group_id, members) in &groups_members {
        let group = new_state
            .groups
            .get_mut(group_id)
            .expect("group disappeared during migration");

        // Initialize new maps with proper prefixes
        group.member_capabilities =
            IterableMap::new(Prefix::GroupMemberCapabilities(*group_id));
        group.context_visibility =
            IterableMap::new(Prefix::GroupContextVisibility(*group_id));
        group.context_allowlists =
            IterableMap::new(Prefix::GroupContextAllowlists(*group_id));
        group.default_member_capabilities = MemberCapabilities::CAN_JOIN_OPEN_CONTEXTS;
        group.default_context_visibility = VisibilityMode::Open;

        // Existing members get CAN_JOIN_OPEN_CONTEXTS to preserve current behavior
        for member in members {
            let _ignored = group
                .member_capabilities
                .insert(*member, MemberCapabilities::CAN_JOIN_OPEN_CONTEXTS);
        }

        env::log_str(&format!(
            "Migrated group `{}` (added permissions, {} members initialized)",
            Repr::new(*group_id),
            members.len()
        ));
    }

    env::state_write(&new_state);
}
