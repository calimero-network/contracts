use calimero_context_config::repr::Repr;
use calimero_context_config::types::{
    AppKey, Application, ContextGroupId, ContextId, ContextIdentity, SignerId,
};
use near_sdk::store::{IterableMap, IterableSet, LazyOption};
use near_sdk::{env, near, AccountId, BlockHeight, CryptoHash};

use crate::guard::Guard;

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

/// Pre-migration group meta without `migration_method`.
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
}

pub fn migrate() {
    let state = env::state_read::<OldContextConfigs>().expect("failed to read state");

    // Re-write state with the new format.
    // The new `migration_method: Option<String>` field defaults to `None`
    // under borsh serialization (Option discriminant 0 = absent).
    env::state_write(&state);

    for (group_id, _group) in state.groups.iter() {
        env::log_str(&format!(
            "Migrated group `{}` (added migration_method)",
            Repr::new(*group_id)
        ));
    }
}
