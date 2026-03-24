use std::io;

use calimero_context_config::repr::Repr;
use calimero_context_config::types::{
    AppKey, Application, ContextGroupId, ContextId, ContextIdentity, SignerId,
};
use near_sdk::store::{IterableMap, IterableSet, LazyOption};
use near_sdk::{env, near, AccountId, BlockHeight, CryptoHash};

use crate::guard::Guard;
use crate::{Config, Prefix};

/// Group meta as it existed at migration 03 time (7 fields only).
#[derive(Debug)]
#[near(serializers = [borsh])]
struct OnChainGroupMeta03 {
    pub app_key: AppKey,
    pub target_application: Application<'static>,
    pub admins: IterableSet<SignerId>,
    pub admin_nonces: IterableMap<SignerId, u64>,
    pub members: IterableSet<SignerId>,
    pub approved_registrations: IterableSet<ContextId>,
    pub context_ids: IterableSet<ContextId>,
}

#[derive(Debug)]
#[near(serializers = [borsh])]
pub struct OldContextConfigs {
    contexts: IterableMap<ContextId, OldContext>,
    config: Config,
    proxy_code: LazyOption<Vec<u8>>,
    proxy_code_hash: LazyOption<CryptoHash>,
    next_proxy_id: u64,
    #[borsh(deserialize_with = "skipped_groups")]
    groups: IterableMap<ContextGroupId, OnChainGroupMeta03>,
    #[borsh(deserialize_with = "skipped_refs")]
    context_group_refs: IterableMap<ContextId, ContextGroupId>,
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
    #[borsh(deserialize_with = "skipped_group_id")]
    pub group_id: Option<ContextGroupId>,
}

#[expect(clippy::unnecessary_wraps, reason = "borsh needs this")]
fn skipped_groups<R: io::Read>(
    _reader: &mut R,
) -> Result<IterableMap<ContextGroupId, OnChainGroupMeta03>, io::Error> {
    Ok(IterableMap::new(Prefix::Groups))
}

#[expect(clippy::unnecessary_wraps, reason = "borsh needs this")]
fn skipped_refs<R: io::Read>(
    _reader: &mut R,
) -> Result<IterableMap<ContextId, ContextGroupId>, io::Error> {
    Ok(IterableMap::new(Prefix::ContextGroupRefs))
}

#[expect(clippy::unnecessary_wraps, reason = "borsh needs this")]
fn skipped_group_id<R: io::Read>(
    _reader: &mut R,
) -> Result<Option<ContextGroupId>, io::Error> {
    Ok(None)
}

pub fn migrate() {
    let mut state = env::state_read::<OldContextConfigs>().expect("failed to read state");

    for (context_id, _context) in state.contexts.iter_mut() {
        env::log_str(&format!(
            "Migrating context `{}` (adding group_id=None)",
            Repr::new(*context_id)
        ));
    }

    env::state_write(&state);
}
