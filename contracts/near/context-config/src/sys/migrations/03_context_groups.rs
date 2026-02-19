use std::io;

use calimero_context_config::repr::Repr;
use calimero_context_config::types::{Application, ContextGroupId, ContextId, ContextIdentity};
use near_sdk::store::{IterableMap, IterableSet, LazyOption};
use near_sdk::{env, near, AccountId, BlockHeight, CryptoHash};

use crate::guard::Guard;
use crate::{Config, OnChainGroupMeta, Prefix};

#[derive(Debug)]
#[near(serializers = [borsh])]
pub struct OldContextConfigs {
    contexts: IterableMap<ContextId, OldContext>,
    config: Config,
    proxy_code: LazyOption<Vec<u8>>,
    proxy_code_hash: LazyOption<CryptoHash>,
    next_proxy_id: u64,
    #[borsh(deserialize_with = "skipped_groups")]
    groups: IterableMap<ContextGroupId, OnChainGroupMeta>,
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
) -> Result<IterableMap<ContextGroupId, OnChainGroupMeta>, io::Error> {
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
