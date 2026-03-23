#![allow(unused_crate_dependencies, reason = "False positives")]
#![allow(
    clippy::multiple_inherent_impl,
    reason = "Needed to separate NEAR functionality"
)]

use calimero_context_config::types::{
    AppKey, Application, ContextGroupId, ContextId, ContextIdentity, SignerId,
};
use calimero_context_config::Timestamp;
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::{IterableMap, IterableSet, LazyOption};
use near_sdk::{near, AccountId, BlockHeight, BorshStorageKey, CryptoHash};

pub mod group_invitation;
pub mod invitation;

mod guard;
mod mutate;
mod query;
mod sys;

use guard::Guard;

const DEFAULT_VALIDITY_THRESHOLD_MS: Timestamp = 10_000;

#[derive(Debug)]
#[near(contract_state)]
pub struct ContextConfigs {
    contexts: IterableMap<ContextId, Context>,
    config: Config,
    proxy_code: LazyOption<Vec<u8>>,
    proxy_code_hash: LazyOption<CryptoHash>,
    next_proxy_id: u64,
    groups: IterableMap<ContextGroupId, OnChainGroupMeta>,
    context_group_refs: IterableMap<ContextId, ContextGroupId>,
}

#[derive(Debug)]
#[near(serializers = [borsh])]
struct Config {
    validity_threshold_ms: Timestamp,
}

#[derive(Debug)]
#[near(serializers = [borsh])]
struct Context {
    pub application: Guard<Application<'static>>,
    pub members: Guard<IterableSet<ContextIdentity>>,
    pub member_nonces: IterableMap<ContextIdentity, u64>,
    pub proxy: Guard<AccountId>,
    /// A set of used open invitation signatures.
    pub used_open_invitations: Guard<IterableSet<CryptoHash>>,
    /// A map that stores pending commitments for the given context.
    pub commitments_open_invitations: IterableMap<CryptoHash, BlockHeight>,
    pub group_id: Option<ContextGroupId>,
}

/// Bitfield constants for group member capabilities.
#[derive(Copy, Clone, Debug)]
pub struct MemberCapabilities;

impl MemberCapabilities {
    pub const CAN_CREATE_CONTEXT: u32 = 1 << 0;
    pub const CAN_INVITE_MEMBERS: u32 = 1 << 1;
    pub const CAN_JOIN_OPEN_CONTEXTS: u32 = 1 << 2;
}

/// Visibility mode for a context within a group.
#[derive(
    Copy, BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Default, Serialize, Deserialize,
)]
#[borsh(crate = "::near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub enum VisibilityMode {
    #[default]
    Open,
    Restricted,
}

/// Convert from SDK VisibilityMode to contract VisibilityMode.
impl From<calimero_context_config::VisibilityMode> for VisibilityMode {
    fn from(mode: calimero_context_config::VisibilityMode) -> Self {
        match mode {
            calimero_context_config::VisibilityMode::Open => VisibilityMode::Open,
            calimero_context_config::VisibilityMode::Restricted => VisibilityMode::Restricted,
        }
    }
}

/// Stores the visibility mode and creator of a context within a group.
#[derive(Copy, BorshSerialize, BorshDeserialize, Clone, Debug)]
#[borsh(crate = "::near_sdk::borsh")]
pub struct VisibilityInfo {
    pub mode: VisibilityMode,
    pub creator: SignerId,
}

/// Structured NEP-297 event emitted when an admin force-joins a restricted
/// context they are not on the allowlist for.
#[derive(Debug, Serialize)]
#[serde(crate = "near_sdk::serde")]
pub struct AdminContextJoinEvent {
    pub group_id: String,
    pub context_id: String,
    pub admin: String,
}

impl AdminContextJoinEvent {
    pub fn emit(&self) {
        #[derive(Serialize)]
        #[serde(crate = "near_sdk::serde")]
        struct EventWrapper<'a> {
            standard: &'static str,
            version: &'static str,
            event: &'static str,
            data: &'a AdminContextJoinEvent,
        }

        let event = EventWrapper {
            standard: "calimero_groups",
            version: "1.0.0",
            event: "admin_context_join",
            data: self,
        };

        let json = near_sdk::serde_json::to_string(&event).expect("event serialization");
        near_sdk::env::log_str(&format!("EVENT_JSON:{json}"));
    }
}

#[derive(Debug)]
#[near(serializers = [borsh])]
pub struct OnChainGroupMeta {
    pub app_key: AppKey,
    pub target_application: Application<'static>,
    pub admins: IterableSet<SignerId>,
    pub admin_nonces: IterableMap<SignerId, u64>,
    pub members: IterableSet<SignerId>,
    pub approved_registrations: IterableSet<ContextId>,
    /// Forward index: contexts that belong to this group.
    /// Enables O(k) pagination in `group_contexts` where k is this group's
    /// context count, instead of scanning the global `context_group_refs` map.
    pub context_ids: IterableSet<ContextId>,
    pub invitation_commitments: IterableMap<CryptoHash, BlockHeight>,
    pub used_invitations: IterableSet<CryptoHash>,
    /// Maps (signer_id, context_id) -> context_identity for group-authorized joins.
    /// Populated by join_context_via_group and consumed during cascading removals.
    pub member_contexts: IterableMap<(SignerId, ContextId), ContextIdentity>,
    /// Optional migration method name for lazy upgrades (e.g. "migrate_v1_to_v2").
    /// Set by `set_group_target` and read by peer nodes during group sync.
    pub migration_method: Option<String>,
    /// Per-member capability bitfields.
    pub member_capabilities: IterableMap<SignerId, u32>,
    /// Visibility info per context (mode + creator).
    pub context_visibility: IterableMap<ContextId, VisibilityInfo>,
    /// Allowlist entries: (context_id, signer_id) -> () for restricted contexts.
    pub context_allowlists: IterableMap<(ContextId, SignerId), ()>,
    /// Default capability bits assigned to new members.
    pub default_member_capabilities: u32,
    /// Default visibility mode for newly created contexts in this group.
    pub default_context_visibility: VisibilityMode,
}

#[derive(Copy, Clone, Debug, BorshSerialize, BorshDeserialize, BorshStorageKey)]
#[borsh(crate = "::near_sdk::borsh", use_discriminant = true)]
#[repr(u8)]
enum Prefix {
    Contexts = 1,
    Members(ContextId) = 2,
    Privileges(PrivilegeScope) = 3,
    ProxyCode = 4,
    ProxyCodeHash = 5,
    MemberNonces(ContextId) = 6,
    UsedOpenInvitations(ContextId) = 7,
    CommitmentsOpenInvitations(ContextId) = 8,
    Groups = 9,
    GroupAdmins(ContextGroupId) = 10,
    ContextGroupRefs = 11,
    GroupAdminNonces(ContextGroupId) = 12,
    GroupMembers(ContextGroupId) = 13,
    GroupApprovedRegistrations(ContextGroupId) = 14,
    GroupContextIds(ContextGroupId) = 15,
    GroupInvitationCommitments(ContextGroupId) = 16,
    GroupUsedInvitations(ContextGroupId) = 17,
    GroupMemberContexts(ContextGroupId) = 18,
    GroupMemberCapabilities(ContextGroupId) = 19,
    GroupContextVisibility(ContextGroupId) = 20,
    GroupContextAllowlists(ContextGroupId) = 21,
}

#[derive(Copy, Clone, Debug)]
#[near(serializers = [borsh])]
enum PrivilegeScope {
    Context(ContextId, ContextPrivilegeScope),
}

#[derive(Copy, Clone, Debug)]
#[near(serializers = [borsh])]
enum ContextPrivilegeScope {
    Application,
    MemberList,
    Proxy,
}

impl Default for ContextConfigs {
    fn default() -> Self {
        Self {
            contexts: IterableMap::new(Prefix::Contexts),
            config: Config {
                validity_threshold_ms: DEFAULT_VALIDITY_THRESHOLD_MS,
            },
            proxy_code: LazyOption::new(Prefix::ProxyCode, None),
            proxy_code_hash: LazyOption::new(Prefix::ProxyCodeHash, None),
            next_proxy_id: 0,
            groups: IterableMap::new(Prefix::Groups),
            context_group_refs: IterableMap::new(Prefix::ContextGroupRefs),
        }
    }
}

macro_rules! _parse_input {
    ($input:ident $(: $input_ty:ty)?) => {
        let $input = ::near_sdk::env::input().unwrap_or_default();

        let $input $(: $input_ty )? = ::near_sdk::serde_json::from_slice(&$input).expect("failed to parse input");
    };
}

use _parse_input as parse_input;
