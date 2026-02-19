use calimero_context_config::repr::Repr;
use calimero_context_config::types::{ContextGroupId, ContextId, SignerId};
use near_sdk::ext_contract;

#[ext_contract(config_contract)]
pub trait ConfigContract {
    fn has_member(&self, context_id: Repr<ContextId>, identity: Repr<SignerId>) -> bool;
    fn proxy_register_in_group(
        &mut self,
        context_id: Repr<ContextId>,
        group_id: Repr<ContextGroupId>,
    );
    fn proxy_unregister_from_group(&mut self, context_id: Repr<ContextId>);
}
