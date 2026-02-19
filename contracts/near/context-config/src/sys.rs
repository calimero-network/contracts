use core::time;

use calimero_context_config::{SystemRequest, Timestamp};
use near_sdk::{env, near, Gas, NearToken, Promise};

use crate::{parse_input, ContextConfigs, ContextConfigsExt};

mod migrations;

const MIN_VALIDITY_THRESHOLD_MS: Timestamp = 5_000;

#[near]
impl ContextConfigs {
    #[private]
    pub fn set(&mut self) {
        parse_input!(request);

        match request {
            SystemRequest::SetValidityThreshold { threshold_ms } => {
                self.set_validity_threshold_ms(threshold_ms);
            }
        }
    }

    #[private]
    pub fn erase(&mut self) {
        env::log_str(&format!(
            "Pre-erase storage usage: {}",
            env::storage_usage()
        ));

        env::log_str("Erasing contract");

        for (_, mut context) in self.contexts.drain() {
            let _ignored = context.application.into_inner();
            context.members.into_inner().clear();
            context.member_nonces.clear();
            let proxy = context.proxy.into_inner();

            let _is_sent_on_drop = Promise::new(proxy).function_call(
                "nuke".to_owned(),
                vec![],
                NearToken::default(),
                Gas::from_tgas(1),
            );
        }

        self.next_proxy_id = 0;
        self.proxy_code.set(None);
        self.proxy_code_hash.set(None);

        for (_, mut group) in self.groups.drain() {
            group.admins.clear();
            group.admin_nonces.clear();
            group.members.clear();
            group.approved_registrations.clear();
            group.context_ids.clear();
        }
        self.context_group_refs.clear();

        env::log_str(&format!(
            "Post-erase storage usage: {}",
            env::storage_usage()
        ));
    }

    #[private]
    pub fn set_proxy_code(&mut self) {
        let input = env::input().expect("Expected proxy code");
        let code_hash = env::sha256(&input);
        let code_hash_hex = hex::encode(code_hash.clone());

        env::log_str(&format!("Proxy code hash: `{}`", code_hash_hex));

        self.proxy_code_hash.set(Some(
            code_hash
                .try_into()
                .expect("Infallible conversion: SHA256 hash should be always 32 bytes long."),
        ));
        self.proxy_code.set(Some(input));
    }

    /// Retrieves a hash for the proxy contract if it exists.
    /// If the proxy code is not set, returns an empty string.
    ///
    /// # Returns
    /// * a hex-encoded string containing the hash of the proxy code.
    /// * an empty string if the proxy code hash is not set.
    pub fn get_proxy_code_hash(&self) -> String {
        if let Some(proxy_code_hash) = self.proxy_code_hash.get() {
            hex::encode(proxy_code_hash)
        } else {
            String::new()
        }
    }
}

impl ContextConfigs {
    fn set_validity_threshold_ms(&mut self, validity_threshold_ms: Timestamp) {
        if validity_threshold_ms < MIN_VALIDITY_THRESHOLD_MS {
            env::panic_str("invalid validity threshold");
        }

        self.config.validity_threshold_ms = validity_threshold_ms;

        env::log_str(&format!(
            "Set validity threshold to `{:?}`",
            time::Duration::from_millis(validity_threshold_ms)
        ));
    }
}
