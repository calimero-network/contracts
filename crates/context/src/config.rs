use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContextConfig {
    pub relayer: Url,
}
