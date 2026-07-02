//! Device-flow support adapters.

use lore_auth_core::{CoreError, ports::DeviceCodeGenerator};

#[derive(Debug, Default)]
pub struct UuidDeviceCodeGenerator;

impl DeviceCodeGenerator for UuidDeviceCodeGenerator {
    fn device_code(&self) -> Result<String, CoreError> {
        Ok([
            uuid::Uuid::new_v4().as_simple().to_string(),
            uuid::Uuid::new_v4().as_simple().to_string(),
        ]
        .join(""))
    }

    fn user_code(&self) -> Result<String, CoreError> {
        let raw = uuid::Uuid::new_v4().as_simple().to_string();
        let code = raw[..8].to_ascii_uppercase();
        Ok(format!("{}-{}", &code[..4], &code[4..]))
    }
}
