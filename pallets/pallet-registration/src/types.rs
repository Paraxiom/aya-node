use alloc::string::String;
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use sp_io::hashing::blake2_256;
use sp_runtime::codec::{Decode, Encode};
use sp_runtime::traits::BlakeTwo256;
use sp_runtime::traits::Hash;
use sp_std::prelude::*;

#[derive(
    Default, Deserialize, Serialize, Encode, Decode, Clone, Debug, PartialEq, Eq, TypeInfo,
)]
pub struct CustomEvent {
    pub id: u64,
    pub data: CustomData,
    pub timestamp: u64,
    pub block_height: u64,
}

impl CustomEvent {
    pub fn is_valid(&self) -> bool {
        self.timestamp != 0 && self.block_height != 0
    }

    pub fn hash_without_timestamp(&self) -> [u8; 32] {
        let mut encoded_data = self.id.encode();
        encoded_data.extend(self.data.encode());
        encoded_data.extend(self.block_height.encode());
        BlakeTwo256::hash_of(&encoded_data).into()
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut encoded_data = self.data.event_type.encode();
        encoded_data.extend(self.data.encode());
        blake2_256(&encoded_data)
    }
}

#[derive(
    Default, Deserialize, Serialize, Encode, Decode, Clone, Debug, PartialEq, Eq, TypeInfo,
)]
pub struct CustomData {
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: RegistrationData,
}

impl CustomData {
    pub fn hash(&self) -> [u8; 32] {
        let mut encoded_data = self.event_type.encode();
        encoded_data.extend(self.data.encode());
        blake2_256(&encoded_data)
    }
}

#[derive(
    Default, Deserialize, Serialize, Encode, Decode, Clone, Debug, PartialEq, Eq, TypeInfo,
)]
pub struct RegistrationData {
    pub user_id: String,
    pub username: String,
    pub email: String,
}

impl RegistrationData {
    pub fn hash(&self) -> [u8; 32] {
        let mut encoded_data = self.user_id.encode();
        encoded_data.extend(self.username.encode());
        encoded_data.extend(self.email.encode());
        blake2_256(&encoded_data)
    }
}
