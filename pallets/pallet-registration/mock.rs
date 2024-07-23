#![cfg_attr(not(feature = "std"), no_std)]

use crate as pallet_registration;
use crate::RegistrationData;
use crate::{CustomData, CustomEvent};
use crate::{Error, Event};
use frame_support::storage::StorageMap;
use frame_support::{
    construct_runtime, parameter_types,
    traits::{ConstU32, ConstU64, Everything, PalletInfo as FramePalletInfo},
};
use frame_system as system;
use frame_system::offchain::SendTransactionTypes;
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use sp_application_crypto::{ed25519, RuntimePublic};
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_core::{offchain::KeyTypeId, Pair, H256};
use sp_runtime::impl_opaque_keys;
use sp_runtime::testing::UintAuthorityId;
use sp_runtime::{
    app_crypto::{sr25519, RuntimeAppPublic},
    codec::{Decode, Encode, MaxEncodedLen},
    generic::{Era, SignedPayload},
    traits::{
        BlakeTwo256, IdentifyAccount, IdentityLookup, OpaqueKeys, SaturatedConversion, Verify,
    },
    AccountId32, BuildStorage, MultiSignature,
};
use sp_std::collections::btree_map::BTreeMap;
use substrate_validator_set;

use sp_core::offchain::{testing, OffchainWorkerExt};
use sp_io::TestExternalities;

type Block = frame_system::mocking::MockBlock<Test>;

#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    Encode,
    Decode,
    MaxEncodedLen,
    TypeInfo,
    Serialize,
    Deserialize,
    Ord,
    PartialOrd,
)]
pub struct MyAccountId(u64);

impl std::fmt::Display for MyAccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for MyAccountId {
    fn from(value: u64) -> Self {
        MyAccountId(value)
    }
}

impl From<MyAccountId> for sp_runtime::AccountId32 {
    fn from(account: MyAccountId) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&account.0.to_le_bytes());
        Self::new(bytes)
    }
}

impl From<sp_runtime::AccountId32> for MyAccountId {
    fn from(account: sp_runtime::AccountId32) -> Self {
        let bytes: &[u8] = account.as_ref();
        let value = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        MyAccountId(value)
    }
}

impl IdentifyAccount for TestAccountPublic {
    type AccountId = MyAccountId;

    fn into_account(self) -> Self::AccountId {
        MyAccountId(0) // Replace with actual logic if needed
    }
}

impl From<sr25519::Public> for TestAccountPublic {
    fn from(pub_key: sr25519::Public) -> Self {
        TestAccountPublic(pub_key)
    }
}

pub struct MockAccountId32Convert;

impl MockAccountId32Convert {
    fn into_account_id(_account: AccountId32) -> MyAccountId {
        MyAccountId(0) // For testing purposes, always return 0
    }

    fn into_account_id32(_account: MyAccountId) -> AccountId32 {
        AccountId32::new([0; 32]) // For testing purposes, return a zero-filled AccountId32
    }
}

impl From<MockAccountId32Convert> for MyAccountId {
    fn from(_: MockAccountId32Convert) -> Self {
        MyAccountId(0)
    }
}

impl Into<u64> for MockAccountId32Convert {
    fn into(self) -> u64 {
        0 // For testing purposes, always return 0
    }
}

impl frame_system::Config for Test {
    type BaseCallFilter = Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type AccountId = MyAccountId;
    type Nonce = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Block = Block;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = ConstU64<250>;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = sp_runtime::traits::ConstU16<42>;
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;

    // New associated types
    type RuntimeTask = ();
    type SingleBlockMigrations = ();
    type MultiBlockMigrator = ();
    type PreInherents = ();
    type PostInherents = ();
    type PostTransactions = ();
}

parameter_types! {

    pub static Validators: Vec<u64> = vec![1, 2, 3];
    pub static NextValidators: Vec<u64> = vec![1, 2, 3];
    pub static Authorities: Vec<UintAuthorityId> = vec![UintAuthorityId(1), UintAuthorityId(2), UintAuthorityId(3)];
    pub static ForceSessionEnd: bool = false;
    pub static SessionLength: u64 = 2;
    pub static SessionChanged: bool = false;
    pub static TestSessionChanged: bool = false;
    pub static Disabled: bool = false;
    pub static BeforeSessionEndCalled: bool = false;
    pub static ValidatorAccounts: BTreeMap<u64, u64> = BTreeMap::new();
    pub const BlockHashCount: u32 = 250;
    pub const AdminAccount: MyAccountId = MyAccountId(1);
}

impl pallet_session::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type ValidatorId = MyAccountId;
    type ValidatorIdOf = substrate_validator_set::ValidatorOf<Self>;
    type ShouldEndSession = TestShouldEndSession;
    type NextSessionRotation = ();
    type SessionManager = substrate_validator_set::Pallet<Self>;
    type SessionHandler = TestSessionHandler;
    type Keys = MockSessionKeys;
    type WeightInfo = ();
}

type UncheckedExtrinsic = sp_runtime::generic::UncheckedExtrinsic<
    u64,
    RuntimeCall,
    MultiSignature,
    frame_system::CheckNonce<Test>,
>;
pub struct TestShouldEndSession;

impl pallet_session::ShouldEndSession<u64> for TestShouldEndSession {
    fn should_end_session(_now: u64) -> bool {
        false
    }
}

pub struct TestSessionHandler;
impl pallet_session::SessionHandler<MyAccountId> for TestSessionHandler {
    const KEY_TYPE_IDS: &'static [sp_runtime::KeyTypeId] = &[UintAuthorityId::ID];

    fn on_genesis_session<T: OpaqueKeys>(_validators: &[(MyAccountId, T)]) {}
    fn on_new_session<T: OpaqueKeys>(
        _changed: bool,
        _validators: &[(MyAccountId, T)],
        _queued_validators: &[(MyAccountId, T)],
    ) {
    }
    fn on_disabled(_validator_index: u32) {}
    fn on_before_session_ending() {}
}

impl substrate_validator_set::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type AddRemoveOrigin = frame_system::EnsureRoot<Self::AccountId>;
    type MinAuthorities = ConstU32<1>;
    type WeightInfo = ();
}

impl_opaque_keys! {
    pub struct MockSessionKeys {
        pub dummy: UintAuthorityId,
    }
}

construct_runtime!(
    pub enum Test {
        System: frame_system,
        ValidatorSet: substrate_validator_set,
        Session: pallet_session,
        Registration: pallet_registration,
    }
);

impl pallet_registration::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type AuthorityId = AuraId;
    type ValidatorId = MyAccountId;
    type AccountId32Convert = MockAccountId32Convert;
    type Call = RuntimeCall;
    type UnsignedPriority = frame_support::traits::ConstU64<100>;
    type AdminAccount = AdminAccount;
}

impl<LocalCall> frame_system::offchain::CreateSignedTransaction<LocalCall> for Test
where
    RuntimeCall: From<LocalCall>,
    LocalCall: Clone + Encode + Decode + PartialEq + Eq,
{
    fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
        call: Self::RuntimeCall,
        public: Self::Public,
        account: Self::AccountId,
        nonce: Self::Nonce,
    ) -> Option<(
        Self::RuntimeCall,
        <Self::Extrinsic as sp_runtime::traits::Extrinsic>::SignaturePayload,
    )> {
        let period = BlockHashCount::get()
            .checked_next_power_of_two()
            .map(|c| c / 2)
            .unwrap_or(2) as u64;
        let current_block = System::block_number()
            .saturated_into::<u64>()
            .saturating_sub(1);
        let era = Era::mortal(period, current_block);
        let extra = (frame_system::CheckNonce::<Test>::from(nonce),);
        let raw_payload = SignedPayload::new(call, extra)
            .map_err(|e| {
                log::warn!("Unable to create signed payload: {:?}", e);
            })
            .ok()?;
        let signature = raw_payload.using_encoded(|payload| C::sign(payload, public))?;
        let address = account;
        let (call, extra, _) = raw_payload.deconstruct();

        Some((call, (address.into(), signature.into(), extra.0)))
    }
}

impl<LocalCall> frame_system::offchain::SendTransactionTypes<LocalCall> for Test
where
    RuntimeCall: From<LocalCall>,
{
    type OverarchingCall = RuntimeCall;
    type Extrinsic = UncheckedExtrinsic;
}

#[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    TypeInfo,
    Encode,
    Decode,
    MaxEncodedLen,
    Serialize,
    Deserialize,
    Ord,
    PartialOrd,
)]
pub struct TestAccountPublic(sr25519::Public);

impl Default for TestAccountPublic {
    fn default() -> Self {
        TestAccountPublic(sr25519::Public::from_raw([0u8; 32]))
    }
}

impl RuntimeAppPublic for TestAccountPublic {
    type Signature = sr25519::Signature;

    fn all() -> Vec<Self> {
        vec![Self::default()]
    }

    fn generate_pair(seed: Option<Vec<u8>>) -> Self {
        sr25519::Public::generate_pair(KeyTypeId(*b"test"), seed).into()
    }

    fn sign<M: AsRef<[u8]>>(&self, msg: &M) -> Option<Self::Signature> {
        Some(sr25519::Pair::from_seed(&[0u8; 32]).sign(msg.as_ref()))
    }

    const ID: KeyTypeId = KeyTypeId(*b"test");

    fn verify<M: AsRef<[u8]>>(&self, msg: &M, signature: &Self::Signature) -> bool {
        signature.verify(msg.as_ref(), &self.0)
    }

    fn to_raw_vec(&self) -> sp_application_crypto::Vec<u8> {
        self.0.to_vec()
    }
}

impl frame_system::offchain::SigningTypes for Test {
    type Public = TestAccountPublic;
    type Signature = sr25519::Signature;
}

impl From<MyAccountId> for u64 {
    fn from(account: MyAccountId) -> Self {
        account.0
    }
}

impl From<AccountId32> for MockAccountId32Convert {
    fn from(_: AccountId32) -> Self {
        MockAccountId32Convert
    }
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let storage = system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    let mut ext = sp_io::TestExternalities::new(storage);
    ext.execute_with(|| System::set_block_number(1));
    ext
}

#[cfg(test)]
mod tests {
    use super::*;
    // use crate::mock::{new_test_ext, Test};
    use crate::mock::system::Origin;
    use crate::mock::{new_test_ext, Registration, Test};
    use crate::EventStorage;
    use crate::Pallet;
    use crate::ProcessedEvents;
    use crate::ProcessedTransactions;
    use frame_support::{assert_noop, assert_ok};
    use frame_system::RawOrigin;
    use sp_runtime::testing::TestSignature;

    fn create_test_event() -> CustomEvent {
        CustomEvent {
            id: 1,
            data: CustomData {
                event_type: "RegistrationEvent".into(),
                data: RegistrationData {
                    user_id: "user123".into(),
                    username: "testuser".into(),
                    email: "test@example.com".into(),
                },
            },
            timestamp: 1000,
            block_height: 100,
        }
    }

    #[test]
    fn test_submit_multiple_events() {
        new_test_ext().execute_with(|| {
            let event1 = create_test_event();
            let event2 = CustomEvent {
                id: 2,
                ..create_test_event()
            };

            assert_ok!(Registration::submit_encoded_payload(
                RuntimeOrigin::none(),
                event1.encode()
            ));
            assert_ok!(Registration::submit_encoded_payload(
                RuntimeOrigin::none(),
                event2.encode()
            ));

            assert_eq!(Registration::event_storage(event1.id), event1);
            assert_eq!(Registration::event_storage(event2.id), event2);
        });
    }

    #[test]
    fn test_submit_invalid_payload() {
        new_test_ext().execute_with(|| {
            let invalid_payload = vec![0, 1, 2, 3]; // This is not a valid encoded CustomEvent
            assert_noop!(
                Registration::submit_encoded_payload(RuntimeOrigin::none(), invalid_payload),
                Error::<Test>::InvalidPayload
            );
        });
    }

    #[test]
    fn test_manual_fetch() {
        new_test_ext().execute_with(|| {
            let account = MyAccountId(1);
            assert_ok!(Registration::manual_fetch(RuntimeOrigin::signed(account)));
        });
    }

    #[test]
    fn test_remove_event_from_storage2() {
        new_test_ext().execute_with(|| {
            let event = create_test_event();
            let payload = event.encode();

            assert_ok!(Registration::submit_encoded_payload(
                RuntimeOrigin::none(),
                payload.clone()
            ));

            let account = MyAccountId(1);
            assert_ok!(Registration::remove_event_from_storage(
                RuntimeOrigin::signed(account),
                event.id
            ));

            // Check if the event is removed
            assert_eq!(
                Registration::event_storage(event.id),
                CustomEvent::default()
            );
        });
    }

    #[test]
    fn test_process_registration_event() {
        new_test_ext().execute_with(|| {
            let event = create_test_event();
            let payload = event.encode();
            let nonce = 1u64;

            assert_ok!(Registration::process_registration_event(
                RuntimeOrigin::signed(MyAccountId(1)),
                nonce,
                payload
            ));
        });
    }
    #[test]
    fn test_fetch_and_process_events_from_queue() {
        let (offchain, state) = testing::TestOffchainExt::new();
        let mut t = TestExternalities::default();
        t.register_extension(OffchainWorkerExt::new(offchain));

        t.execute_with(|| {
            // Mock the HTTP request
            state.write().expect_request(testing::PendingRequest {
                method: "POST".into(),
                uri: "http://127.0.0.1:5555".into(),
                headers: vec![
                    ("User-Agent".into(), "SubstrateOffchainWorker".into()),
                    ("Content-Type".into(), "application/json".into()),
                ],
                body: br#"{"id":1,"jsonrpc":"2.0","method":"list_all_events","params":[]}"#
                    .to_vec(),
                response: Some(
                    br#"{"result":"{\"events\":[],\"duplicates\":[],\"success\":true}"}"#.to_vec(),
                ),
                sent: true,
                ..Default::default()
            });

            // This test checks if the function doesn't panic
            assert_ok!(Registration::fetch_and_process_events_from_queue());
        });
    }
    #[test]
    fn test_fetch_event_id() {
        let (offchain, state) = testing::TestOffchainExt::new();
        let mut t = TestExternalities::default();
        t.register_extension(OffchainWorkerExt::new(offchain));

        t.execute_with(|| {
            let event_id = 1;

            // Mock the HTTP request
            state.write().expect_request(testing::PendingRequest {
                method: "POST".into(),
                uri: "http://127.0.0.1:5555".into(),
                headers: vec![
                    ("Content-Type".into(), "application/json".into()),
                    ("User-Agent".into(), "SubstrateOffchainWorker".into()),
                ],
                body: br#"{"id":1,"jsonrpc":"2.0","method":"get_event_id","params":[1]}"#.to_vec(),
                response: Some(br#"{"success":true,"event_id":"mocked_event_id"}"#.to_vec()),
                sent: true,
                ..Default::default()
            });

            let result = Registration::fetch_event_id(event_id);
            assert!(result.is_ok(), "fetch_event_id should succeed");
            assert_eq!(result.unwrap(), "mocked_event_id".to_string());
        });
    }

    #[test]
    fn test_event_duplication() {
        new_test_ext().execute_with(|| {
            let event = create_test_event();
            let payload = event.encode();

            // First submission should succeed
            assert_ok!(Registration::submit_encoded_payload(
                RuntimeOrigin::none(),
                payload.clone()
            ));

            // Second submission of the same event should fail due to duplication
            assert_noop!(
                Registration::submit_encoded_payload(RuntimeOrigin::none(), payload.clone()),
                Error::<Test>::DuplicateEvent
            );

            // Verify that the event is stored
            assert_eq!(Registration::event_storage(event.id), event);
        });
    }

    #[test]
    fn test_event_storage() {
        new_test_ext().execute_with(|| {
            let event = CustomEvent {
                id: 1,
                data: CustomData {
                    event_type: "Test".into(),
                    data: RegistrationData {
                        user_id: "user1".into(),
                        username: "testuser".into(),
                        email: "test@example.com".into(),
                    },
                },
                timestamp: 1000,
                block_height: 10,
            };

            // Use the public interface to store the event
            assert_ok!(Registration::submit_encoded_payload(
                RuntimeOrigin::none(),
                event.encode()
            ));

            // Check if the event is stored correctly
            assert_eq!(Registration::event_storage(event.id), event);
        });
    }
    #[test]
    fn test_log_event_processing() {
        new_test_ext().execute_with(|| {
            let event = CustomEvent {
                id: 1,
                data: CustomData {
                    event_type: "Test".into(),
                    data: RegistrationData {
                        user_id: "user1".into(),
                        username: "testuser".into(),
                        email: "test@example.com".into(),
                    },
                },
                timestamp: 1000,
                block_height: 10,
            };

            // This test just ensures the function doesn't panic
            Registration::log_event_processing(&event);

            // Since we can't easily check the log output in a test,
            // we'll just assert that the function completed successfully
            assert!(true);
        });
    }

    #[test]
    fn test_pending_events() {
        new_test_ext().execute_with(|| {
            // Insert a pending event
            crate::PendingEvents::<Test>::insert(1, ());

            // Check if the pending event exists
            assert!(crate::PendingEvents::<Test>::contains_key(1));

            // Optional: Check that a non-existent key returns false
            assert!(!crate::PendingEvents::<Test>::contains_key(2));
        });
    }

    #[test]
    fn test_process_response() {
        let data = r#"[{"asset_id":"BTC","quantity":100}]"#.as_bytes().to_vec();
        assert_ok!(Pallet::<Test>::process_response(data));
    }

    #[test]
    fn test_processed_events() {
        new_test_ext().execute_with(|| {
            ProcessedEvents::<Test>::insert(1, true);
            assert!(ProcessedEvents::<Test>::contains_key(1));
        });
    }

    #[test]
    fn test_remove_event_from_storage() {
        new_test_ext().execute_with(|| {
            let event = CustomEvent {
                id: 1,
                data: CustomData {
                    event_type: "Test".into(),
                    data: RegistrationData {
                        user_id: "user1".into(),
                        username: "testuser".into(),
                        email: "test@example.com".into(),
                    },
                },
                timestamp: 1000,
                block_height: 10,
            };

            EventStorage::<Test>::insert(event.id, event);

            assert_ok!(Pallet::<Test>::remove_event_from_storage(
                RawOrigin::Signed(MyAccountId(1)).into(),
                1
            ));
            assert!(!EventStorage::<Test>::contains_key(1));
        });
    }

    #[test]
    fn test_processed_transactions() {
        new_test_ext().execute_with(|| {
            let payload = vec![0, 1, 2, 3];
            ProcessedTransactions::<Test>::insert(payload.clone(), true);
            assert!(ProcessedTransactions::<Test>::contains_key(payload));
        });
    }

    #[test]
    fn test_store_event_in_mempool() {
        new_test_ext().execute_with(|| {
            let event = CustomEvent {
                id: 1,
                data: CustomData {
                    event_type: "Test".into(),
                    data: RegistrationData {
                        user_id: "user1".into(),
                        username: "testuser".into(),
                        email: "test@example.com".into(),
                    },
                },
                timestamp: 1000,
                block_height: 10,
            };

            assert_ok!(Pallet::<Test>::store_event_in_mempool(event.clone()));
            assert_eq!(EventStorage::<Test>::get(event.id), event);
        });
    }

    #[test]
    fn test_submit_encoded_payload() {
        new_test_ext().execute_with(|| {
            let event = CustomEvent {
                id: 1,
                data: CustomData {
                    event_type: "Test".into(),
                    data: RegistrationData {
                        user_id: "user1".into(),
                        username: "testuser".into(),
                        email: "test@example.com".into(),
                    },
                },
                timestamp: 1000,
                block_height: 10,
            };
            let payload = event.encode();
            assert_ok!(Pallet::<Test>::submit_encoded_payload(
                RawOrigin::None.into(),
                payload
            ));
        });
    }

    #[test]
    fn test_validate_and_process_event() {
        new_test_ext().execute_with(|| {
            let event = CustomEvent {
                id: 1,
                data: CustomData {
                    event_type: "Test".into(),
                    data: RegistrationData {
                        user_id: "user1".into(),
                        username: "testuser".into(),
                        email: "test@example.com".into(),
                    },
                },
                timestamp: 1000,
                block_height: 10,
            };
            assert_ok!(Pallet::<Test>::validate_and_process_event(event));
        });
    }

    #[test]
    fn test_store_event_id() {
        new_test_ext().execute_with(|| {
            assert_ok!(Pallet::<Test>::store_event_id(
                RawOrigin::None.into(),
                "event1".into()
            ));
        });
    }
    #[test]
    fn test_submit_event_with_max_values() {
        new_test_ext().execute_with(|| {
            let event = CustomEvent {
                id: u64::MAX,
                data: CustomData {
                    event_type: "MaxValueEvent".into(),
                    data: RegistrationData {
                        user_id: "user123".into(),
                        username: "maxuser".into(),
                        email: "max@example.com".into(),
                    },
                },
                timestamp: u64::MAX,
                block_height: u64::MAX,
            };
            let payload = event.encode();
            assert_ok!(Pallet::<Test>::submit_encoded_payload(
                RawOrigin::None.into(),
                payload
            ));
            assert_eq!(Registration::event_storage(event.id), event);
        });
    }
    #[test]
    fn test_submit_event_with_zero_values() {
        new_test_ext().execute_with(|| {
            let event = CustomEvent {
                id: 0,
                data: CustomData {
                    event_type: "".into(),
                    data: RegistrationData {
                        user_id: "".into(),
                        username: "".into(),
                        email: "".into(),
                    },
                },
                timestamp: 0,
                block_height: 0,
            };
            let payload = event.encode();
            assert_ok!(Pallet::<Test>::submit_encoded_payload(
                RawOrigin::None.into(),
                payload
            ));
            assert_eq!(Registration::event_storage(event.id), event);
        });
    }
    #[test]
    fn test_remove_nonexistent_event_from_storage() {
        new_test_ext().execute_with(|| {
            let admin_account = MyAccountId(1);
            // Attempt to remove a nonexistent event
            assert_noop!(
                Registration::remove_event_from_storage(
                    RawOrigin::Signed(admin_account).into(),
                    999
                ),
                Error::<Test>::EventNotFound
            );
        });
    }
    //  #[test]
    fn test_event_retrieval() {
        new_test_ext().execute_with(|| {
            let event = create_test_event();
            let payload = event.encode();

            assert_ok!(Registration::submit_encoded_payload(
                RuntimeOrigin::none(),
                payload.clone()
            ));

            // Retrieve the event by ID
            let retrieved_event = Registration::event_storage(event.id);
            assert_eq!(retrieved_event, event);
        });
    }

    #[test]
    fn test_duplicate_event_detection() {
        new_test_ext().execute_with(|| {
            let event = create_test_event();
            let payload = event.encode();

            // First submission should succeed
            assert_ok!(Registration::submit_encoded_payload(
                RuntimeOrigin::none(),
                payload.clone()
            ));

            // Second submission of the same event should fail due to duplication
            assert_noop!(
                Registration::submit_encoded_payload(RuntimeOrigin::none(), payload.clone()),
                Error::<Test>::DuplicateEvent
            );
        });
    }
    #[test]
    fn test_large_payload_submission() {
        new_test_ext().execute_with(|| {
            let large_data = "a".repeat(10_000); // Adjust the size as needed for testing limits
            let event = CustomEvent {
                id: 1,
                data: CustomData {
                    event_type: "LargePayloadEvent".into(),
                    data: RegistrationData {
                        user_id: large_data.clone(),
                        username: large_data.clone(),
                        email: large_data.clone(),
                    },
                },
                timestamp: 1000,
                block_height: 100,
            };

            let payload = event.encode();
            assert_ok!(Registration::submit_encoded_payload(
                RawOrigin::None.into(),
                payload
            ));
            assert_eq!(Registration::event_storage(event.id), event);
        });
    }
    #[test]
    fn test_event_update() {
        new_test_ext().execute_with(|| {
            let event = create_test_event();
            let payload = event.encode();

            // Submit the event
            assert_ok!(Registration::submit_encoded_payload(
                RuntimeOrigin::none(),
                payload.clone()
            ));
            assert_eq!(Registration::event_storage(event.id), event);

            // Update the event
            let updated_event = CustomEvent {
                id: event.id,
                data: CustomData {
                    event_type: "UpdatedEvent".into(),
                    data: RegistrationData {
                        user_id: "updated_user".into(),
                        username: "updated_user".into(),
                        email: "updated@example.com".into(),
                    },
                },
                timestamp: 2000,
                block_height: 200,
            };

            // Use the new update_event method
            assert_ok!(Registration::update_event(
                RuntimeOrigin::signed(MyAccountId(1)),
                event.id,
                updated_event.clone()
            ));
            assert_eq!(Registration::event_storage(updated_event.id), updated_event);
        });
    }

    #[test]
    fn test_authorized_event_removal() {
        new_test_ext().execute_with(|| {
            let event = create_test_event();
            let payload = event.encode();

            // Submit the event
            assert_ok!(Registration::submit_encoded_payload(
                RuntimeOrigin::none(),
                payload.clone()
            ));
            assert_eq!(Registration::event_storage(event.id), event);

            // Authorized user removes the event
            let authorized_account = MyAccountId(1);
            assert_ok!(Registration::remove_event_from_storage(
                RawOrigin::Signed(authorized_account).into(),
                event.id
            ));
            assert_eq!(
                Registration::event_storage(event.id),
                CustomEvent::default()
            );
        });
    }
    #[test]
    fn test_system_stability_under_load() {
        new_test_ext().execute_with(|| {
            for i in 0..1_000 {
                let event = CustomEvent {
                    id: i,
                    data: CustomData {
                        event_type: "LoadTestEvent".into(),
                        data: RegistrationData {
                            user_id: format!("user{}", i),
                            username: format!("testuser{}", i),
                            email: format!("test{}@example.com", i),
                        },
                    },
                    timestamp: 1000,
                    block_height: 100,
                };

                let payload = event.encode();
                assert_ok!(Registration::submit_encoded_payload(
                    RawOrigin::None.into(),
                    payload
                ));
                assert_eq!(Registration::event_storage(event.id), event);
            }
        });
    }
    #[test]
    fn test_submit_event_with_min_values() {
        new_test_ext().execute_with(|| {
            let event = CustomEvent {
                id: u64::MIN,
                data: CustomData {
                    event_type: "".into(),
                    data: RegistrationData {
                        user_id: "".into(),
                        username: "".into(),
                        email: "".into(),
                    },
                },
                timestamp: u64::MIN,
                block_height: u64::MIN,
            };
            let payload = event.encode();
            assert_ok!(Pallet::<Test>::submit_encoded_payload(
                RawOrigin::None.into(),
                payload
            ));
            assert_eq!(Registration::event_storage(event.id), event);
        });
    }
    #[test]
    fn test_only_admin_can_remove_event() {
        new_test_ext().execute_with(|| {
            // Ensure account 1 is treated as an admin
            let admin_account = MyAccountId(1);
            let non_admin_account = MyAccountId(2);

            // Create and submit an event
            let event = create_test_event();
            let payload = event.encode();
            assert_ok!(Registration::submit_encoded_payload(
                RuntimeOrigin::none(),
                payload.clone()
            ));

            // Ensure non-admin cannot remove the event
            assert_noop!(
                Registration::remove_event_from_storage(
                    RawOrigin::Signed(non_admin_account).into(),
                    event.id
                ),
                Error::<Test>::NotAuthorized
            );

            // Ensure admin can remove the event
            assert_ok!(Registration::remove_event_from_storage(
                RawOrigin::Signed(admin_account).into(),
                event.id
            ));

            // Verify the event has been removed by checking if the storage is empty or default value
            assert_eq!(
                Registration::event_storage(event.id),
                CustomEvent::default()
            );
        });
    }
    #[test]
    fn test_stress_submit_events() {
        new_test_ext().execute_with(|| {
            for i in 0..1000 {
                let event = CustomEvent {
                    id: i,
                    data: CustomData {
                        event_type: format!("Event{}", i),
                        data: RegistrationData {
                            user_id: format!("user{}", i),
                            username: format!("user{}", i),
                            email: format!("user{}@example.com", i),
                        },
                    },
                    timestamp: 1000 + i,
                    block_height: 100 + i,
                };
                let payload = event.encode();
                assert_ok!(Pallet::<Test>::submit_encoded_payload(
                    RawOrigin::None.into(),
                    payload
                ));
            }
        });
    }
    #[test]
    fn test_invalid_event_removal() {
        new_test_ext().execute_with(|| {
            let account = MyAccountId(1);
            assert_noop!(
                Registration::remove_event_from_storage(RawOrigin::Signed(account).into(), 999), // Non-existent event ID
                Error::<Test>::EventNotFound
            );
        });
    }
}
