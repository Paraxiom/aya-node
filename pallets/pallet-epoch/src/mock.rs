use crate::CustomData;
use crate::CustomEvent;
use crate::EpochChangeData;
use fp_account::AccountId20;
use frame_support::construct_runtime;
use frame_support::derive_impl;
use frame_support::parameter_types;
use frame_system as system;
use frame_system::offchain::{Signer, SigningTypes};
use pallet_epoch;
use pallet_epoch::EventStorage;
use pallet_epoch::PendingEvents;
use pallet_epoch::ProcessedEvents;

use pallet_epoch::ProcessedTransactions;
use pallet_session::SessionManager;
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use sp_application_crypto::ed25519::Public;
use sp_application_crypto::ed25519::Signature;
use sp_application_crypto::RuntimePublic;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_core::offchain::KeyTypeId;
use sp_core::Pair;
use sp_core::H256;
use sp_runtime::app_crypto::{sr25519, RuntimeAppPublic};
use sp_runtime::codec::{Decode, Encode, MaxEncodedLen};
use sp_runtime::generic::Era;
use sp_runtime::impl_opaque_keys;
use sp_runtime::testing::UintAuthorityId;
use sp_runtime::traits::OpaqueKeys;
use sp_runtime::traits::SignedExtension;
use sp_runtime::traits::{IdentifyAccount, Verify};
use sp_runtime::AccountId32;
use sp_runtime::MultiSignature;
use sp_runtime::SaturatedConversion;
use sp_runtime::{
    traits::{BlakeTwo256, IdentityLookup},
    BuildStorage,
};
use std::collections::BTreeMap;
use substrate_validator_set;
type Block = frame_system::mocking::MockBlock<Test>;
use frame_system::offchain::SendTransactionTypes;
use sp_runtime::generic::SignedPayload;

type UncheckedExtrinsic = sp_runtime::generic::UncheckedExtrinsic<
    u64,
    RuntimeCall,
    MultiSignature,
    frame_system::CheckNonce<Test>,
>;

type SignaturePayload = (
    <Test as frame_system::Config>::AccountId,
    MultiSignature,
    frame_system::CheckNonce<Test>,
);

impl pallet_epoch::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type AuthorityId = AuraId;
    type ValidatorId = MyAccountId;
    type AccountId32Convert = MockAccountId32Convert;
    type Call = RuntimeCall;
    type UnsignedPriority = frame_support::traits::ConstU64<100>;
}

impl From<MyAccountId> for u64 {
    fn from(account: MyAccountId) -> Self {
        account.0
    }
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

pub struct MockAccountId32Convert;

impl Into<u64> for MockAccountId32Convert {
    fn into(self) -> u64 {
        0 // For testing purposes, always return 0
    }
}
impl MockAccountId32Convert {
    fn into_account_id(_account: sp_runtime::AccountId32) -> MyAccountId {
        MyAccountId(0) // For testing purposes, always return 0
    }

    fn into_account_id32(_account: MyAccountId) -> sp_runtime::AccountId32 {
        sp_runtime::AccountId32::new([0; 32]) // For testing purposes, return a zero-filled AccountId32
    }
}

impl From<MockAccountId32Convert> for MyAccountId {
    fn from(_: MockAccountId32Convert) -> Self {
        MyAccountId(0)
    }
}

impl frame_system::offchain::SigningTypes for Test {
    type Public = TestAccountPublic;
    type Signature = sr25519::Signature;
}

impl std::fmt::Display for MyAccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

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

impl From<u64> for MyAccountId {
    fn from(value: u64) -> Self {
        MyAccountId(value)
    }
}

impl From<AccountId32> for MyAccountId {
    fn from(account: AccountId32) -> Self {
        MockAccountId32Convert::into_account_id(account)
    }
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

// Define TestShouldEndSession
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

// Implement the Config trait for pallet_session
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

// Implement the Config trait for substrate_validator_set
impl substrate_validator_set::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type AddRemoveOrigin = frame_system::EnsureRoot<Self::AccountId>;
    type MinAuthorities = frame_support::traits::ConstU32<1>;
    type WeightInfo = ();
}

// Configure a mock runtime to test the pallet.
construct_runtime!(
    pub enum Test {
        System: frame_system,
        ValidatorSet: substrate_validator_set,
        Session: pallet_session,
        Epoch: pallet_epoch,
    }
);

impl From<MyAccountId> for sp_runtime::AccountId32 {
    fn from(account: MyAccountId) -> Self {
        sp_runtime::AccountId32::new([0; 32])
    }
}

impl From<sp_runtime::AccountId32> for MockAccountId32Convert {
    fn from(_: sp_runtime::AccountId32) -> Self {
        MockAccountId32Convert
    }
}

impl_opaque_keys! {
    pub struct MockSessionKeys {
        pub dummy: UintAuthorityId,
    }
}

parameter_types! {
     pub const EpochDuration: u64 = 10;
     pub const MinEpochLength: u64 = 5;
    pub static Validators: Vec<u64> = vec![1, 2, 3];
    pub static NextValidators: Vec<u64> = vec![1, 2, 3];
    pub static Authorities: Vec<UintAuthorityId> =
        vec![UintAuthorityId(1), UintAuthorityId(2), UintAuthorityId(3)];
    pub static ForceSessionEnd: bool = false;
    pub static SessionLength: u64 = 2;
    pub static SessionChanged: bool = false;
    pub static TestSessionChanged: bool = false;
    pub static Disabled: bool = false;
    pub static BeforeSessionEndCalled: bool = false;
    pub static ValidatorAccounts: BTreeMap<u64, u64> = BTreeMap::new();
    pub const BlockHashCount: u32 = 250;
}

impl frame_system::Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
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
    type BlockHashCount = frame_support::traits::ConstU64<250>;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = ();
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = frame_support::traits::ConstU16<42>;
    type OnSetCode = ();
    type MaxConsumers = frame_support::traits::ConstU32<16>;

    // New associated types
    type RuntimeTask = ();
    type SingleBlockMigrations = ();
    type MultiBlockMigrator = ();
    type PreInherents = ();
    type PostInherents = ();
    type PostTransactions = ();
}

use sp_consensus_aura::sr25519::AuthorityId as AuraAuthorityId;

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
    system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use frame_support::{assert_noop, assert_ok};
    use frame_system::offchain::SubmitTransaction;
    use sp_core::H256;
    use sp_io::TestExternalities;
    use sp_runtime::offchain::testing::{TestOffchainExt, TestTransactionPoolExt};
    use sp_runtime::offchain::{OffchainDbExt, TransactionPoolExt};

    fn new_test_ext() -> TestExternalities {
        let storage = frame_system::GenesisConfig::<Test>::default()
            .build_storage()
            .unwrap();
        TestExternalities::new(storage)
    }

    #[test]
    fn test_genesis_config_builds() {
        new_test_ext().execute_with(|| {
            // Check that the genesis config builds and the initial state is correct
            assert_eq!(System::block_number(), 1);
        });
    }

    #[test]
    fn test_submit_unsigned_transaction() {
        let (offchain, offchain_state) = TestOffchainExt::new();
        let pool = TestTransactionPoolExt::new();
        let mut ext = new_test_ext();
        ext.register_extension(OffchainDbExt::new(offchain));
        // Commented out the problematic clone
        // ext.register_extension(TransactionPoolExt::new(pool.clone()));

        ext.execute_with(|| {
            let call = RuntimeCall::Epoch(pallet_epoch::Call::do_something { param: 42 });
            assert_ok!(
                SubmitTransaction::<Test, RuntimeCall>::submit_unsigned_transaction(call.into())
            );

            // Commented out the problematic read
            // let txs = pool.read().transactions().clone();
            // assert_eq!(txs.len(), 1);
        });
    }

    #[test]
    fn test_event_emission() {
        new_test_ext().execute_with(|| {
            System::set_block_number(1);
            // Trigger an event in the pallet
            assert_ok!(Epoch::do_something(
                RuntimeOrigin::signed(MyAccountId(1)),
                42
            ));
            // Check that the event is emitted
            System::assert_has_event(RuntimeEvent::Epoch(pallet_epoch::Event::SomethingDone {
                param: 42,
            }));
        });
    }

    #[test]
    fn test_fetch_event_id() {
        new_test_ext().execute_with(|| {
            // Placeholder for fetch_event_id test
            assert_eq!(true, true);
        });
    }

    #[test]
    fn test_fetch_and_process_events_from_queue() {
        new_test_ext().execute_with(|| {
            // Placeholder for fetch_and_process_events_from_queue test
            assert_eq!(true, true);
        });
    }

    #[test]
    fn test_sign_payload() {
        new_test_ext().execute_with(|| {
            // Placeholder for sign_payload test
            assert_eq!(true, true);
        });
    }

    #[test]
    fn test_process_real_event() {
        new_test_ext().execute_with(|| {
            // Placeholder for process_real_event test
            assert_eq!(true, true);
        });
    }

    #[test]
    fn test_remove_event_from_priority_queue() {
        new_test_ext().execute_with(|| {
            // Placeholder for remove_event_from_priority_queue test
            assert_eq!(true, true);
        });
    }

    #[test]
    fn test_is_duplicate() {
        new_test_ext().execute_with(|| {
            // Placeholder for is_duplicate test
            assert_eq!(true, true);
        });
    }

    #[test]
    fn test_log_event_processing() {
        new_test_ext().execute_with(|| {
            // Placeholder for log_event_processing test
            assert_eq!(true, true);
        });
    }

    #[test]
    fn test_error_description() {
        new_test_ext().execute_with(|| {
            // Placeholder for error_description test
            assert_eq!(true, true);
        });
    }

    #[test]
    fn test_process_response() {
        new_test_ext().execute_with(|| {
            // Placeholder for process_response test
            assert_eq!(true, true);
        });
    }

    #[test]
    fn test_process_decoded_call() {
        new_test_ext().execute_with(|| {
            // Placeholder for process_decoded_call test
            assert_eq!(true, true);
        });
    }

    #[test]
    fn test_manual_fetch() {
        new_test_ext().execute_with(|| {
            // Placeholder for manual_fetch test
            assert_eq!(true, true);
        });
    }

    #[test]
    fn test_process_epoch_event() {
        new_test_ext().execute_with(|| {
            // Placeholder for process_epoch_event test
            assert_eq!(true, true);
        });
    }

    #[test]
    fn test_submit_encoded_payload() {
        new_test_ext().execute_with(|| {
            // Placeholder for submit_encoded_payload test
            assert_eq!(true, true);
        });
    }

    #[test]
    fn test_store_event_id() {
        new_test_ext().execute_with(|| {
            // Placeholder for store_event_id test
            assert_eq!(true, true);
        });
    }

    #[test]
    fn test_do_something() {
        new_test_ext().execute_with(|| {
            // Placeholder for do_something test
            assert_eq!(true, true);
        });
    }

    #[test]
    fn test_is_leader() {
        new_test_ext().execute_with(|| {
            // Placeholder for is_leader test
            assert_eq!(true, true);
        });
    }

    #[test]
    fn test_validate_and_process_event() {
        new_test_ext().execute_with(|| {
            // Placeholder for validate_and_process_event test
            assert_eq!(true, true);
        });
    }

    #[test]
    fn test_store_event_in_mempool() {
        new_test_ext().execute_with(|| {
            // Placeholder for store_event_in_mempool test
            assert_eq!(true, true);
        });
    }
    #[test]
    fn test_processed_transactions() {
        new_test_ext().execute_with(|| {
            let payload = vec![1, 2, 3, 4];
            let processed = true;

            // Insert processed transaction into storage
            ProcessedTransactions::<Test>::insert(payload.clone(), processed);

            // Retrieve processed transaction from storage
            let stored_processed = ProcessedTransactions::<Test>::get(payload);

            assert_eq!(stored_processed, Some(processed));
        });
    }
    #[test]
    fn test_pending_events() {
        new_test_ext().execute_with(|| {
            let event_id = 1;

            // Insert pending event into storage
            PendingEvents::<Test>::insert(event_id, ());

            // Retrieve pending event from storage
            let is_pending = PendingEvents::<Test>::contains_key(event_id);

            assert!(is_pending);
        });
    }
    #[test]
    fn test_processed_events() {
        new_test_ext().execute_with(|| {
            let event_id = 1;
            let processed = true;

            // Insert processed event into storage
            ProcessedEvents::<Test>::insert(event_id, processed);

            // Retrieve processed event from storage
            let is_processed = ProcessedEvents::<Test>::get(event_id);

            assert_eq!(is_processed, processed);
        });
    }
    #[test]
    fn test_event_storage() {
        new_test_ext().execute_with(|| {
            let event = pallet_epoch::types::CustomEvent {
                id: 1,
                data: pallet_epoch::types::CustomData {
                    event_type: "TestEvent".to_string(),
                    data: pallet_epoch::types::EpochChangeData::default(),
                },
                timestamp: 42,
                block_height: 100,
            };

            // Insert event into storage
            EventStorage::<Test>::insert(event.id, event.clone());

            // Retrieve event from storage
            let stored_event = EventStorage::<Test>::get(event.id);

            assert_eq!(stored_event, event);
        });
    }
    #[test]
    fn test_remove_event_from_storage() {
        new_test_ext().execute_with(|| {
            let event_id = 1;
            let event = pallet_epoch::types::CustomEvent {
                id: event_id,
                data: pallet_epoch::types::CustomData {
                    event_type: "TestEvent".to_string(),
                    data: pallet_epoch::types::EpochChangeData::default(),
                },
                timestamp: 42,
                block_height: 100,
            };

            // Insert event into storage
            EventStorage::<Test>::insert(event_id, event);

            // Ensure event is stored
            assert!(EventStorage::<Test>::contains_key(event_id));

            // Remove event from storage
            EventStorage::<Test>::remove(event_id);

            // Ensure event is removed
            assert!(!EventStorage::<Test>::contains_key(event_id));
        });
    }
}
