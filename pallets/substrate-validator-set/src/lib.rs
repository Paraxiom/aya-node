#![cfg_attr(not(feature = "std"), no_std)]

mod benchmarking;
mod mock;
mod tests;
pub mod weights;

use sp_std::collections::btree_set::BTreeSet;
use core::{fmt::Debug, str};
use frame_support::{
	ensure,
	pallet_prelude::*,
	traits::{EstimateNextSessionRotation, Get, ValidatorSet, ValidatorSetWithIdentification},
	DefaultNoBound,
};
use sp_core::{blake2_256, crypto::UncheckedFrom, ed25519, Pair};
use sp_std::convert::TryFrom;

use frame_system::pallet_prelude::*;
use log;
pub use pallet::*;
use scale_info::TypeInfo;
use sp_runtime::traits::{Convert, Zero};
use sp_staking::offence::{Offence, OffenceError, ReportOffence};
use sp_std::prelude::*;
pub use weights::*;

pub const LOG_TARGET: &'static str = "runtime::validator-set";

pub struct CardanoAddress {
	payment_part: [u8; 28],
	network_tag: u8,
}
impl Clone for CardanoAddress {
    fn clone(&self) -> Self {
        CardanoAddress {
            payment_part: self.payment_part,
            network_tag: self.network_tag,
        }
    }
}
impl CardanoAddress {
	pub fn new(address: &[u8]) -> Option<Self> {
		if address.len() != 29 {
			return None;
		}
		let mut payment_part = [0u8; 28];
		payment_part.copy_from_slice(&address[0..28]);
		Some(CardanoAddress { payment_part, network_tag: address[28] })
	}

	pub fn to_bytes(&self) -> Vec<u8> {
		let mut result = Vec::with_capacity(29);
		result.extend_from_slice(&self.payment_part);
		result.push(self.network_tag);
		result
	}
}

#[frame_support::pallet()]
pub mod pallet {
	use super::*;

	/// Configure the pallet by specifying the parameters and types on which it
	/// depends.
	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_session::Config {
		/// The Event type.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		/// Origin for adding or removing a validator.
		type AddRemoveOrigin: EnsureOrigin<Self::RuntimeOrigin>;

		/// Minimum number of validators to leave in the validator set during
		/// auto removal.
		/// Initial validator count could be less than this.
		type MinAuthorities: Get<u32>;

		/// Information on runtime weights.
		type WeightInfo: WeightInfo;
	}

	#[pallet::pallet]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	#[pallet::storage]
	#[pallet::getter(fn validators)]
	pub type Validators<T: Config> = StorageValue<_, Vec<T::ValidatorId>, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn offline_validators)]
	pub type OfflineValidators<T: Config> = StorageValue<_, Vec<T::ValidatorId>, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn cardano_nft_addresses)]
	pub type CardanoNftAddresses<T: Config> =
		StorageMap<_, Blake2_128Concat, Vec<u8>, (Vec<u8>, Vec<u8>)>;

	#[pallet::storage]
	#[pallet::getter(fn validator_public_keys)]
	pub type ValidatorPublicKeys<T: Config> = StorageValue<_, Vec<Vec<u8>>, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// New validator addition initiated. Effective in ~2 sessions.
		ValidatorAdditionInitiated(T::ValidatorId),

		/// Validator removal initiated. Effective in ~2 sessions.
		ValidatorRemovalInitiated(T::ValidatorId),
		ValidatorRegistered(T::ValidatorId),
	}

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		/// Target (post-removal) validator count is below the minimum.
		TooLowValidatorCount,
		/// Validator is already in the validator set.
		Duplicate,
		InvalidNFTMintEvent,
		NotEligible,
		InvalidCardanoKey,
		InvalidCardanoAddress,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	#[pallet::genesis_config]
	#[derive(DefaultNoBound)]
	pub struct GenesisConfig<T: Config> {
		pub initial_validators: Vec<<T as pallet_session::Config>::ValidatorId>,
	}

	#[pallet::genesis_build]
	impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
		fn build(&self) {
			assert!(<Validators<T>>::get().is_empty(), "Validators are already initialized!");
			<Validators<T>>::put(&self.initial_validators);
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Add a new validator.
		///
		/// New validator's session keys should be set in Session pallet before
		/// calling this.
		///
		/// The origin can be configured using the `AddRemoveOrigin` type in the
		/// host runtime. Can also be set to sudo/root.
		#[pallet::call_index(0)]
		#[pallet::weight(<T as pallet::Config>::WeightInfo::add_validator())]
		pub fn add_validator(origin: OriginFor<T>, validator_id: T::ValidatorId) -> DispatchResult {
			T::AddRemoveOrigin::ensure_origin(origin)?;

			Self::do_add_validator(validator_id.clone())?;

			Ok(())
		}

		/// Remove a validator.
		///
		/// The origin can be configured using the `AddRemoveOrigin` type in the
		/// host runtime. Can also be set to sudo/root.
		#[pallet::call_index(1)]
		#[pallet::weight(<T as pallet::Config>::WeightInfo::remove_validator())]
		pub fn remove_validator(
			origin: OriginFor<T>,
			validator_id: T::ValidatorId,
		) -> DispatchResult {
			T::AddRemoveOrigin::ensure_origin(origin)?;

			Self::do_remove_validator(validator_id.clone())?;

			Ok(())
		}

		#[pallet::call_index(2)]
		#[pallet::weight(<T as pallet::Config>::WeightInfo::register_validator())]
		pub fn register_validator(
			origin: OriginFor<T>,
			nft_policy_id: Vec<u8>,
			nft_asset_name: Vec<u8>,
			cardano_address: Vec<u8>,
			recipient_address: T::AccountId,
			cardano_private_key: Vec<u8>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
	
			ensure!(
				Self::verify_cardano_nft_owner(
					&cardano_address,
					&nft_policy_id,
					&nft_asset_name,
					&cardano_private_key
				)?,
				Error::<T>::NotEligible
			);
	
			let validator_id = T::ValidatorIdOf::convert(recipient_address.clone())
				.ok_or(Error::<T>::NotEligible)?;
	
			Self::do_add_validator(validator_id.clone())?;
	
			Self::deposit_event(Event::ValidatorRegistered(validator_id));
	
			Ok(())
		}
		

		#[pallet::weight(10_000)]
		pub fn add_nft_address(
			origin: OriginFor<T>,
			cardano_address: Vec<u8>,
			policy_id: Vec<u8>,
			asset_name: Vec<u8>,
		) -> DispatchResult {
			ensure_root(origin)?;
			CardanoNftAddresses::<T>::insert(cardano_address, (policy_id, asset_name));
			Ok(())
		}

		#[pallet::weight(10_000)]
		pub fn remove_nft_address(
			origin: OriginFor<T>,
			cardano_address: Vec<u8>,
		) -> DispatchResult {
			ensure_root(origin)?;
			CardanoNftAddresses::<T>::remove(cardano_address);
			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {
	// pub fn initialize_nft_addresses(addresses: Vec<Vec<u8>>) {
    //     let address_set: BTreeSet<Vec<u8>> = addresses.into_iter().collect();
    //     ValidNftAddresses::<T>::put(address_set);
    // }

    // fn is_valid_nft_address(address: &[u8]) -> bool {
    //     ValidNftAddresses::<T>::get().contains(address)
    // }
	fn private_key_to_public(private_key: &[u8]) -> Option<[u8; 32]> {
		if private_key.len() != 32 {
			return None;
		}
		let seed = private_key.try_into().ok()?;
		let pair = ed25519::Pair::from_seed(&seed);
		Some(pair.public().0)
	}
	pub fn derive_cardano_address(public_key: &[u8], network_tag: u8) -> Option<CardanoAddress> {
		if public_key.len() != 32 {
			return None;
		}
		let ed25519_public = ed25519::Public::try_from(public_key).ok()?;
		let hashed_key = blake2_256(ed25519_public.as_ref());
		let mut payment_part = [0u8; 28];
		payment_part.copy_from_slice(&hashed_key[0..28]);
		Some(CardanoAddress { payment_part, network_tag })
	}

	pub fn verify_cardano_address(address: &CardanoAddress, public_key: &[u8]) -> bool {
		if let Some(derived_address) = Self::derive_cardano_address(public_key, address.network_tag)
		{
			derived_address.payment_part == address.payment_part
		} else {
			false
		}
	}
	fn is_eligible_validator(
		cardano_address: &[u8],
		nft_policy_id: &[u8],
		nft_asset_name: &[u8],
	) -> bool {
		fn is_valid_nft(policy_id: &[u8], asset_name: &[u8]) -> bool {
			let valid_nfts = vec![("policy_id_1", "asset_name_1"), ("policy_id_2", "asset_name_2")];
			let policy_id_str = core::str::from_utf8(policy_id).ok();
			let asset_name_str = core::str::from_utf8(asset_name).ok();

			match (policy_id_str, asset_name_str) {
				(Some(policy_id_str), Some(asset_name_str)) => {
					valid_nfts.contains(&(policy_id_str, asset_name_str))
				},
				_ => false,
			}
		}

		// Check if the Cardano address owns this NFT
		Self::check_nft_ownership(cardano_address, nft_policy_id, nft_asset_name)
			&& is_valid_nft(nft_policy_id, nft_asset_name)
	}
	fn verify_cardano_nft_owner(
		cardano_address: &[u8],
		nft_policy_id: &[u8],
		nft_asset_name: &[u8],
		cardano_private_key: &[u8],
	) -> Result<bool, DispatchError> {
		// First, verify the private key
		let public_key = Self::private_key_to_public(cardano_private_key)
			.ok_or(Error::<T>::InvalidCardanoKey)?;
	
		// Derive address from public key
		let derived_address = Self::derive_cardano_address(&public_key, cardano_address[28])
			.ok_or(Error::<T>::InvalidCardanoAddress)?;
	
		// Check if derived address matches the provided address
		if derived_address.to_bytes() != cardano_address {
			return Err(Error::<T>::InvalidCardanoAddress.into());
		}
	
		// Check if the address is in storage
		let stored_nft = CardanoNftAddresses::<T>::get(cardano_address.to_vec());
	
		match stored_nft {
			Some((stored_policy_id, stored_asset_name)) => {
				// Check if the stored NFT matches the provided NFT
				if stored_policy_id == nft_policy_id && stored_asset_name == nft_asset_name {
					Ok(true)
				} else {
					Ok(false)
				}
			},
			None => Ok(false),
		}
	}
	fn check_nft_ownership(address: &[u8], policy_id: &[u8], asset_name: &[u8]) -> bool {
		let key = address.to_vec();
		if let Some((stored_policy_id, stored_asset_name)) = CardanoNftAddresses::<T>::get(key) {
			stored_policy_id == policy_id && stored_asset_name == asset_name
		} else {
			false
		}
	}

	fn do_add_validator(
		validator_id: <T as pallet_session::Config>::ValidatorId,
	) -> DispatchResult {
		ensure!(!<Validators<T>>::get().contains(&validator_id), Error::<T>::Duplicate);
		<Validators<T>>::mutate(|v| v.push(validator_id.clone()));

		Self::deposit_event(Event::ValidatorAdditionInitiated(validator_id.clone()));
		log::debug!(target: LOG_TARGET, "Validator addition initiated.");

		Ok(())
	}

	fn do_remove_validator(
		validator_id: <T as pallet_session::Config>::ValidatorId,
	) -> DispatchResult {
		let mut validators = <Validators<T>>::get();

		// Ensuring that the post removal, target validator count doesn't go
		// below the minimum.
		ensure!(
			validators.len().saturating_sub(1) as u32 >= T::MinAuthorities::get(),
			Error::<T>::TooLowValidatorCount
		);

		validators.retain(|v| *v != validator_id);

		<Validators<T>>::put(validators);

		Self::deposit_event(Event::ValidatorRemovalInitiated(validator_id.clone()));
		log::debug!(target: LOG_TARGET, "Validator removal initiated.");

		Ok(())
	}

	// Adds offline validators to a local cache for removal on new session.
	fn mark_for_removal(validator_id: <T as pallet_session::Config>::ValidatorId) {
		<OfflineValidators<T>>::mutate(|v| v.push(validator_id));
		log::debug!(target: LOG_TARGET, "Offline validator marked for auto removal.");
	}

	// Removes offline validators from the validator set and clears the offline
	// cache. It is called in the session change hook and removes the validators
	// who were reported offline during the session that is ending. We do not
	// check for `MinAuthorities` here, because the offline validators will not
	// produce blocks and will have the same overall effect on the runtime.
	fn remove_offline_validators() {
		let validators_to_remove = <OfflineValidators<T>>::get();

		// Delete from active validator set.
		<Validators<T>>::mutate(|vs| vs.retain(|v| !validators_to_remove.contains(v)));
		log::debug!(
			target: LOG_TARGET,
			"Initiated removal of {:?} offline validators.",
			validators_to_remove.len()
		);

		// Clear the offline validator list to avoid repeated deletion.
		<OfflineValidators<T>>::put(Vec::<T::ValidatorId>::new());
	}
}

// Provides the new set of validators to the session module when session is
// being rotated.
impl<T: Config> pallet_session::SessionManager<T::ValidatorId> for Pallet<T> {
	// Plan a new session and provide new validator set.
	fn new_session(_new_index: u32) -> Option<Vec<T::ValidatorId>> {
		// Remove any offline validators. This will only work when the runtime
		// also has the im-online pallet.
		Self::remove_offline_validators();

		log::debug!(target: LOG_TARGET, "New session called; updated validator set provided.");

		Some(Self::validators())
	}

	fn end_session(_end_index: u32) {}

	fn start_session(_start_index: u32) {}
}

impl<T: Config> EstimateNextSessionRotation<BlockNumberFor<T>> for Pallet<T> {
	fn average_session_length() -> BlockNumberFor<T> {
		Zero::zero()
	}

	fn estimate_current_session_progress(
		_now: BlockNumberFor<T>,
	) -> (Option<sp_runtime::Permill>, sp_weights::Weight) {
		(None, Zero::zero())
	}

	fn estimate_next_session_rotation(
		_now: BlockNumberFor<T>,
	) -> (Option<BlockNumberFor<T>>, sp_weights::Weight) {
		(None, Zero::zero())
	}
}

// Implementation of Convert trait to satisfy trait bounds in session pallet.
// Here it just returns the same ValidatorId.
pub struct ValidatorOf<T>(sp_std::marker::PhantomData<T>);

impl<T: Config>
	Convert<
		<T as pallet_session::Config>::ValidatorId,
		Option<<T as pallet_session::Config>::ValidatorId>,
	> for ValidatorOf<T>
{
	fn convert(
		account: <T as pallet_session::Config>::ValidatorId,
	) -> Option<<T as pallet_session::Config>::ValidatorId> {
		Some(account)
	}
}

impl<T: Config> ValidatorSet<T::ValidatorId> for Pallet<T> {
	type ValidatorId = <T as pallet_session::Config>::ValidatorId;
	type ValidatorIdOf = ValidatorOf<T>;

	fn session_index() -> sp_staking::SessionIndex {
		pallet_session::Pallet::<T>::current_index()
	}

	fn validators() -> Vec<T::ValidatorId> {
		pallet_session::Pallet::<T>::validators()
	}
}

impl<T: Config> ValidatorSetWithIdentification<T::ValidatorId> for Pallet<T> {
	type Identification = <T as pallet_session::Config>::ValidatorId;
	type IdentificationOf = ValidatorOf<T>;
}

// Offence reporting and unresponsiveness management.
// This is for the ImOnline pallet integration.
impl<
		T: Config,
		O: Offence<(
			<T as pallet_session::Config>::ValidatorId,
			<T as pallet_session::Config>::ValidatorId,
		)>,
	>
	ReportOffence<
		T::AccountId,
		(<T as pallet_session::Config>::ValidatorId, <T as pallet_session::Config>::ValidatorId),
		O,
	> for Pallet<T>
{
	fn report_offence(_reporters: Vec<T::AccountId>, offence: O) -> Result<(), OffenceError> {
		let offenders = offence.offenders();

		for (v, _) in offenders.into_iter() {
			Self::mark_for_removal(v);
		}

		Ok(())
	}

	fn is_known_offence(
		_offenders: &[(T::ValidatorId, T::ValidatorId)],
		_time_slot: &O::TimeSlot,
	) -> bool {
		false
	}
}
