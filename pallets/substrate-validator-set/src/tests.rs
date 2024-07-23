#![cfg(test)]

use super::*;
use crate::mock::{authorities, new_test_ext, RuntimeOrigin, Session, Test, ValidatorSet};
use frame_support::{assert_noop, assert_ok, pallet_prelude::*};
use pallet_session::SessionManager;
use sp_runtime::testing::UintAuthorityId;
use sp_runtime::traits::BadOrigin;
use frame_system::Origin;
use frame_system::RawOrigin;


#[test]
fn test_real_cardano_address_verification() {
    new_test_ext().execute_with(|| {
        let private_key = ed25519::Pair::generate().0.to_raw_vec();
        let public_key = ValidatorSet::private_key_to_public(&private_key).unwrap();
        let cardano_address = ValidatorSet::derive_cardano_address(&public_key, 1).unwrap();
        let cardano_address_bytes = cardano_address.to_bytes();

        let nft_policy_id = vec![1, 2, 3, 4];
        let nft_asset_name = vec![5, 6, 7, 8];

        // Add the NFT to storage
        assert_ok!(ValidatorSet::add_nft_address(
            RawOrigin::Root.into(),
            cardano_address_bytes.clone(),
            nft_policy_id.clone(),
            nft_asset_name.clone()
        ));

        assert!(ValidatorSet::verify_cardano_nft_owner(
            &cardano_address_bytes,
            &nft_policy_id,
            &nft_asset_name,
            &private_key
        ).unwrap());
    });
}

#[test]
fn it_rotates_sessions() {
	new_test_ext().execute_with(|| {
		let validator_id = 4;
		assert_ok!(ValidatorSet::add_validator(RawOrigin::Root.into(), validator_id));
		assert!(ValidatorSet::validators().contains(&validator_id));

		// Simulate session end
		ValidatorSet::end_session(0);
		ValidatorSet::start_session(1);

		// Ensure the new session includes the added validator
		assert!(ValidatorSet::validators().contains(&validator_id));
	});
}

#[test]
fn test_register_validator() {
    new_test_ext().execute_with(|| {
        let private_key = ed25519::Pair::generate().0.to_raw_vec();
        let public_key = ValidatorSet::private_key_to_public(&private_key).unwrap();
        let cardano_address = ValidatorSet::derive_cardano_address(&public_key, 1).unwrap();
        let cardano_address_bytes = cardano_address.to_bytes();

        let nft_policy_id = vec![1, 2, 3, 4];
        let nft_asset_name = vec![5, 6, 7, 8];
        let recipient_address = 4u64.into(); // Changed from 1 to 4 to ensure it's not in the initial set

        // Add the NFT to storage
        assert_ok!(ValidatorSet::add_nft_address(
            RawOrigin::Root.into(),
            cardano_address_bytes.clone(),
            nft_policy_id.clone(),
            nft_asset_name.clone()
        ));

        // Ensure the validator is not already in the set
        assert!(!<Validators<Test>>::get().contains(&recipient_address));

        // Register the validator
        assert_ok!(ValidatorSet::register_validator(
            RuntimeOrigin::signed(1),
            nft_policy_id,
            nft_asset_name,
            cardano_address_bytes,
            recipient_address,
            private_key,
        ));

        // Check if the validator was added
        assert!(<Validators<Test>>::get().contains(&recipient_address));
    });
}

#[test]
fn it_fails_to_register_invalid_validator() {
    new_test_ext().execute_with(|| {
        let private_key = vec![0; 32]; // Invalid key
        let public_key = ValidatorSet::private_key_to_public(&private_key).unwrap();
        let cardano_address = ValidatorSet::derive_cardano_address(&public_key, 1).unwrap().to_bytes();
        let nft_policy_id = vec![1, 2, 3, 4];
        let nft_asset_name = vec![5, 6, 7, 8];
        let recipient_address = 4u64.into();

        // Add the NFT to storage to pass the NFT ownership check
        assert_ok!(ValidatorSet::add_nft_address(
            RawOrigin::Root.into(),
            cardano_address.clone(),
            nft_policy_id.clone(),
            nft_asset_name.clone()
        ));

        // Attempt to register the validator with invalid address
        let invalid_address = vec![9; 29]; // Invalid address
        let result = ValidatorSet::register_validator(
            RuntimeOrigin::signed(1),
            nft_policy_id.clone(),
            nft_asset_name.clone(),
            invalid_address.clone(),
            recipient_address,
            private_key.clone()
        );

        // Print the error for debugging
        println!("Error: {:?}", result);

        // Check each step of the verification process
        let verify_result = ValidatorSet::verify_cardano_nft_owner(
            &invalid_address,
            &nft_policy_id,
            &nft_asset_name,
            &private_key
        );
        println!("Verify result: {:?}", verify_result);

        assert_noop!(
            result,
            Error::<Test>::InvalidCardanoAddress
        );
    });
}

#[test]
fn it_removes_validator() {
	new_test_ext().execute_with(|| {
		let validator_id = 1;
		// Ensure initial state is clean
		if !ValidatorSet::validators().contains(&validator_id) {
			assert_ok!(ValidatorSet::add_validator(RawOrigin::Root.into(), validator_id));
		}
		assert!(ValidatorSet::validators().contains(&validator_id));

		assert_ok!(ValidatorSet::remove_validator(RawOrigin::Root.into(), validator_id));
		assert!(!ValidatorSet::validators().contains(&validator_id));
	});
}

#[test]
fn simple_setup_should_work() {
	new_test_ext().execute_with(|| {
		assert_eq!(authorities(), vec![UintAuthorityId(1), UintAuthorityId(2), UintAuthorityId(3)]);
		assert_eq!(ValidatorSet::validators(), vec![1u64, 2u64, 3u64]);
		assert_eq!(Session::validators(), vec![1, 2, 3]);
	});
}

#[test]
fn add_validator_updates_validators_list() {
	new_test_ext().execute_with(|| {
		assert_ok!(ValidatorSet::add_validator(RawOrigin::Root.into(), 4));
		assert_eq!(ValidatorSet::validators(), vec![1u64, 2u64, 3u64, 4u64])
	});
}

#[test]
fn remove_validator_updates_validators_list() {
	new_test_ext().execute_with(|| {
		assert_ok!(ValidatorSet::remove_validator(RawOrigin::Root.into(), 2));
		assert_eq!(ValidatorSet::validators(), &[1, 3]);
		// Add validator again
		assert_ok!(ValidatorSet::add_validator(RawOrigin::Root.into(), 2));
		assert_eq!(ValidatorSet::validators(), &[1, 3, 2]);
	});
}

#[test]
fn add_validator_fails_with_invalid_origin() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ValidatorSet::add_validator(RuntimeOrigin::signed(1), 4),
            DispatchError::BadOrigin
        );
    });
}

#[test]
fn remove_validator_fails_with_invalid_origin() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ValidatorSet::remove_validator(RuntimeOrigin::signed(1), 4),
            DispatchError::BadOrigin
        );
    });
}

#[test]
fn duplicate_check() {
	new_test_ext().execute_with(|| {
		assert_ok!(ValidatorSet::add_validator(RawOrigin::Root.into(), 4));
		assert_eq!(ValidatorSet::validators(), vec![1u64, 2u64, 3u64, 4u64]);
		assert_noop!(
			ValidatorSet::add_validator(RawOrigin::Root.into(), 4),
			Error::<Test>::Duplicate
		);
	});
}
