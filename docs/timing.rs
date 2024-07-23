pub struct TimingConfig {
    pub block_time: u32,  // in seconds
    pub epoch_length: u32,  // in blocks
    pub confirmations_required: u32,
}

impl<T: Config> Pallet<T> {
    pub fn get_timing_config(chain: Chain) -> TimingConfig {
        match chain {
            Chain::Ethereum => TimingConfig {
                block_time: 15,
                epoch_length: 32 * 100,  // ~6.4 minutes * 100
                confirmations_required: 20,
            },
            Chain::Cardano => TimingConfig {
                block_time: 20,
                epoch_length: 21600,  // 5 days
                confirmations_required: 10,
            },
            // ... other chains
        }
    }

    pub fn is_event_final(event: &OracleEvent<T>) -> bool {
        let config = Self::get_timing_config(event.source_chain);
        let current_block = <frame_system::Pallet<T>>::block_number();
        let blocks_passed = current_block - event.submission_block;
        
        blocks_passed >= config.confirmations_required
    }
}