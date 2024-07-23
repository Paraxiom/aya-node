fn compare_events(event1: &Event, event2: &Event) -> bool {
    let hash1 = hash_event(event1);
    let hash2 = hash_event(event2);
    hash1 == hash2
}

fn hash_event(event: &Event) -> Vec<u8> {
    // Create a hash of the event's contents
    // This could use SHA-256 or another suitable hash function
}
fn compare_events(event1: &Event, event2: &Event) -> bool {
    event1.id == event2.id &&
    event1.source == event2.source &&
    event1.data == event2.data &&
    event1.timestamp == event2.timestamp
}
fn compare_events_with_tolerance(event1: &Event, event2: &Event, time_tolerance: u64) -> bool {
    event1.id == event2.id &&
    event1.source == event2.source &&
    event1.data == event2.data &&
    (event1.timestamp.abs_diff(event2.timestamp) <= time_tolerance)
}
impl<T: Config> Pallet<T> {
    fn validate_event(event: &CustomEvent) -> Result<(), Error<T>> {
        let validators = Self::get_active_validators();
        let threshold = (validators.len() * 2) / 3 + 1; // 2/3 majority

        let validations = validators.iter()
            .map(|validator| validator.validate_event(event))
            .filter(|result| result.is_ok())
            .count();

        if validations >= threshold {
            Ok(())
        } else {
            Err(Error::<T>::InsufficientValidations)
        }
    }

    fn compare_events(event1: &CustomEvent, event2: &CustomEvent) -> bool {
        event1.id == event2.id &&
        event1.data == event2.data &&
        (event1.timestamp.abs_diff(event2.timestamp) <= T::TimestampTolerance::get())
    }

    pub fn process_event(event: CustomEvent) -> DispatchResult {
        // Validate the event
        Self::validate_event(&event)?;

        // Check for duplicates
        let existing_events = EventStorage::<T>::get();
        if existing_events.iter().any(|e| Self::compare_events(e, &event)) {
            return Err(Error::<T>::DuplicateEvent.into());
        }

        // Process the event
        // ... (rest of your event processing logic)

        Ok(())
    }
}