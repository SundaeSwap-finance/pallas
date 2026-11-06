//! Historical slot/time translation for native Dijkstra validation.

/// The start and slot duration of one known era. Times are POSIX milliseconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EraTime {
    pub start_slot: u64,
    pub start_time_ms: u64,
    pub slot_length_ms: u64,
}

/// The first slot the ledger's time forecast does not cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForecastHorizon {
    Slot(u64),
    Unbounded,
}

labels! {
    /// The rule an era time history breaks.
    pub enum HistoryFailure {
        DiscontinuousEraTimes => "discontinuous era times",
        EmptyHistory => "empty history",
        EraStartsMustIncrease => "era starts must increase",
        ZeroSlotLength => "zero slot length",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DijkstraTimeError {
    #[error("invalid era time history: {0}")]
    InvalidHistory(HistoryFailure),
    #[error("slot {slot} precedes available time history starting at {first_slot}")]
    BeforeHistory { slot: u64, first_slot: u64 },
    #[error("POSIX millisecond conversion overflows at slot {0}")]
    Overflow(u64),
    #[error("slot {slot} is at or past the forecast horizon {horizon}")]
    PastHorizon { slot: u64, horizon: u64 },
}

impl EraTime {
    fn translate(&self, slot: u64) -> Result<u64, DijkstraTimeError> {
        let elapsed =
            slot.checked_sub(self.start_slot)
                .ok_or(DijkstraTimeError::BeforeHistory {
                    slot,
                    first_slot: self.start_slot,
                })?;
        elapsed
            .checked_mul(self.slot_length_ms)
            .and_then(|x| self.start_time_ms.checked_add(x))
            .ok_or(DijkstraTimeError::Overflow(slot))
    }
}

/// Slot to POSIX millisecond translation over the known eras up to the forecast horizon.
///
/// Slots past the last known era start use that era's slot length.
#[derive(Debug, Clone)]
pub struct DijkstraTimeContext {
    eras: Vec<EraTime>,
    horizon: ForecastHorizon,
}

impl DijkstraTimeContext {
    pub fn new(eras: Vec<EraTime>, horizon: ForecastHorizon) -> Result<Self, DijkstraTimeError> {
        if eras.is_empty() {
            return Err(DijkstraTimeError::InvalidHistory(
                HistoryFailure::EmptyHistory,
            ));
        }
        if eras.iter().any(|e| e.slot_length_ms == 0) {
            return Err(DijkstraTimeError::InvalidHistory(
                HistoryFailure::ZeroSlotLength,
            ));
        }
        for pair in eras.windows(2) {
            if pair[0].start_slot >= pair[1].start_slot {
                return Err(DijkstraTimeError::InvalidHistory(
                    HistoryFailure::EraStartsMustIncrease,
                ));
            }
            if pair[0].translate(pair[1].start_slot)? != pair[1].start_time_ms {
                return Err(DijkstraTimeError::InvalidHistory(
                    HistoryFailure::DiscontinuousEraTimes,
                ));
            }
        }
        Ok(Self { eras, horizon })
    }

    pub fn slot_to_posix_ms(&self, slot: u64) -> Result<u64, DijkstraTimeError> {
        if let ForecastHorizon::Slot(horizon) = self.horizon
            && slot >= horizon
        {
            return Err(DijkstraTimeError::PastHorizon { slot, horizon });
        }
        let era = self
            .eras
            .iter()
            .rev()
            .find(|e| e.start_slot <= slot)
            .ok_or(DijkstraTimeError::BeforeHistory {
                slot,
                first_slot: self.eras[0].start_slot,
            })?;
        era.translate(slot)
    }

    pub fn validity_bounds(
        &self,
        lower: Option<u64>,
        upper: Option<u64>,
    ) -> Result<(Option<u64>, Option<u64>), DijkstraTimeError> {
        Ok((
            lower.map(|s| self.slot_to_posix_ms(s)).transpose()?,
            upper.map(|s| self.slot_to_posix_ms(s)).transpose()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn history() -> Vec<EraTime> {
        vec![
            EraTime {
                start_slot: 0,
                start_time_ms: 1_000_000,
                slot_length_ms: 20_000,
            },
            EraTime {
                start_slot: 10,
                start_time_ms: 1_200_000,
                slot_length_ms: 1000,
            },
        ]
    }

    fn unbounded(eras: Vec<EraTime>) -> DijkstraTimeContext {
        DijkstraTimeContext::new(eras, ForecastHorizon::Unbounded).unwrap()
    }

    #[test]
    fn historical_and_future_bounds_use_their_correct_slot_lengths() {
        let time = unbounded(history());
        assert_eq!(
            time.validity_bounds(Some(5), Some(100)).unwrap(),
            (Some(1_100_000), Some(1_290_000))
        );
        assert_eq!(time.slot_to_posix_ms(9).unwrap(), 1_180_000);
        assert_eq!(time.slot_to_posix_ms(10).unwrap(), 1_200_000);
        assert_eq!(time.slot_to_posix_ms(20).unwrap(), 1_210_000);
        assert_eq!(time.slot_to_posix_ms(21).unwrap(), 1_211_000);
        // Forward extension has no arbitrary fixed TTL distance.
        assert_eq!(time.slot_to_posix_ms(1_000_000).unwrap(), 1_001_190_000);
    }

    #[test]
    fn absent_bounds_remain_absent() {
        let time = unbounded(history());
        assert_eq!(time.validity_bounds(None, None).unwrap(), (None, None));
        assert_eq!(
            time.validity_bounds(None, Some(10)).unwrap(),
            (None, Some(1_200_000))
        );
        assert_eq!(
            time.validity_bounds(Some(10), None).unwrap(),
            (Some(1_200_000), None)
        );
    }

    #[test]
    fn unavailable_history_is_an_explicit_error() {
        assert!(matches!(
            DijkstraTimeContext::new(vec![], ForecastHorizon::Unbounded),
            Err(DijkstraTimeError::InvalidHistory(_))
        ));
        let era = EraTime {
            start_slot: 10,
            start_time_ms: 1000,
            slot_length_ms: 1000,
        };
        let time = unbounded(vec![era]);
        assert!(matches!(
            time.validity_bounds(Some(9), Some(20)),
            Err(DijkstraTimeError::BeforeHistory { .. })
        ));
        let mut gap = history();
        gap[1].start_time_ms += 1;
        assert!(matches!(
            DijkstraTimeContext::new(gap, ForecastHorizon::Unbounded),
            Err(DijkstraTimeError::InvalidHistory(_))
        ));
        let mut zero = history();
        zero[0].slot_length_ms = 0;
        assert!(matches!(
            DijkstraTimeContext::new(zero, ForecastHorizon::Unbounded),
            Err(DijkstraTimeError::InvalidHistory(_))
        ));
    }

    #[test]
    fn slots_at_or_past_the_horizon_are_refused() {
        let time = DijkstraTimeContext::new(history(), ForecastHorizon::Slot(100)).unwrap();
        assert_eq!(
            time.validity_bounds(Some(20), Some(99)).unwrap(),
            (Some(1_210_000), Some(1_289_000))
        );
        let past = DijkstraTimeError::PastHorizon {
            slot: 100,
            horizon: 100,
        };
        assert_eq!(time.slot_to_posix_ms(100), Err(past.clone()));
        assert_eq!(time.validity_bounds(Some(20), Some(100)), Err(past.clone()));
        assert_eq!(time.validity_bounds(Some(100), None), Err(past));
    }

    #[test]
    fn conversion_overflow_never_wraps_or_drops_a_bound() {
        let time = unbounded(history());
        assert_eq!(
            time.validity_bounds(None, Some(u64::MAX)),
            Err(DijkstraTimeError::Overflow(u64::MAX))
        );
        let near_max = EraTime {
            start_slot: 0,
            start_time_ms: u64::MAX - 1000,
            slot_length_ms: 1000,
        };
        let time = unbounded(vec![near_max]);
        assert_eq!(time.slot_to_posix_ms(1).unwrap(), u64::MAX);
        assert_eq!(
            time.slot_to_posix_ms(2),
            Err(DijkstraTimeError::Overflow(2))
        );
    }

    #[test]
    fn known_era_transitions_apply_to_later_slots() {
        let time = unbounded(history());
        assert_eq!(time.slot_to_posix_ms(9).unwrap(), 1_180_000);
        assert_eq!(time.slot_to_posix_ms(10).unwrap(), 1_200_000);
        assert_eq!(time.slot_to_posix_ms(15).unwrap(), 1_205_000);
        assert_eq!(time.slot_to_posix_ms(1_000_000).unwrap(), 1_001_190_000);
    }
}
