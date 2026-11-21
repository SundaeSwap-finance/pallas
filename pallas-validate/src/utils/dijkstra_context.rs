//! The Dijkstra transactions the script context of each Plutus language can hold.
use crate::{phase1::dijkstra_ledger::Level, utils::ContextFailure};
use pallas_addresses::{Address, ShelleyAddress, ShelleyDelegationPart};
use pallas_primitives::dijkstra::{Certificate, DatumOption, Guards, Language, StakeCredential};
use pallas_traverse::MultiEraOutput;

/// The part of a transaction that a script context cannot hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Untranslatable(pub ContextFailure);

/// The transaction parts a language's script context can hold.
struct Holds {
    governance: bool,
    dijkstra_fields: bool,
    inline_datums: bool,
    shared_inputs: bool,
}

/// The sub transaction a PlutusV1 to V3 script context cannot hold.
pub(crate) const LEGACY_IN_SUB: Untranslatable =
    Untranslatable(ContextFailure::LegacyScriptInSubtransaction);

/// The Shelley address a script context holds for an output at `address`.
pub(crate) fn context_address(address: Address) -> Result<ShelleyAddress, Untranslatable> {
    match address {
        Address::Shelley(x) => Ok(x),
        Address::Byron(_) => Err(Untranslatable(ContextFailure::ByronAddress)),
        Address::Stake(_) => Err(Untranslatable(ContextFailure::RewardAccountAddress)),
    }
}

/// The stake credential a PlutusV4 script context holds for the delegation part of `address`.
pub(crate) fn v4_stake(
    address: &ShelleyAddress,
) -> Result<Option<StakeCredential>, Untranslatable> {
    match address.delegation() {
        ShelleyDelegationPart::Key(hash) => Ok(Some(StakeCredential::AddrKeyhash(*hash))),
        ShelleyDelegationPart::Script(hash) => Ok(Some(StakeCredential::ScriptHash(*hash))),
        ShelleyDelegationPart::Null => Ok(None),
        ShelleyDelegationPart::Pointer(_) => Err(Untranslatable(ContextFailure::PointerAddress)),
    }
}

/// Checks that the `language` script context can hold the level `b`, whose inputs and reference inputs resolve to `inputs` and `references`.
pub(crate) fn check_translatable(
    language: &Language,
    b: &Level<'_>,
    inputs: &[&MultiEraOutput<'_>],
    references: &[&MultiEraOutput<'_>],
) -> Result<(), Untranslatable> {
    if b.sub.is_some() && *language != Language::PlutusV4 {
        return Err(LEGACY_IN_SUB);
    }
    let holds = match language {
        Language::PlutusV1 => Holds {
            governance: false,
            dijkstra_fields: false,
            inline_datums: false,
            shared_inputs: true,
        },
        Language::PlutusV2 => Holds {
            governance: false,
            dijkstra_fields: false,
            inline_datums: true,
            shared_inputs: true,
        },
        Language::PlutusV3 => Holds {
            governance: true,
            dijkstra_fields: false,
            inline_datums: true,
            shared_inputs: false,
        },
        Language::PlutusV4 => Holds {
            governance: true,
            dijkstra_fields: true,
            inline_datums: true,
            shared_inputs: false,
        },
    };
    let refuse = |part| Err(Untranslatable(part));
    if !holds.governance {
        if b.votes.is_some_and(|x| !x.is_empty()) {
            return refuse(ContextFailure::Votes);
        }
        if b.proposals.is_some() {
            return refuse(ContextFailure::ProposalProcedures);
        }
        if b.treasury_value.is_some() {
            return refuse(ContextFailure::TreasuryValue);
        }
        if b.donation.is_some() {
            return refuse(ContextFailure::TreasuryDonation);
        }
        if b.certificates.into_iter().flatten().any(|x| {
            !matches!(
                x,
                Certificate::Reg(..)
                    | Certificate::UnReg(..)
                    | Certificate::StakeDelegation(..)
                    | Certificate::PoolRegistration { .. }
                    | Certificate::PoolRetirement(..)
            )
        }) {
            return refuse(ContextFailure::CertificateKind);
        }
    }
    if !holds.dijkstra_fields {
        if b.direct_deposits.is_some_and(|x| !x.is_empty()) {
            return refuse(ContextFailure::DirectDeposits);
        }
        if b.intervals.is_some_and(|x| !x.is_empty()) {
            return refuse(ContextFailure::AccountBalanceIntervals);
        }
        if b.required_top_level_guards.is_some_and(|x| !x.is_empty()) {
            return refuse(ContextFailure::RequiredTopLevelGuards);
        }
        if let Some(Guards::Credentials(xs)) = b.guards
            && xs
                .iter()
                .any(|x| matches!(x, StakeCredential::ScriptHash(_)))
        {
            return refuse(ContextFailure::ScriptGuards);
        }
    }
    let outputs: Vec<_> = b
        .outputs
        .iter()
        .map(MultiEraOutput::from_dijkstra)
        .collect();
    let any = |f: &dyn Fn(&MultiEraOutput<'_>) -> bool| {
        inputs.iter().any(|x| f(x)) || references.iter().any(|x| f(x)) || outputs.iter().any(f)
    };
    let addresses = inputs
        .iter()
        .map(|x| x.address())
        .chain(references.iter().map(|x| x.address()))
        .chain(outputs.iter().map(MultiEraOutput::address))
        .filter_map(Result::ok)
        .map(context_address)
        .collect::<Result<Vec<_>, _>>()?;
    if *language == Language::PlutusV4 {
        for address in &addresses {
            v4_stake(address)?;
        }
    }
    if !holds.inline_datums && any(&|x| matches!(x.datum(), Some(DatumOption::Data(_)))) {
        return refuse(ContextFailure::InlineDatum);
    }
    if !holds.shared_inputs
        && b.reference_inputs
            .into_iter()
            .flatten()
            .any(|x| b.inputs.contains(x))
    {
        return refuse(ContextFailure::InputsAlsoReferenced);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pallas_codec::minicbor;
    use pallas_codec::utils::{CborWrap, MaybeIndefArray};
    use pallas_primitives::dijkstra as n;

    fn output(datum: DatumOption<'static>) -> n::TransactionOutput<'static> {
        n::TransactionOutput::PostAlonzo(
            n::PostAlonzoTransactionOutput {
                address: [vec![0x60], vec![1; 28]].concat().into(),
                value: pallas_primitives::conway::Value::Coin(2_000_000)
                    .try_into()
                    .unwrap(),
                datum_option: Some(datum.into()),
                script_ref: None,
            }
            .into(),
        )
    }

    fn inline() -> n::TransactionOutput<'static> {
        output(DatumOption::Data(CborWrap(
            n::PlutusData::BigInt(n::BigInt::Int(0.into())).into(),
        )))
    }

    fn hashed() -> n::TransactionOutput<'static> {
        output(DatumOption::Hash([3; 32].into()))
    }

    fn held(
        language: Language,
        input: &n::TransactionOutput<'_>,
        reference: &n::TransactionOutput<'_>,
        output: n::TransactionOutput<'static>,
    ) -> Result<(), Untranslatable> {
        let mut body: n::TransactionBody =
            minicbor::decode(&[0xa3, 0x00, 0x80, 0x01, 0x80, 0x02, 0x00]).unwrap();
        body.outputs = MaybeIndefArray::Def(vec![output]);
        let level = Level::top(&body, [0; 32].into());
        let input = MultiEraOutput::from_dijkstra(input);
        let reference = MultiEraOutput::from_dijkstra(reference);
        check_translatable(&language, &level, &[&input], &[&reference])
    }

    #[test]
    fn plutus_v1_refuses_an_inline_datum_in_an_input_a_reference_input_or_an_output() {
        let refused = Err(Untranslatable(ContextFailure::InlineDatum));
        let (data, hash) = (inline(), hashed());
        assert_eq!(held(Language::PlutusV1, &data, &hash, hashed()), refused);
        assert_eq!(held(Language::PlutusV1, &hash, &data, hashed()), refused);
        assert_eq!(held(Language::PlutusV1, &hash, &hash, inline()), refused);
        assert_eq!(held(Language::PlutusV1, &hash, &hash, hashed()), Ok(()));
        assert_eq!(held(Language::PlutusV2, &data, &data, inline()), Ok(()));
    }
}
