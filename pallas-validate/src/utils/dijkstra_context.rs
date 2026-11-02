//! The Dijkstra transactions the script context of each Plutus language up to V3 can hold.
use pallas_addresses::Address;
use pallas_primitives::{
    conway::Language,
    dijkstra::{Certificate, DatumOption, Guards, StakeCredential, TransactionBody},
};
use pallas_traverse::MultiEraOutput;

/// The part of a transaction that a script context cannot hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Untranslatable(pub &'static str);

/// Checks that the `language` script context can hold the top level of `b`, whose inputs and reference inputs resolve to `inputs` and `references`.
pub(crate) fn check_translatable(
    language: Language,
    b: &TransactionBody<'_>,
    inputs: &[&MultiEraOutput<'_>],
    references: &[&MultiEraOutput<'_>],
) -> Result<(), Untranslatable> {
    let refuse = |part| Err(Untranslatable(part));
    if matches!(language, Language::PlutusV1 | Language::PlutusV2) {
        if b.voting_procedures.as_ref().is_some_and(|x| !x.is_empty()) {
            return refuse("votes");
        }
        if b.proposal_procedures.is_some() {
            return refuse("proposal procedures");
        }
        if b.treasury_value.is_some() {
            return refuse("treasury value");
        }
        if b.donation.is_some() {
            return refuse("treasury donation");
        }
        if b.certificates.iter().flatten().any(|x| {
            !matches!(
                x,
                Certificate::Reg(..)
                    | Certificate::UnReg(..)
                    | Certificate::StakeDelegation(..)
                    | Certificate::PoolRegistration { .. }
                    | Certificate::PoolRetirement(..)
            )
        }) {
            return refuse("certificate kind");
        }
    }
    if b.direct_deposits.as_ref().is_some_and(|x| !x.is_empty()) {
        return refuse("direct deposits");
    }
    if b.account_balance_intervals
        .as_ref()
        .is_some_and(|x| !x.is_empty())
    {
        return refuse("account balance intervals");
    }
    if b.required_top_level_guards
        .as_ref()
        .is_some_and(|x| !x.is_empty())
    {
        return refuse("required top-level guards");
    }
    if let Some(Guards::Credentials(xs)) = &b.guards
        && xs
            .iter()
            .any(|x| matches!(x, StakeCredential::ScriptHash(_)))
    {
        return refuse("script guards");
    }
    let outputs: Vec<_> = b
        .outputs
        .iter()
        .map(MultiEraOutput::from_dijkstra)
        .collect();
    let any = |f: &dyn Fn(&MultiEraOutput<'_>) -> bool| {
        inputs.iter().any(|x| f(x)) || references.iter().any(|x| f(x)) || outputs.iter().any(f)
    };
    if any(&|x| matches!(x.address(), Ok(Address::Byron(_)))) {
        return refuse("Byron address");
    }
    if language == Language::PlutusV1 && any(&|x| matches!(x.datum(), Some(DatumOption::Data(_)))) {
        return refuse("inline datum");
    }
    if language == Language::PlutusV3
        && b.reference_inputs
            .iter()
            .flatten()
            .any(|x| b.inputs.contains(x))
    {
        return refuse("inputs that are also reference inputs");
    }
    Ok(())
}
