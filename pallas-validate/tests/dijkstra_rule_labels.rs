#![cfg(feature = "unstable")]

use pallas_validate::utils::{
    AccountFailure, CertificateFailure, ContextFailure, GovernanceFailure, HistoryFailure,
    MalformedField, ParameterFailure, UnsupportedFeature, ValidationError, WithdrawalFailure,
};

/// The text, Display and Debug of every label of one type.
fn rendered<T: std::fmt::Display + std::fmt::Debug>(
    all: &[T],
    text: fn(&T) -> &'static str,
) -> Vec<(&'static str, String, String)> {
    all.iter()
        .map(|label| (text(label), label.to_string(), format!("{label:?}")))
        .collect()
}

#[test]
fn a_labelled_refusal_prints_the_message_and_debug_text_of_its_label() {
    let e = ValidationError::DijkstraInvalidCertificate(CertificateFailure::RegistrationDeposit);
    assert_eq!(
        e.to_string(),
        "invalid Dijkstra certificate: registration deposit"
    );
    assert_eq!(
        format!("{e:?}"),
        "DijkstraInvalidCertificate(\"registration deposit\")"
    );
    let e = ValidationError::DijkstraUnsupported(UnsupportedFeature::ProtocolVersion);
    assert_eq!(
        e.to_string(),
        "unsupported Dijkstra phase-one feature: protocol version (requires 12.0)"
    );
    assert_eq!(
        format!("{e:?}"),
        "DijkstraUnsupported(\"protocol version (requires 12.0)\")"
    );
}

#[test]
fn every_label_displays_its_text_and_debugs_it_quoted() {
    let all = [
        rendered(UnsupportedFeature::ALL, |l| l.as_str()),
        rendered(CertificateFailure::ALL, |l| l.as_str()),
        rendered(AccountFailure::ALL, |l| l.as_str()),
        rendered(GovernanceFailure::ALL, |l| l.as_str()),
        rendered(ParameterFailure::ALL, |l| l.as_str()),
        rendered(WithdrawalFailure::ALL, |l| l.as_str()),
        rendered(MalformedField::ALL, |l| l.as_str()),
        rendered(ContextFailure::ALL, |l| l.as_str()),
        rendered(HistoryFailure::ALL, |l| l.as_str()),
    ];
    for labels in all {
        assert!(!labels.is_empty());
        for (text, display, debug) in labels {
            assert_eq!(display, text);
            assert_eq!(debug, format!("{text:?}"));
        }
    }
}
