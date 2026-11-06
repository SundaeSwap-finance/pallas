//! Types for validating transactions in each era.
use thiserror::Error;

#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum ValidationError {
    #[cfg(feature = "unstable")]
    #[error("Dijkstra time translation: {0}")]
    DijkstraTime(#[from] super::DijkstraTimeError),
    #[cfg(feature = "unstable")]
    #[error("unsupported Dijkstra phase-one feature: {0}")]
    DijkstraUnsupported(UnsupportedFeature),

    #[cfg(feature = "unstable")]
    #[error("Dijkstra validation requires ledger state: {0}")]
    DijkstraLedgerStateUnavailable(String),

    #[cfg(feature = "unstable")]
    #[error("invalid Dijkstra certificate: {0}")]
    DijkstraInvalidCertificate(CertificateFailure),

    #[cfg(feature = "unstable")]
    #[error("invalid Dijkstra account balance use: {0}")]
    DijkstraInvalidAccount(AccountFailure),

    #[cfg(feature = "unstable")]
    #[error("invalid Dijkstra governance: {0}")]
    DijkstraInvalidGovernance(GovernanceFailure),

    #[cfg(feature = "unstable")]
    #[error("Dijkstra treasury value does not equal the ledger treasury")]
    DijkstraTreasuryValueMismatch,

    #[cfg(feature = "unstable")]
    #[error("missing or invalid Dijkstra protocol parameter: {0}")]
    DijkstraMissingParameters(ParameterFailure),

    #[cfg(feature = "unstable")]
    #[error("Dijkstra reference script size exceeds the protocol limit")]
    DijkstraReferenceScriptsTooLarge,

    #[cfg(feature = "unstable")]
    #[error("input has already been consumed within the Dijkstra batch")]
    DijkstraInputAlreadySpent,

    #[cfg(feature = "unstable")]
    #[error("Dijkstra input locked by a Plutus V1 or V2 script has no datum")]
    DijkstraInputWithoutDatum,

    #[cfg(feature = "unstable")]
    #[error(
        "Dijkstra required top-level guard has a datum its credential does not take, or lacks one its Plutus script takes"
    )]
    DijkstraMalformedGuardDatum,

    #[cfg(feature = "unstable")]
    #[error("Dijkstra collateral return pays to a pointer address")]
    DijkstraPointerInCollateralReturn,

    #[cfg(feature = "unstable")]
    #[error("Dijkstra output Byron address attributes exceed 64 bytes")]
    DijkstraBootstrapAttributesTooLarge,

    #[cfg(feature = "unstable")]
    #[error("invalid Dijkstra withdrawal: {0}")]
    DijkstraInvalidWithdrawal(WithdrawalFailure),

    #[cfg(feature = "unstable")]
    #[error("invalid Dijkstra metadata")]
    DijkstraInvalidMetadata,

    #[cfg(feature = "unstable")]
    #[error("malformed Dijkstra Plutus script")]
    DijkstraMalformedScript,

    #[cfg(feature = "unstable")]
    #[error("malformed Dijkstra transaction field: {0}")]
    DijkstraMalformed(MalformedField),

    #[cfg(feature = "unstable")]
    #[error("Dijkstra script context cannot be built: {0}")]
    DijkstraScriptContext(ContextFailure),

    #[error("transaction and protocol parameters differ")]
    TxAndProtParamsDiffer,

    #[error("byron doesn't need account state")]
    PParamsByronDoesntNeedAccountState,

    #[error("missing account state")]
    EnvMissingAccountState,

    #[error("unknown protocol parameters")]
    UnknownProtParams,

    #[error("{0}")]
    Byron(ByronError),

    #[error("{0}")]
    ShelleyMA(ShelleyMAError),

    #[error("{0}")]
    Alonzo(AlonzoError),

    #[error("{0}")]
    PostAlonzo(PostAlonzoError),
}

#[cfg(feature = "unstable")]
labels! {
    /// A Dijkstra construct the phase one validator does not implement.
    pub enum UnsupportedFeature {
        AuxiliaryFields => "auxiliary fields",
        AuxiliaryScripts => "auxiliary scripts",
        BodyFields => "body fields",
        DuplicateCollateralInputs => "duplicate collateral inputs",
        DuplicateInputs => "duplicate inputs",
        DuplicateRedeemerPointers => "duplicate redeemer pointers",
        DuplicateReferenceInputs => "duplicate reference inputs",
        NewScriptLanguage => "new script language (requires V3)",
        OutputFields => "output fields",
        PlutusUpperBoundWithoutForecast => "Plutus validity upper bound requires forecast state",
        PlutusWithoutPhase2 => "new Plutus script validation requires phase2 feature",
        ProtocolVersion => "protocol version (requires 12.0)",
        ReferenceScriptLanguage => "reference script language (requires V3)",
        RequiredTopLevelGuards => "required top-level guards",
        SubtransactionBodyFields => "subtransaction body fields",
        Subtransactions => "subtransactions",
        UnsuccessfulBlockTransaction => "unsuccessful block transaction",
        WitnessFields => "witness fields",
    }
}

#[cfg(feature = "unstable")]
labels! {
    /// The rule a Dijkstra certificate breaks.
    pub enum CertificateFailure {
        AccountBalanceNotZero => "account balance is not zero",
        AlreadyRegistered => "already registered",
        BlsProofOfPossession => "BLS proof of possession",
        CommitteeMemberResigned => "committee member has resigned",
        CommitteeMemberUnknown => "committee member is unknown",
        DelegateeDRepNotRegistered => "delegatee DRep not registered",
        DelegateePoolNotRegistered => "delegatee pool not registered",
        DRepAlreadyRegistered => "DRep already registered",
        DRepDeposit => "DRep deposit",
        DRepNotRegistered => "DRep not registered",
        DRepRefund => "DRep refund",
        PoolCostBelowMinimum => "pool cost below the minimum",
        PoolNotRegistered => "pool not registered",
        PoolRetirementEpoch => "pool retirement epoch",
        Refund => "refund",
        RegistrationDeposit => "registration deposit",
        VrfKeyHashAlreadyRegistered => "VRF key hash already registered",
    }
}

#[cfg(feature = "unstable")]
labels! {
    /// The rule a Dijkstra account balance use breaks.
    pub enum AccountFailure {
        BalanceIntervalUnregistered => "balance interval names an unregistered account",
        BalanceOutsideInterval => "balance outside its interval",
        DirectDepositUnregistered => "direct deposit names an unregistered account",
        StakeCredentialNotRegistered => "stake credential not registered",
    }
}

#[cfg(feature = "unstable")]
labels! {
    /// The rule a Dijkstra proposal or vote breaks.
    pub enum GovernanceFailure {
        ActionDoesNotExist => "governance action does not exist",
        CommitteeTermTooSmall => "committee term too small",
        ConflictingCommitteeUpdate => "conflicting committee update",
        GuardrailsScriptHash => "guardrails script hash",
        HardForkVersionCannotFollow => "hard fork version cannot follow",
        MalformedParameterUpdate => "malformed parameter update",
        PreviousActionId => "previous action id",
        ProposalDeposit => "proposal deposit",
        ProposalReturnAccountNotRegistered => "proposal return account not registered",
        TreasuryWithdrawalAccountNotRegistered => "treasury withdrawal account not registered",
        UnelectedCommitteeVoter => "unelected committee voter",
        VoteOnExpiredAction => "vote on an expired action",
        VoterDoesNotExist => "voter does not exist",
        VoterMayNotVote => "voter may not vote on the action",
        ZeroTreasuryWithdrawals => "zero treasury withdrawals",
    }
}

#[cfg(feature = "unstable")]
labels! {
    /// A Dijkstra protocol parameter that is missing or holds a value the validator cannot use.
    pub enum ParameterFailure {
        NonzeroPriceDenominator => "nonzero price denominator",
        ReferenceFeeStride => "reference fee stride",
    }
}

#[cfg(feature = "unstable")]
labels! {
    /// The rule a Dijkstra withdrawal breaks.
    pub enum WithdrawalFailure {
        AccountMissingFromOriginalState => "account missing from the original state",
        AmountExceedsBalance => "amount exceeds the balance",
        AmountExceedsOriginalBalance => "amount exceeds the original balance",
        DuplicateAccount => "duplicate account",
        Encoding => "encoding",
        LegacyPlutusMustDrain => "legacy Plutus withdrawals must drain the account",
        UnregisteredAccount => "unregistered account",
    }
}

#[cfg(feature = "unstable")]
labels! {
    /// A Dijkstra transaction field whose encoding the ledger decoder refuses.
    pub enum MalformedField {
        BootstrapWitness => "bootstrap witness",
        DuplicateBootstrapWitnesses => "duplicate bootstrap witnesses",
        DuplicateDatums => "duplicate datums",
        DuplicateGuards => "duplicate guards",
        DuplicateKeyWitnesses => "duplicate key witnesses",
        DuplicateRequiredTopLevelGuards => "duplicate required top-level guards",
        EmptyAccountBalanceIntervals => "empty account balance intervals",
        EmptyCertificates => "empty certificates",
        EmptyCollateralInputs => "empty collateral inputs",
        EmptyDirectDeposits => "empty direct deposits",
        EmptyProposalProcedures => "empty proposal procedures",
        EmptyRedeemers => "empty redeemers",
        EmptyReferenceInputs => "empty reference inputs",
        EmptyRequiredTopLevelGuards => "empty required top-level guards",
        EmptyStartingAccountBalanceIntervals => "empty starting account balance intervals",
        EmptySubtransactions => "empty subtransactions",
        EmptyVotingProcedures => "empty voting procedures",
        EmptyWithdrawals => "empty withdrawals",
        ExecutionUnits => "execution units",
        KeyWitness => "key witness",
        MultiAssetValue => "multi-asset value",
        ProtocolParameterUpdate => "protocol parameter update",
        ZeroDonation => "zero donation",
    }
}

#[cfg(feature = "unstable")]
labels! {
    /// A part of a Dijkstra transaction that a script context cannot hold.
    pub enum ContextFailure {
        AccountBalanceIntervals => "account balance intervals",
        ByronAddress => "Byron address",
        CertificateKind => "certificate kind",
        CostModel => "cost model",
        DirectDeposits => "direct deposits",
        InlineDatum => "inline datum",
        InputsAlsoReferenced => "inputs that are also reference inputs",
        LegacyScriptInSubtransaction => "Plutus V1 to V3 script in a subtransaction",
        PointerAddress => "pointer address",
        ProposalProcedures => "proposal procedures",
        RequiredTopLevelGuards => "required top-level guards",
        RewardAccountAddress => "reward account address",
        ScriptGuards => "script guards",
        TreasuryDonation => "treasury donation",
        TreasuryValue => "treasury value",
        Votes => "votes",
    }
}

#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum ByronError {
    #[error("transaction has no inputs")]
    TxInsEmpty,

    #[error("transaction has no outputs")]
    TxOutsEmpty,

    #[error("some transaction input is not present in the UTxO set")]
    InputNotInUTxO,

    #[error("transaction output has no lovelace")]
    OutputWithoutLovelace,

    #[error("transaction size could not be determined")]
    UnknownTxSize,

    #[error("transaction fee cannot be computed")]
    UnableToComputeFees,

    #[error("transaction fee is below the minimum fee required")]
    FeesBelowMin,

    #[error("transaction size exceeds the maximum allowed")]
    MaxTxSizeExceeded,

    #[error("unable to process witnesses from the transaction")]
    UnableToProcessWitness,

    #[error("transaction witness is missing")]
    MissingWitness,

    #[error("transaction has the wrong signature")]
    WrongSignature,
}

#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum ShelleyMAError {
    #[error("transaction has no inputs")]
    TxInsEmpty,

    #[error("some transaction input is not present in the UTxO set")]
    InputNotInUTxO,

    #[error("transaction exceeds the TTL range")]
    TTLExceeded,

    #[error("transaction composition is not compatible with shelley")]
    AlonzoCompNotShelley,

    #[error("transaction size could not be determined")]
    UnknownTxSize,

    #[error("transaction size exceeds the maximum allowed")]
    MaxTxSizeExceeded,

    #[error("some value in the transaction is not shelley-compatible")]
    ValueNotShelley,

    #[error("minimum lovelace requirement was not met")]
    MinLovelaceUnreached,

    #[error("transaction values are not preserved correctly")]
    PreservationOfValue,

    #[error("transaction contains a negative value")]
    NegativeValue,

    #[error("transaction fee is below the minimum fee required")]
    FeesBelowMin,

    #[error("transaction output is from a different era")]
    WrongEraOutput,

    #[error("failed to decode the address")]
    AddressDecoding,

    #[error("transaction has the wrong network ID")]
    WrongNetworkID,

    #[error("metadata hash is invalid")]
    MetadataHash,

    #[error("vkey witness is missing")]
    MissingVKWitness,

    #[error("script witness is missing")]
    MissingScriptWitness,

    #[error("transaction has the wrong signature")]
    WrongSignature,

    #[error("minting lacks the required policy")]
    MintingLacksPolicy,

    #[error("key is already registered")]
    KeyAlreadyRegistered,

    #[error("key is not yet registered")]
    KeyNotRegistered,

    #[error("pointer is already in use")]
    PointerInUse,

    #[error("rewards are not null")]
    RewardsNotNull,

    #[error("pool is already registered")]
    PoolAlreadyRegistered,

    #[error("pool is not yet registered")]
    PoolNotRegistered,

    #[error("pool cost is below the minimum")]
    PoolCostBelowMin,

    #[error("transaction has duplicate genesis delegates")]
    DuplicateGenesisDelegate,

    #[error("transaction has duplicate genesis VRF")]
    DuplicateGenesisVRF,

    #[error("genesis key is not in the mapping")]
    GenesisKeyNotInMapping,

    #[error("insufficient funds for instantaneous rewards")]
    InsufficientForInstantaneousRewards,

    #[error("MIR certificate is too late in the epoch")]
    MIRCertificateTooLateinEpoch,

    #[error("script is denied")]
    ScriptDenial,
}

#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum AlonzoError {
    #[error("transaction size could not be determined")]
    UnknownTxSize,

    #[error("transaction has no inputs")]
    TxInsEmpty,

    #[error("some transaction input is not present in the UTxO set")]
    InputNotInUTxO,

    #[error("collateral is not present in the UTxO set")]
    CollateralNotInUTxO,

    #[error("block precedes the validity interval")]
    BlockExceedsValInt,

    #[error("block exceeds the validity interval")]
    BlockPrecedesValInt,

    #[error("upper bound of the validity interval is missing")]
    ValIntUpperBoundMissing,

    #[error("transaction fee is below the minimum fee required")]
    FeeBelowMin,

    #[error("collateral input is missing from the transaction")]
    CollateralMissing,

    #[error("transaction contains too many collateral inputs")]
    TooManyCollaterals,

    #[error("the collateral input is not VKey locked")]
    CollateralNotVKeyLocked,

    #[error("failed to decode the address")]
    AddressDecoding,

    #[error("collateral input does not meet the minimum lovelace required")]
    CollateralMinLovelace,

    #[error("collateral input contains non-lovelace assets")]
    NonLovelaceCollateral,

    #[error("transaction contains a negative value")]
    NegativeValue,

    #[error("transaction values are not preserved correctly")]
    PreservationOfValue,

    #[error("minimum lovelace requirement was not met")]
    MinLovelaceUnreached,

    #[error("the maximum value size has been exceeded")]
    MaxValSizeExceeded,

    #[error("transaction output has the wrong network ID")]
    OutputWrongNetworkID,

    #[error("transaction has the wrong network ID")]
    TxWrongNetworkID,

    #[error("required redeemer is missing")]
    RedeemerMissing,

    #[error("the transaction's execution units exceed the maximum allowed")]
    TxExUnitsExceeded,

    #[error("transaction size exceeds the maximum allowed")]
    MaxTxSizeExceeded,

    #[error("vkey witness is missing")]
    VKWitnessMissing,

    #[error("vkey witness has the wrong signature")]
    VKWrongSignature,

    #[error("required signer is missing")]
    ReqSignerMissing,

    #[error("required signer has the wrong signature")]
    ReqSignerWrongSig,

    #[error("script witness is missing")]
    ScriptWitnessMissing,

    #[error("minting lacks the required policy")]
    MintingLacksPolicy,

    #[error("failed to decode the input")]
    InputDecoding,

    #[error("an unnecessary native script is present")]
    UnneededNativeScript,

    #[error("an unnecessary Plutus V1 script is present")]
    UnneededPlutusScript,

    #[error("an unnecessary redeemer is present")]
    UnneededRedeemer,

    #[error("required datum is missing")]
    DatumMissing,

    #[error("an unnecessary datum is present")]
    UnneededDatum,

    #[error("metadata hash is invalid")]
    MetadataHash,

    #[error("invalid script integrity hash")]
    ScriptIntegrityHash,
}

#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum PostAlonzoError {
    #[error("native reference script uses features unsupported by this validator")]
    UnsupportedNativeScript,

    #[error("native script evaluation failed")]
    NativeScriptDenial,

    #[error("transaction size could not be determined")]
    UnknownTxSize,

    #[error("transaction has no inputs")]
    TxInsEmpty,

    #[error("some transaction input is not present in the UTxO set")]
    InputNotInUTxO,

    #[error("collateral is not present in the UTxO set")]
    CollateralNotInUTxO,

    #[error("reference input is not present in the UTxO set")]
    ReferenceInputNotInUTxO,

    #[error("block precedes the validity interval")]
    BlockPrecedesValInt,

    #[error("block exceeds the validity interval")]
    BlockExceedsValInt,

    #[error("transaction fee is below the minimum fee required")]
    FeeBelowMin,

    #[error("collateral input is missing from the transaction")]
    CollateralMissing,

    #[error("transaction contains too many collateral inputs")]
    TooManyCollaterals,

    #[error("failed to decode the input")]
    InputDecoding,

    #[error("the collateral input is not VKey locked")]
    CollateralNotVKeyLocked,

    #[error("collateral input does not meet the minimum lovelace required")]
    CollateralMinLovelace,

    #[error("collateral input contains non-lovelace assets")]
    NonLovelaceCollateral,

    #[error("collateral input contains incorrect assets")]
    CollateralWrongAssets,

    #[error("transaction contains a negative value")]
    NegativeValue,

    #[error("paid collateral does not match the annotated collateral")]
    CollateralAnnotation,

    #[error("transaction values are not preserved correctly")]
    PreservationOfValue,

    #[error("minimum lovelace requirement was not met")]
    MinLovelaceUnreached,

    #[error("the maximum value size has been exceeded")]
    MaxValSizeExceeded,

    #[error("failed to decode the address")]
    AddressDecoding,

    #[error("transaction output has the wrong network ID")]
    OutputWrongNetworkID,

    #[error("transaction has the wrong network ID")]
    TxWrongNetworkID,

    #[error("the transaction's execution units exceed the maximum allowed")]
    TxExUnitsExceeded,

    #[error("required redeemer is missing")]
    RedeemerMissing,

    #[error("an unnecessary redeemer is present")]
    UnneededRedeemer,

    #[error("transaction size exceeds the maximum allowed")]
    MaxTxSizeExceeded,

    #[error("minting lacks the required policy: {0}")]
    MintingLacksPolicy(pallas_crypto::hash::Hash<28>),

    #[error("metadata hash is invalid")]
    MetadataHash,

    #[error("required datum is missing")]
    DatumMissing,

    #[error("an unnecessary datum is present")]
    UnneededDatum,

    #[error("script witness is missing")]
    ScriptWitnessMissing,

    #[error("an unnecessary native script is present")]
    UnneededNativeScript,

    #[error("an unnecessary Plutus V1 script is present")]
    UnneededPlutusV1Script,

    #[error("an unnecessary Plutus V2 script is present")]
    UnneededPlutusV2Script,

    #[error("an unnecessary Plutus V3 script is present")]
    UnneededPlutusV3Script,

    #[error("required signer is missing")]
    ReqSignerMissing,

    #[error("required signer has the wrong signature")]
    ReqSignerWrongSig,

    #[error("vkey witness is missing")]
    VKWitnessMissing,

    #[error("vkey witness has the wrong signature")]
    VKWrongSignature,

    #[error("transaction contains an unsupported plutus language")]
    UnsupportedPlutusLanguage,

    #[error("invalid script integrity hash")]
    ScriptIntegrityHash,
}

pub type ValidationResult = Result<(), ValidationError>;
