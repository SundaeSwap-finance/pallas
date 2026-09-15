use super::*;
use pallas_codec::minicbor::{Decode, Decoder, Encode, Encoder, data::Tag, decode, encode};

impl Encode<()> for BlockQuery {
    fn encode<W: encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut (),
    ) -> Result<(), encode::Error<W::Error>> {
        match self {
            BlockQuery::GetLedgerTip => {
                e.array(1)?;
                e.u16(0)?;
            }
            BlockQuery::GetEpochNo => {
                e.array(1)?;
                e.u16(1)?;
            }
            BlockQuery::GetNonMyopicMemberRewards(x) => {
                e.array(2)?;
                e.u16(2)?;
                e.encode(x)?;
            }
            BlockQuery::GetCurrentPParams => {
                e.array(1)?;
                e.u16(3)?;
            }
            BlockQuery::GetProposedPParamsUpdates => {
                e.array(1)?;
                e.u16(4)?;
            }
            BlockQuery::GetStakeDistribution => {
                e.array(1)?;
                e.u16(5)?;
            }
            BlockQuery::GetUTxOByAddress(addrs) => {
                e.array(2)?;
                e.u16(6)?;
                e.encode(addrs)?;
            }
            BlockQuery::GetUTxOWhole => {
                e.encode((7,))?;
            }
            BlockQuery::DebugEpochState => {
                e.array(1)?;
                e.u16(8)?;
            }
            BlockQuery::GetCBOR(x) => {
                e.array(2)?;
                e.u16(9)?;
                e.encode(x)?;
            }
            BlockQuery::GetFilteredDelegationsAndRewardAccounts(x) => {
                e.array(2)?;
                e.u16(10)?;
                e.encode(x)?;
            }
            BlockQuery::GetGenesisConfig => {
                e.array(1)?;
                e.u16(11)?;
            }
            BlockQuery::DebugNewEpochState => {
                e.array(1)?;
                e.u16(12)?;
            }
            BlockQuery::DebugChainDepState => {
                e.array(1)?;
                e.u16(13)?;
            }
            BlockQuery::GetRewardProvenance => {
                e.array(1)?;
                e.u16(14)?;
            }
            BlockQuery::GetUTxOByTxIn(txin) => {
                e.array(2)?;
                e.u16(15)?;
                e.encode(txin)?;
            }
            BlockQuery::GetStakePools => {
                e.array(1)?;
                e.u16(16)?;
            }
            BlockQuery::GetStakePoolParams(x) => {
                e.array(2)?;
                e.u16(17)?;
                e.encode(x)?;
            }
            BlockQuery::GetRewardInfoPools => {
                e.array(1)?;
                e.u16(18)?;
            }
            BlockQuery::GetPoolState(x) => {
                e.array(2)?;
                e.u16(19)?;
                e.encode(x)?;
            }
            BlockQuery::GetStakeSnapshots(pools) => {
                e.array(2)?;
                e.u16(20)?;
                e.encode(pools)?;
            }
            BlockQuery::GetPoolDistr(x) => {
                e.array(2)?;
                e.u16(21)?;
                e.encode(x)?;
            }
            BlockQuery::GetStakeDelegDeposits(x) => {
                e.array(2)?;
                e.u16(22)?;
                e.encode(x)?;
            }
            BlockQuery::GetConstitution => {
                e.array(1)?;
                e.u16(23)?;
            }
            BlockQuery::GetGovState => {
                e.array(1)?;
                e.u16(24)?;
            }
            BlockQuery::GetDRepState(x) => {
                e.array(2)?;
                e.u16(25)?;
                e.encode(x)?;
            }
            BlockQuery::GetDRepStakeDistr(dreps) => {
                e.array(2)?;
                e.u16(26)?;
                e.encode(dreps)?;
            }
            BlockQuery::GetCommitteeMembersState(set1, set2, status) => {
                e.array(4)?;
                e.u16(27)?;
                e.encode(set1)?;
                e.encode(set2)?;
                e.encode(status)?;
            }
            BlockQuery::GetFilteredVoteDelegatees(addrs) => {
                e.array(2)?;
                e.u16(28)?;
                e.encode(addrs)?;
            }
            BlockQuery::GetAccountState => {
                e.array(1)?;
                e.u16(29)?;
            }
            BlockQuery::GetSPOStakeDistr(pools) => {
                e.array(2)?;
                e.u16(30)?;
                e.encode(pools)?;
            }
            BlockQuery::GetProposals(proposals) => {
                e.array(2)?;
                e.u16(31)?;
                e.encode(proposals)?;
            }
            BlockQuery::GetRatifyState => {
                e.array(1)?;
                e.u16(32)?;
            }
            BlockQuery::GetFuturePParams => {
                e.array(1)?;
                e.u16(33)?;
            }
            BlockQuery::GetBigLedgerPeerSnapshot => {
                e.array(1)?;
                e.u16(34)?;
            }
            BlockQuery::GetLedgerPeerSnapshot(kind) => {
                e.array(2)?;
                e.u16(34)?;
                e.u8(*kind as u8)?;
            }
            BlockQuery::GetPoolDistr2(x) => {
                e.array(2)?;
                e.u16(36)?;
                e.encode(x)?;
            }
            BlockQuery::GetStakeDistribution2 => {
                e.array(1)?;
                e.u16(37)?;
            }
            BlockQuery::GetDRepsDelegations(dreps) => {
                e.array(2)?;
                e.u16(39)?;
                e.encode(dreps)?;
            }
        }
        Ok(())
    }
}

impl<'b> Decode<'b, ()> for BlockQuery {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut ()) -> Result<Self, decode::Error> {
        let len = d.array()?;

        match d.u16()? {
            0 => Ok(Self::GetLedgerTip),
            1 => Ok(Self::GetEpochNo),
            2 => Ok(Self::GetNonMyopicMemberRewards(d.decode()?)),
            3 => Ok(Self::GetCurrentPParams),
            4 => Ok(Self::GetProposedPParamsUpdates),
            5 => Ok(Self::GetStakeDistribution),
            6 => Ok(Self::GetUTxOByAddress(d.decode()?)),
            7 => Ok(Self::GetUTxOWhole),
            8 => Ok(Self::DebugEpochState),
            9 => Ok(Self::GetCBOR(d.decode()?)),
            10 => Ok(Self::GetFilteredDelegationsAndRewardAccounts(d.decode()?)),
            11 => Ok(Self::GetGenesisConfig),
            12 => Ok(Self::DebugNewEpochState),
            13 => Ok(Self::DebugChainDepState),
            14 => Ok(Self::GetRewardProvenance),
            15 => Ok(Self::GetUTxOByTxIn(d.decode()?)),
            16 => Ok(Self::GetStakePools),
            17 => Ok(Self::GetStakePoolParams(d.decode()?)),
            18 => Ok(Self::GetRewardInfoPools),
            19 => Ok(Self::GetPoolState(d.decode()?)),
            20 => Ok(Self::GetStakeSnapshots(d.decode()?)),
            21 => Ok(Self::GetPoolDistr(d.decode()?)),
            22 => Ok(Self::GetStakeDelegDeposits(d.decode()?)),
            23 => Ok(Self::GetConstitution),
            24 => Ok(Self::GetGovState),
            25 => Ok(Self::GetDRepState(d.decode()?)),
            26 => Ok(Self::GetDRepStakeDistr(d.decode()?)),
            27 => Ok(Self::GetCommitteeMembersState(
                d.decode()?,
                d.decode()?,
                d.decode()?,
            )),
            28 => Ok(Self::GetFilteredVoteDelegatees(d.decode()?)),
            29 => Ok(Self::GetAccountState),
            30 => Ok(Self::GetSPOStakeDistr(d.decode()?)),
            31 => Ok(Self::GetProposals(d.decode()?)),
            32 => Ok(Self::GetRatifyState),
            33 => Ok(Self::GetFuturePParams),
            // Tag 34 is overloaded: legacy single-element form (v11–v14)
            // returns the big peer snapshot only, while the v15+ form carries
            // a peer-kind discriminator (0 = All, 1 = Big).
            34 => match len {
                Some(1) => Ok(Self::GetBigLedgerPeerSnapshot),
                Some(2) => {
                    let kind = match d.u8()? {
                        0 => LedgerPeerSnapshotKind::All,
                        1 => LedgerPeerSnapshotKind::Big,
                        n => {
                            return Err(decode::Error::message(format!(
                                "unknown LedgerPeerSnapshot kind tag: {n}"
                            )));
                        }
                    };
                    Ok(Self::GetLedgerPeerSnapshot(kind))
                }
                _ => Err(decode::Error::message(
                    "GetLedgerPeerSnapshot: unexpected array length",
                )),
            },
            36 => Ok(Self::GetPoolDistr2(d.decode()?)),
            37 => Ok(Self::GetStakeDistribution2),
            39 => Ok(Self::GetDRepsDelegations(d.decode()?)),
            tag => Err(decode::Error::message(format!(
                "unknown BlockQuery tag: {tag}"
            ))),
        }
    }
}

impl Encode<()> for HardForkQuery {
    fn encode<W: encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut (),
    ) -> Result<(), encode::Error<W::Error>> {
        match self {
            HardForkQuery::GetInterpreter => {
                e.encode((0,))?;
            }
            HardForkQuery::GetCurrentEra => {
                e.encode((1,))?;
            }
        }

        Ok(())
    }
}

impl<'b> Decode<'b, ()> for HardForkQuery {
    fn decode(d: &mut Decoder<'b>, _: &mut ()) -> Result<Self, decode::Error> {
        d.array()?;
        let tag = d.u16()?;
        match tag {
            0 => Ok(Self::GetInterpreter),
            1 => Ok(Self::GetCurrentEra),
            _ => Err(decode::Error::message("invalid tag")),
        }
    }
}

impl Encode<()> for LedgerQuery {
    fn encode<W: encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _: &mut (),
    ) -> Result<(), encode::Error<W::Error>> {
        match self {
            LedgerQuery::BlockQuery(era, q) => {
                e.encode((0, (era, q)))?;
            }
            LedgerQuery::HardForkQuery(q) => {
                e.encode((2, q))?;
            }
        }

        Ok(())
    }
}

impl<'b> Decode<'b, ()> for LedgerQuery {
    fn decode(d: &mut Decoder<'b>, _: &mut ()) -> Result<Self, decode::Error> {
        d.array()?;
        let tag = d.u16()?;
        match tag {
            0 => {
                let (era, q) = d.decode()?;
                Ok(Self::BlockQuery(era, q))
            }
            2 => {
                let q = d.decode()?;
                Ok(Self::HardForkQuery(q))
            }
            _ => Err(decode::Error::message("invalid tag")),
        }
    }
}

impl Encode<()> for Request {
    fn encode<W: encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut (),
    ) -> Result<(), encode::Error<W::Error>> {
        match self {
            Self::LedgerQuery(q) => {
                e.encode((0, q))?;
                Ok(())
            }
            Self::GetSystemStart => {
                e.array(1)?;
                e.u16(1)?;
                Ok(())
            }
            Self::GetChainBlockNo => {
                e.array(1)?;
                e.u16(2)?;
                Ok(())
            }
            Self::GetChainPoint => {
                e.array(1)?;
                e.u16(3)?;
                Ok(())
            }
        }
    }
}

impl<'b> Decode<'b, ()> for Request {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut ()) -> Result<Self, decode::Error> {
        d.array()?;
        let tag = d.u16()?;

        match tag {
            0 => Ok(Self::LedgerQuery(d.decode()?)),
            1 => Ok(Self::GetSystemStart),
            2 => Ok(Self::GetChainBlockNo),
            3 => Ok(Self::GetChainPoint),
            _ => Err(decode::Error::message("invalid tag")),
        }
    }
}

impl<'b, C> minicbor::decode::Decode<'b, C> for Value {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        match d.datatype()? {
            minicbor::data::Type::U8 => Ok(Value::Coin(d.decode_with(ctx)?)),
            minicbor::data::Type::U16 => Ok(Value::Coin(d.decode_with(ctx)?)),
            minicbor::data::Type::U32 => Ok(Value::Coin(d.decode_with(ctx)?)),
            minicbor::data::Type::U64 => Ok(Value::Coin(d.decode_with(ctx)?)),
            minicbor::data::Type::Array => {
                d.array()?;
                let coin = d.decode_with(ctx)?;
                let multiasset = d.decode_with(ctx)?;
                Ok(Value::Multiasset(coin, multiasset))
            }
            _ => Err(minicbor::decode::Error::message(
                "unknown cbor data type for Value enum",
            )),
        }
    }
}

impl<C> minicbor::encode::Encode<C> for Value {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Value::Coin(coin) => {
                e.encode_with(coin, ctx)?;
            }
            Value::Multiasset(coin, other) => {
                e.array(2)?;
                e.encode_with(coin, ctx)?;
                e.encode_with(other, ctx)?;
            }
        };

        Ok(())
    }
}

impl<'b, C> minicbor::decode::Decode<'b, C> for RationalNumber {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        d.tag()?;
        d.array()?;

        Ok(RationalNumber {
            numerator: d.decode_with(ctx)?,
            denominator: d.decode_with(ctx)?,
        })
    }
}

impl<C> minicbor::encode::Encode<C> for RationalNumber {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.tag(Tag::new(30))?;
        e.array(2)?;
        e.encode_with(self.numerator, ctx)?;
        e.encode_with(self.denominator, ctx)?;

        Ok(())
    }
}

impl<'b, C> minicbor::decode::Decode<'b, C> for DijkstraProtocolParam {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        // The ledger writes one entry per protocol parameter and its own
        // decoder checks the count, so a different count is a different era or
        // a different ledger and reading it positionally would put every value
        // after the difference under the wrong name.
        match d.array()? {
            Some(DIJKSTRA_PROTOCOL_PARAM_FIELDS) => (),
            Some(found) => {
                return Err(decode::Error::message(format!(
                    "expected {DIJKSTRA_PROTOCOL_PARAM_FIELDS} Dijkstra protocol parameters, found an array of {found}"
                )));
            }
            None => {
                return Err(decode::Error::message(format!(
                    "expected a definite array of {DIJKSTRA_PROTOCOL_PARAM_FIELDS} Dijkstra protocol parameters, found an indefinite array"
                )));
            }
        }

        Ok(DijkstraProtocolParam {
            minfee_a: d.decode_with(ctx)?,
            minfee_b: d.decode_with(ctx)?,
            max_block_body_size: d.decode_with(ctx)?,
            max_transaction_size: d.decode_with(ctx)?,
            max_block_header_size: d.decode_with(ctx)?,
            key_deposit: d.decode_with(ctx)?,
            pool_deposit: d.decode_with(ctx)?,
            maximum_epoch: d.decode_with(ctx)?,
            desired_number_of_stake_pools: d.decode_with(ctx)?,
            pool_pledge_influence: d.decode_with(ctx)?,
            expansion_rate: d.decode_with(ctx)?,
            treasury_growth_rate: d.decode_with(ctx)?,
            protocol_version: d.decode_with(ctx)?,
            min_pool_cost: d.decode_with(ctx)?,
            ada_per_utxo_byte: d.decode_with(ctx)?,
            cost_models_for_script_languages: d.decode_with(ctx)?,
            execution_costs: d.decode_with(ctx)?,
            max_tx_ex_units: d.decode_with(ctx)?,
            max_block_ex_units: d.decode_with(ctx)?,
            max_value_size: d.decode_with(ctx)?,
            collateral_percentage: d.decode_with(ctx)?,
            max_collateral_inputs: d.decode_with(ctx)?,
            pool_voting_thresholds: d.decode_with(ctx)?,
            drep_voting_thresholds: d.decode_with(ctx)?,
            min_committee_size: d.decode_with(ctx)?,
            committee_term_limit: d.decode_with(ctx)?,
            governance_action_validity_period: d.decode_with(ctx)?,
            governance_action_deposit: d.decode_with(ctx)?,
            drep_deposit: d.decode_with(ctx)?,
            drep_inactivity_period: d.decode_with(ctx)?,
            minfee_refscript_cost_per_byte: d.decode_with(ctx)?,
            max_ref_script_size_per_block: d.decode_with(ctx)?,
            max_ref_script_size_per_tx: d.decode_with(ctx)?,
            ref_script_cost_stride: d.decode_with(ctx)?,
            ref_script_cost_multiplier: d.decode_with(ctx)?,
            max_pledge_leverage: d.decode_with(ctx)?,
            min_pool_margin: d.decode_with(ctx)?,
            leios_announcement_period_length: d.decode_with(ctx)?,
            leios_vote_period_length: d.decode_with(ctx)?,
            leios_diffusion_period_length: d.decode_with(ctx)?,
            leios_committee_size: d.decode_with(ctx)?,
            leios_quorum_stake_threshold: d.decode_with(ctx)?,
            max_endorser_block_references_size: d.decode_with(ctx)?,
            max_endorser_block_txs_size: d.decode_with(ctx)?,
            max_endorser_block_ex_units: d.decode_with(ctx)?,
            max_ref_script_size_per_endorser_block: d.decode_with(ctx)?,
        })
    }
}

impl<'b, C> minicbor::decode::Decode<'b, C> for TransactionOutput {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        match d.datatype()? {
            minicbor::data::Type::Map => Ok(TransactionOutput::Current(d.decode_with(ctx)?)),
            minicbor::data::Type::Array => Ok(TransactionOutput::Legacy(d.decode_with(ctx)?)),
            _ => Err(minicbor::decode::Error::message(
                "unknown cbor data type for TransactionOutput enum",
            )),
        }
    }
}

impl<C> minicbor::encode::Encode<C> for TransactionOutput {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            TransactionOutput::Current(map) => {
                e.encode_with(map, ctx)?;
            }
            TransactionOutput::Legacy(array) => {
                e.encode_with(array, ctx)?;
            }
        };

        Ok(())
    }
}

impl<'b, S, T, C> minicbor::decode::Decode<'b, C> for Either<S, T>
where
    S: minicbor::Decode<'b, C> + Ord,
    T: minicbor::Decode<'b, C> + Ord,
{
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        d.array()?;
        match d.u8()? {
            0 => Ok(Either::Left(d.decode_with(ctx)?)),
            1 => Ok(Either::Right(d.decode_with(ctx)?)),
            _ => Err(minicbor::decode::Error::message(
                "unknown cbor variant for `Either` enum",
            )),
        }
    }
}

impl<S, T, C> minicbor::encode::Encode<C> for Either<S, T>
where
    S: Clone + minicbor::Encode<C>,
    T: Clone + minicbor::Encode<C>,
{
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.array(2)?;
        match self {
            Either::Left(x) => {
                e.u8(0)?;
                e.encode_with(x, ctx)?;
            }
            Either::Right(x) => {
                e.u8(1)?;
                e.encode_with(x, ctx)?;
            }
        }

        Ok(())
    }
}

impl<'b, C> minicbor::decode::Decode<'b, C> for DRep {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        d.array()?;
        match d.u16()? {
            0 => Ok(Self::KeyHash(d.decode()?)),
            1 => Ok(Self::ScriptHash(d.decode()?)),
            2 => Ok(Self::AlwaysAbstain),
            3 => Ok(Self::AlwaysNoConfidence),
            _ => unreachable!(),
        }
    }
}

impl<C> minicbor::encode::Encode<C> for DRep {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            DRep::KeyHash(bytes) => {
                e.array(2)?;
                e.u16(0)?;
                e.encode(bytes)?;
            }
            DRep::ScriptHash(bytes) => {
                e.array(2)?;
                e.u16(1)?;
                e.encode(bytes)?;
            }
            DRep::AlwaysAbstain => {
                e.array(1)?;
                e.u16(2)?;
            }
            DRep::AlwaysNoConfidence => {
                e.array(1)?;
                e.u16(3)?;
            }
        }
        Ok(())
    }
}

impl<'b, C> minicbor::decode::Decode<'b, C> for CommitteeAuthorization {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        d.array()?;
        match d.u16()? {
            0 => Ok(Self::HotCredential(d.decode()?)),
            1 => Ok(Self::MemberResigned(d.decode()?)),
            _ => unreachable!(),
        }
    }
}

impl<C> minicbor::encode::Encode<C> for CommitteeAuthorization {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            CommitteeAuthorization::HotCredential(credential) => {
                e.array(2)?;
                e.u16(0)?;
                e.encode(credential)?;
            }
            CommitteeAuthorization::MemberResigned(anchor) => {
                e.array(2)?;
                e.u16(1)?;
                e.encode(anchor)?;
            }
        }
        Ok(())
    }
}

impl<'b, C> minicbor::decode::Decode<'b, C> for FuturePParams {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        d.array()?;
        match d.u16()? {
            0 => Ok(FuturePParams::NoPParamsUpdate),
            1 => Ok(FuturePParams::DefinitePParamsUpdate(d.decode()?)),
            2 => Ok(FuturePParams::PotentialPParamsUpdate(d.decode()?)),
            _ => unreachable!(),
        }
    }
}

impl<C> minicbor::encode::Encode<C> for FuturePParams {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            FuturePParams::NoPParamsUpdate => {
                e.array(1)?;
                e.u16(0)?;
            }
            FuturePParams::DefinitePParamsUpdate(param) => {
                e.array(2)?;
                e.u16(1)?;
                e.encode(param)?;
            }
            FuturePParams::PotentialPParamsUpdate(maybe_param) => {
                e.array(2)?;
                e.u16(2)?;
                e.encode(maybe_param)?;
            }
        }
        Ok(())
    }
}

impl<'b, C> minicbor::decode::Decode<'b, C> for GovAction {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        d.array()?;
        match d.u16()? {
            0 => Ok(Self::ParameterChange(d.decode()?, d.decode()?, d.decode()?)),
            1 => Ok(Self::HardForkInitiation(d.decode()?, d.decode()?)),
            2 => Ok(Self::TreasuryWithdrawals(d.decode()?, d.decode()?)),
            3 => Ok(Self::NoConfidence(d.decode()?)),
            4 => Ok(Self::UpdateCommittee(
                d.decode()?,
                d.decode()?,
                d.decode()?,
                d.decode()?,
            )),
            5 => Ok(Self::NewConstitution(d.decode()?, d.decode()?)),
            6 => Ok(Self::InfoAction),
            _ => unreachable!(),
        }
    }
}

impl<C> minicbor::encode::Encode<C> for GovAction {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            GovAction::ParameterChange(sm_id, params, hash) => {
                e.array(4)?;
                e.u16(0)?;
                e.encode(sm_id)?;
                e.encode(params)?;
                e.encode(hash)?;
            }
            GovAction::HardForkInitiation(sm_id, version) => {
                e.array(3)?;
                e.u16(1)?;
                e.encode(sm_id)?;
                e.encode(version)?;
            }
            GovAction::TreasuryWithdrawals(withdrawals, hash) => {
                e.array(3)?;
                e.u16(2)?;
                e.encode(withdrawals)?;
                e.encode(hash)?;
            }
            GovAction::NoConfidence(sm_id) => {
                e.array(2)?;
                e.u16(3)?;
                e.encode(sm_id)?;
            }
            GovAction::UpdateCommittee(sm_id, removed, added, threshold) => {
                e.array(5)?;
                e.u16(4)?;
                e.encode(sm_id)?;
                e.encode(removed)?;
                e.encode(added)?;
                e.encode(threshold)?;
            }
            GovAction::NewConstitution(sm_id, constitution) => {
                e.array(3)?;
                e.u16(5)?;
                e.encode(sm_id)?;
                e.encode(constitution)?;
            }
            GovAction::InfoAction => {
                e.array(1)?;
                e.u16(6)?;
            }
        }
        Ok(())
    }
}

impl<'b, C> minicbor::decode::Decode<'b, C> for HotCredAuthStatus {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        d.array()?;
        match d.u16()? {
            0 => Ok(Self::MemberAuthorized(d.decode()?)),
            1 => Ok(Self::MemberNotAuthorized),
            2 => Ok(Self::MemberResigned(d.decode()?)),
            _ => Err(minicbor::decode::Error::message(
                "Unknown variant for HotCredAuthStatus",
            )),
        }
    }
}

impl<C> minicbor::encode::Encode<C> for HotCredAuthStatus {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            HotCredAuthStatus::MemberAuthorized(credential) => {
                e.array(2)?;
                e.u16(0)?;
                e.encode(credential)?;
            }
            HotCredAuthStatus::MemberNotAuthorized => {
                e.array(1)?;
                e.u16(1)?;
            }
            HotCredAuthStatus::MemberResigned(anchor) => {
                e.array(2)?;
                e.u16(2)?;
                e.encode(anchor)?;
            }
        }
        Ok(())
    }
}

impl<'b, C> minicbor::decode::Decode<'b, C> for NextEpochChange {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        d.array()?;
        match d.u16()? {
            0 => Ok(Self::ToBeEnacted),
            1 => Ok(Self::ToBeRemoved),
            2 => Ok(Self::NoChangeExpected),
            3 => Ok(Self::ToBeExpired),
            4 => Ok(Self::TermAdjusted(d.decode()?)),
            _ => unreachable!(),
        }
    }
}

impl<C> minicbor::encode::Encode<C> for NextEpochChange {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::ToBeEnacted => {
                e.array(1)?;
                e.u16(0)?;
            }
            Self::ToBeRemoved => {
                e.array(1)?;
                e.u16(1)?;
            }
            Self::NoChangeExpected => {
                e.array(1)?;
                e.u16(2)?;
            }
            Self::ToBeExpired => {
                e.array(1)?;
                e.u16(3)?;
            }
            Self::TermAdjusted(epoch) => {
                e.array(2)?;
                e.u16(4)?;
                e.encode(epoch)?;
            }
        }
        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for CostModels {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let models: KeyValuePairs<u64, CostModel> = d.decode_with(ctx)?;

        let mut plutus_v1 = None;
        let mut plutus_v2 = None;
        let mut plutus_v3 = None;
        let mut plutus_v4 = None;
        let mut unknown: Vec<(u64, CostModel)> = Vec::new();

        for (k, v) in models.iter() {
            match k {
                0 => plutus_v1 = Some(v.clone()),
                1 => plutus_v2 = Some(v.clone()),
                2 => plutus_v3 = Some(v.clone()),
                3 => plutus_v4 = Some(v.clone()),
                _ => unknown.push((*k, v.clone())),
            }
        }

        Ok(Self {
            plutus_v1,
            plutus_v2,
            plutus_v3,
            plutus_v4,
            unknown: unknown.into(),
        })
    }
}

impl<C> minicbor::Encode<C> for CostModels {
    /// Writes every model that arrived, under the key it arrived under.
    ///
    /// The named fields go out first in key order and `unknown` follows, which
    /// is the order the node writes and the order the decoder above reads back
    /// into the same value.
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let named = [
            (0u64, self.plutus_v1.as_ref()),
            (1, self.plutus_v2.as_ref()),
            (2, self.plutus_v3.as_ref()),
            (3, self.plutus_v4.as_ref()),
        ];

        let present =
            named.iter().filter(|(_, model)| model.is_some()).count() + self.unknown.len();
        e.map(present as u64)?;

        for (key, model) in named.iter() {
            if let Some(model) = model {
                e.u64(*key)?;
                encode_cost_model(e, model)?;
            }
        }

        for (key, model) in self.unknown.iter() {
            e.u64(*key)?;
            encode_cost_model(e, model)?;
        }

        Ok(())
    }
}

/// Writes one cost model as the indefinite length array a node writes.
///
/// The Haskell encoder the node runs writes a list that way, and the captured
/// reply in `test_data` carries all four of its models as `0x9f ... 0xff`. A
/// definite array holds the same numbers, so a client that reads one is no
/// worse off, but a reply re-encoded with definite arrays is no longer the
/// bytes the node sent and cannot be compared with them or served on.
fn encode_cost_model<W: minicbor::encode::Write>(
    e: &mut minicbor::Encoder<W>,
    model: &CostModel,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    e.begin_array()?;

    for cost in model {
        e.i64(*cost)?;
    }

    e.end()?;

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use pallas_codec::minicbor;

    /// Decode/encode roundtrip tests for the localstate example queries/results.
    #[test]
    #[cfg(feature = "blueprint")]
    fn test_api_example_roundtrip() {
        use crate::miniprotocols::localstate::{
            Message,
            queries_v16::{Request, SystemStart},
        };
        use pallas_codec::utils::AnyCbor;

        macro_rules! include_example_pair {
            ($path:literal) => {
                (include_str!(concat!(
                    "../../../../../cardano-blueprint/src/client/node-to-client/state-query/examples/",
                    $path,
                    "/query.cbor"
                ))
                , include_str!(concat!(
                    "../../../../../cardano-blueprint/src/client/node-to-client/state-query/examples/",
                    $path,
                    "/result.cbor"
                ))
                 )
            };
        }

        let examples = [include_example_pair!("getSystemStart")];
        for (idx, (query_str, result_str)) in examples.iter().enumerate() {
            println!("Roundtrip query {idx}");
            roundtrips_with(query_str, |q| match q {
                Message::Query(cbor) => {
                    let request = minicbor::decode(&cbor[..]).unwrap_or_else(|e| {
                        panic!("error decoding cbor from query message: {e:?}")
                    });
                    match request {
                        Request::GetSystemStart => Message::Query(AnyCbor::from_encode(request)),
                        _ => panic!("unexpected query type"),
                    }
                }
                _ => panic!("unexpected message type"),
            });

            println!("Roundtrip result {idx}");
            roundtrips_with(result_str, |q| match q {
                Message::Result(cbor) => {
                    let result = minicbor::decode::<SystemStart>(&cbor[..]).unwrap_or_else(|e| {
                        panic!("error decoding cbor from query message: {e:?}")
                    });
                    Message::Result(AnyCbor::from_encode(result))
                }
                _ => panic!("unexpected message type"),
            });
        }
    }

    /// Encode-then-decode roundtrip for the `BlockQuery` variants added for
    /// the post-V_16 NodeToClient versions (up to V_23 / van Rossem).
    /// This validates internal codec consistency only — byte-for-byte
    /// agreement with a live node should be confirmed at integration time.
    #[test]
    fn test_post_v16_block_queries_roundtrip() {
        use crate::miniprotocols::localstate::queries_v16::{BlockQuery, LedgerPeerSnapshotKind};
        use crate::miniprotocols::localtxsubmission::TaggedSet;

        let cases = vec![
            BlockQuery::GetBigLedgerPeerSnapshot,
            BlockQuery::GetLedgerPeerSnapshot(LedgerPeerSnapshotKind::All),
            BlockQuery::GetLedgerPeerSnapshot(LedgerPeerSnapshotKind::Big),
            BlockQuery::GetStakeDistribution2,
            BlockQuery::GetDRepsDelegations(TaggedSet::from(std::collections::BTreeSet::new())),
        ];

        for q in cases {
            let bytes = minicbor::to_vec(&q).expect("encode");
            let decoded: BlockQuery = minicbor::decode(&bytes).expect("decode");
            let bytes2 = minicbor::to_vec(&decoded).expect("re-encode");
            assert_eq!(
                hex::encode(&bytes),
                hex::encode(&bytes2),
                "roundtrip mismatch for {q:?}",
            );
        }
    }

    /// Spot-check the wire-level CBOR envelope of the new BlockQuery
    /// variants against the upstream Haskell encoder
    /// (`encodeShelleyQuery` in `ouroboros-consensus-cardano`).
    /// `minicbor` writes the minimal CBOR uint encoding, so tag values
    /// 24..=255 use the 1-byte minor type (`0x18 vv`), matching the
    /// upstream `encodeWord8` calls for BlockQuery dispatch tags.
    #[test]
    fn test_post_v16_block_queries_wire_shape() {
        use crate::miniprotocols::localstate::queries_v16::{BlockQuery, LedgerPeerSnapshotKind};
        use crate::miniprotocols::localtxsubmission::{SMaybe, TaggedSet};

        // [34] — legacy single-element form (NodeToClient v11–v14)
        let bytes = minicbor::to_vec(BlockQuery::GetBigLedgerPeerSnapshot).unwrap();
        assert_eq!(hex::encode(bytes), "811822");

        // [34, 0] — v15+ form, peer-kind = All
        let bytes = minicbor::to_vec(BlockQuery::GetLedgerPeerSnapshot(
            LedgerPeerSnapshotKind::All,
        ))
        .unwrap();
        assert_eq!(hex::encode(bytes), "82182200");

        // [34, 1] — v15+ form, peer-kind = Big
        let bytes = minicbor::to_vec(BlockQuery::GetLedgerPeerSnapshot(
            LedgerPeerSnapshotKind::Big,
        ))
        .unwrap();
        assert_eq!(hex::encode(bytes), "82182201");

        // [36, SMaybe::None=[]] — GetPoolDistr2, no pool filter
        let bytes = minicbor::to_vec(BlockQuery::GetPoolDistr2(SMaybe::None)).unwrap();
        assert_eq!(hex::encode(bytes), "82182480");

        // [37] — GetStakeDistribution2, no payload
        let bytes = minicbor::to_vec(BlockQuery::GetStakeDistribution2).unwrap();
        assert_eq!(hex::encode(bytes), "811825");

        // [39, TaggedSet::empty=tag(258)[]] — GetDRepsDelegations, empty DRep set
        let bytes = minicbor::to_vec(BlockQuery::GetDRepsDelegations(TaggedSet::from(
            std::collections::BTreeSet::new(),
        )))
        .unwrap();
        assert_eq!(hex::encode(bytes), "821827d9010280");
    }

    /// A Dijkstra protocol parameter value carrying, at the fifteen positions
    /// Dijkstra appends, the values the network reports for them.
    fn dijkstra_protocol_param_sample()
    -> crate::miniprotocols::localstate::queries_v16::DijkstraProtocolParam {
        use crate::miniprotocols::localstate::queries_v16::*;
        use pallas_codec::utils::{AnyUInt, Nullable};

        let ratio = |numerator, denominator| RationalNumber {
            numerator,
            denominator,
        };

        DijkstraProtocolParam {
            minfee_a: 44,
            minfee_b: 155381,
            max_block_body_size: 90112,
            max_transaction_size: 16384,
            max_block_header_size: 1100,
            key_deposit: AnyUInt::U32(2000000),
            pool_deposit: AnyUInt::U32(500000000),
            maximum_epoch: 18,
            desired_number_of_stake_pools: 150,
            pool_pledge_influence: ratio(3, 10),
            expansion_rate: ratio(3, 1000),
            treasury_growth_rate: ratio(1, 5),
            protocol_version: (12, 0),
            min_pool_cost: AnyUInt::U32(170000000),
            ada_per_utxo_byte: AnyUInt::U16(4310),
            cost_models_for_script_languages: CostModels {
                plutus_v1: Some(vec![100788, 420]),
                plutus_v2: None,
                plutus_v3: Some(vec![100788]),
                plutus_v4: None,
                unknown: Vec::new().into(),
            },
            execution_costs: ExUnitPrices {
                mem_price: ratio(577, 10000),
                step_price: ratio(721, 10000000),
            },
            max_tx_ex_units: ExUnits {
                mem: 16500000,
                steps: 10000000000,
            },
            max_block_ex_units: ExUnits {
                mem: 72000000,
                steps: 20000000000,
            },
            max_value_size: 5000,
            collateral_percentage: 150,
            max_collateral_inputs: 3,
            pool_voting_thresholds: PoolVotingThresholds {
                motion_no_confidence: ratio(51, 100),
                committee_normal: ratio(51, 100),
                committee_no_confidence: ratio(51, 100),
                hard_fork_initiation: ratio(51, 100),
                pp_security_group: ratio(51, 100),
            },
            drep_voting_thresholds: DRepVotingThresholds {
                motion_no_confidence: ratio(67, 100),
                committee_normal: ratio(67, 100),
                committee_no_confidence: ratio(3, 5),
                update_to_constitution: ratio(3, 4),
                hard_fork_initiation: ratio(3, 5),
                pp_network_group: ratio(67, 100),
                pp_economic_group: ratio(67, 100),
                pp_technical_group: ratio(67, 100),
                pp_gov_group: ratio(3, 4),
                treasury_withdrawal: ratio(67, 100),
            },
            min_committee_size: 3,
            committee_term_limit: 293,
            governance_action_validity_period: 120,
            governance_action_deposit: AnyUInt::U64(100000000000),
            drep_deposit: AnyUInt::U32(500000000),
            drep_inactivity_period: 20,
            minfee_refscript_cost_per_byte: ratio(15, 1),
            max_ref_script_size_per_block: 1048576,
            max_ref_script_size_per_tx: 204800,
            ref_script_cost_stride: 25600,
            ref_script_cost_multiplier: ratio(6, 5),
            max_pledge_leverage: Nullable::Null,
            min_pool_margin: ratio(3, 200),
            leios_announcement_period_length: 1000,
            leios_vote_period_length: 4000,
            leios_diffusion_period_length: 7000,
            leios_committee_size: 900,
            leios_quorum_stake_threshold: ratio(3, 4),
            max_endorser_block_references_size: 100000,
            max_endorser_block_txs_size: 1000000,
            max_endorser_block_ex_units: ExUnits {
                mem: 310000000,
                steps: 100000000000,
            },
            max_ref_script_size_per_endorser_block: 4000000,
        }
    }

    /// The forty six entries go out as one definite array and come back
    /// carrying the same values, including the four reference script appends,
    /// which are named here by value so the test says what those positions
    /// mean. The eleven entries after them are named the same way by
    /// [`test_dijkstra_protocol_param_decodes_w36_reply`], against bytes this
    /// crate did not write.
    #[test]
    fn test_dijkstra_protocol_param_roundtrip() {
        let sample = dijkstra_protocol_param_sample();
        let bytes = minicbor::to_vec(&sample).expect("encode");

        // 0x98 0x2e is array(46), the header the ledger's own encoder writes
        // for `encodeListLen (length (eraPParams @DijkstraEra))`.
        assert_eq!(&bytes[..2], &[0x98, 0x2e]);

        let decoded: crate::miniprotocols::localstate::queries_v16::DijkstraProtocolParam =
            minicbor::decode(&bytes).expect("decode");
        assert_eq!(decoded, sample);
        assert_eq!(decoded.max_ref_script_size_per_block, 1048576);
        assert_eq!(decoded.max_ref_script_size_per_tx, 204800);
        assert_eq!(decoded.ref_script_cost_stride, 25600);
        assert_eq!(decoded.ref_script_cost_multiplier.numerator, 6);
        assert_eq!(decoded.ref_script_cost_multiplier.denominator, 5);
    }

    /// Any array that is not forty six entries long is refused, and the refusal
    /// names the length that arrived. Conway's 31 and the earlier Dijkstra 35
    /// are the two lengths that actually turn up in practice, from a decoder
    /// pointed at the wrong era or at a node built on an earlier ledger.
    #[test]
    fn test_dijkstra_protocol_param_refuses_other_lengths() {
        type Params = crate::miniprotocols::localstate::queries_v16::DijkstraProtocolParam;

        let good = minicbor::to_vec(dijkstra_protocol_param_sample()).expect("encode");
        let entries = &good[2..];

        let refusal = |bytes: &[u8]| match minicbor::decode::<Params>(bytes) {
            Ok(value) => panic!(
                "decoded {} bytes that are not 46 entries: {value:?}",
                bytes.len()
            ),
            Err(e) => e.to_string(),
        };

        // Conway's length, which is what a Conway node's answer looks like.
        let mut conway = vec![0x98, 0x1f];
        conway.extend_from_slice(entries);
        let said = refusal(&conway);
        assert!(said.contains("46"), "refusal does not name 46: {said}");
        assert!(said.contains("31"), "refusal does not name 31: {said}");

        // The Dijkstra length before the parameters below were added, which is
        // what a node built on cardano-ledger f3104f0 answers with.
        let mut earlier = vec![0x98, 0x23];
        earlier.extend_from_slice(entries);
        let said = refusal(&earlier);
        assert!(said.contains("46"), "refusal does not name 46: {said}");
        assert!(said.contains("35"), "refusal does not name 35: {said}");

        // One entry too many.
        let mut long = vec![0x98, 0x2f];
        long.extend_from_slice(entries);
        long.push(0x00);
        let said = refusal(&long);
        assert!(said.contains("47"), "refusal does not name 47: {said}");

        // A short array, refused on the header before any entry is read.
        let said = refusal(&[0x82, 0x00, 0x00]);
        assert!(said.contains('2'), "refusal does not name 2: {said}");

        // An indefinite array has no length to check, so it is refused too.
        let mut indefinite = vec![0x9f];
        indefinite.extend_from_slice(entries);
        indefinite.push(0xff);
        let said = refusal(&indefinite);
        assert!(
            said.contains("indefinite"),
            "refusal does not say indefinite: {said}"
        );
    }

    /// One CBOR fragment per entry of a `prototype-2026w36` protocol parameter
    /// reply, in the order of `eraPParams` for Dijkstra, each named by the
    /// field it belongs to.
    ///
    /// These bytes are hand built and not captured from a node. They are
    /// written from the CDDL rather than produced by this crate's own encoder,
    /// which is the point of them: a round trip through [`Encode`] and
    /// [`Decode`] agrees with itself whatever order the fields are in, and
    /// cannot say whether the order is the ledger's. The values of the first
    /// thirty five entries are the ones [`dijkstra_protocol_param_sample`]
    /// carries. The values of the last eleven are the ones the network's
    /// published dijkstra genesis gives those parameters, including a null
    /// `maxPledgeLeverage`.
    ///
    /// The captured reply beside them in `test_data` ends with exactly the last
    /// eleven of these fragments, which
    /// [`test_dijkstra_protocol_param_decodes_a_captured_reply`] checks.
    ///
    /// The cost model entry writes each of its models as an indefinite length
    /// array, which is the form all four models of the captured reply arrive
    /// in, and not a form chosen to suit this crate's encoder.
    const DIJKSTRA_W36_ENTRIES: [(&str, &str); 46] = [
        ("minfee_a", "182c"),
        ("minfee_b", "1a00025ef5"),
        ("max_block_body_size", "1a00016000"),
        ("max_transaction_size", "194000"),
        ("max_block_header_size", "19044c"),
        ("key_deposit", "1a001e8480"),
        ("pool_deposit", "1a1dcd6500"),
        ("maximum_epoch", "12"),
        ("desired_number_of_stake_pools", "1896"),
        ("pool_pledge_influence", "d81e82030a"),
        ("expansion_rate", "d81e82031903e8"),
        ("treasury_growth_rate", "d81e820105"),
        ("protocol_version", "820c00"),
        ("min_pool_cost", "1a0a21fe80"),
        ("ada_per_utxo_byte", "1910d6"),
        (
            "cost_models_for_script_languages",
            "a2009f1a000189b41901a4ff029f1a000189b4ff",
        ),
        (
            "execution_costs",
            "82d81e82190241192710d81e821902d11a00989680",
        ),
        ("max_tx_ex_units", "821a00fbc5201b00000002540be400"),
        ("max_block_ex_units", "821a044aa2001b00000004a817c800"),
        ("max_value_size", "191388"),
        ("collateral_percentage", "1896"),
        ("max_collateral_inputs", "03"),
        (
            "pool_voting_thresholds",
            "85d81e8218331864d81e8218331864d81e8218331864d81e8218331864d81e8218331864",
        ),
        (
            "drep_voting_thresholds",
            "8ad81e8218431864d81e8218431864d81e820305d81e820304d81e820305d81e8218431864d81e8218431864d81e8218431864d81e820304d81e8218431864",
        ),
        ("min_committee_size", "03"),
        ("committee_term_limit", "190125"),
        ("governance_action_validity_period", "1878"),
        ("governance_action_deposit", "1b000000174876e800"),
        ("drep_deposit", "1a1dcd6500"),
        ("drep_inactivity_period", "14"),
        ("minfee_refscript_cost_per_byte", "d81e820f01"),
        ("max_ref_script_size_per_block", "1a00100000"),
        ("max_ref_script_size_per_tx", "1a00032000"),
        ("ref_script_cost_stride", "196400"),
        ("ref_script_cost_multiplier", "d81e820605"),
        ("max_pledge_leverage", "f6"),
        ("min_pool_margin", "d81e820318c8"),
        ("leios_announcement_period_length", "1903e8"),
        ("leios_vote_period_length", "190fa0"),
        ("leios_diffusion_period_length", "191b58"),
        ("leios_committee_size", "190384"),
        ("leios_quorum_stake_threshold", "d81e820304"),
        ("max_endorser_block_references_size", "1a000186a0"),
        ("max_endorser_block_txs_size", "1a000f4240"),
        (
            "max_endorser_block_ex_units",
            "821a127a39801b000000174876e800",
        ),
        ("max_ref_script_size_per_endorser_block", "1a003d0900"),
    ];

    /// The entries above behind the array header the ledger's encoder writes
    /// for forty six parameters, which is `0x98 0x2e`, with one named entry's
    /// fragment replaced, so a case the live network does not currently produce
    /// can still be put to the decoder.
    fn dijkstra_w36_reply_bytes(replace: (&str, &str)) -> Vec<u8> {
        let (target, with) = replace;
        let mut replaced = false;

        let mut bytes = vec![0x98, 0x2e];
        for (name, fragment) in DIJKSTRA_W36_ENTRIES {
            let fragment = if name == target {
                replaced = true;
                with
            } else {
                fragment
            };
            let raw =
                hex::decode(fragment).unwrap_or_else(|e| panic!("bad fragment for {name}: {e:?}"));
            bytes.extend_from_slice(&raw);
        }

        assert!(replaced, "no entry is named {target}");
        bytes
    }

    /// The `GetCurrentPParams` reply captured from a node running
    /// `prototype-2026w36`, as the node wrote it. Provenance is in the sibling
    /// markdown note.
    const DIJKSTRA_CAPTURED_REPLY: &str =
        include_str!("../../../../../test_data/dijkstra-pparams-w36.hex");

    /// A reply a node actually sent decodes, the eleven entries the w36 ledger
    /// adds arrive under the names they have in the genesis that set them, and
    /// those eleven entries go back out as the same bytes. A field read from
    /// the wrong position would carry a neighbour's value here.
    ///
    /// The tail check is the order claim: both the captured reply and the value
    /// encoded back out end with the last eleven fragments of
    /// [`DIJKSTRA_W36_ENTRIES`], which were written from the CDDL, so the
    /// eleven parameters are appended in that order with those encodings rather
    /// than inserted somewhere earlier.
    ///
    /// The node writes four cost models, one of them at key 3 for Plutus v4,
    /// each as an indefinite array, and all four arrive under a named field of
    /// [`CostModels`] and go back out from one.
    /// [`test_dijkstra_protocol_param_reencodes_a_captured_reply_byte_for_byte`]
    /// is the whole reply put the same way in one comparison.
    #[test]
    fn test_dijkstra_protocol_param_decodes_a_captured_reply() {
        use pallas_codec::utils::Nullable;

        let bytes = hex::decode(DIJKSTRA_CAPTURED_REPLY.trim()).expect("the captured reply is hex");
        assert_eq!(bytes.len(), 3756);
        assert_eq!(&bytes[..2], &[0x98, 0x2e]);

        let mut tail = String::new();
        for (_, fragment) in &DIJKSTRA_W36_ENTRIES[35..] {
            tail.push_str(fragment);
        }
        let captured = hex::encode(&bytes);
        assert!(
            captured.ends_with(&tail),
            "the captured reply does not end with the eleven appended entries: {tail}"
        );

        let decoded: crate::miniprotocols::localstate::queries_v16::DijkstraProtocolParam =
            minicbor::decode(&bytes).expect("decode the captured reply");

        let reencoded = hex::encode(minicbor::to_vec(&decoded).expect("encode"));
        assert!(
            reencoded.ends_with(&tail),
            "the eleven appended entries do not go back out as they came in: {reencoded}"
        );

        // The Plutus v4 cost model the node sent lands in the field named for
        // it, and no key of this reply falls through to `unknown`.
        let models = &decoded.cost_models_for_script_languages;
        let unknown: Vec<u64> = models.unknown.iter().map(|(k, _)| *k).collect();
        assert_eq!(unknown, Vec::<u64>::new());
        assert_eq!(models.plutus_v4.as_ref().expect("plutus v4").len(), 251);
        assert_eq!(models.plutus_v1.as_ref().expect("plutus v1").len(), 332);
        assert_eq!(models.plutus_v2.as_ref().expect("plutus v2").len(), 332);
        assert_eq!(models.plutus_v3.as_ref().expect("plutus v3").len(), 350);

        // maxPledgeLeverage is null in the published genesis, and null is a
        // value the node sent rather than an entry it left out.
        assert_eq!(decoded.max_pledge_leverage, Nullable::Null);
        assert_eq!(decoded.min_pool_margin.numerator, 3);
        assert_eq!(decoded.min_pool_margin.denominator, 200);
        assert_eq!(decoded.leios_announcement_period_length, 1000);
        assert_eq!(decoded.leios_vote_period_length, 4000);
        assert_eq!(decoded.leios_diffusion_period_length, 7000);
        assert_eq!(decoded.leios_committee_size, 900);
        assert_eq!(decoded.leios_quorum_stake_threshold.numerator, 3);
        assert_eq!(decoded.leios_quorum_stake_threshold.denominator, 4);
        assert_eq!(decoded.max_endorser_block_references_size, 100000);
        assert_eq!(decoded.max_endorser_block_txs_size, 1000000);
        assert_eq!(decoded.max_endorser_block_ex_units.mem, 310000000);
        assert_eq!(decoded.max_endorser_block_ex_units.steps, 100000000000);
        assert_eq!(decoded.max_ref_script_size_per_endorser_block, 4000000);

        // The four entries before them keep the values they had at the earlier
        // ledger commit, which is what says the eleven were appended rather
        // than inserted.
        assert_eq!(decoded.max_ref_script_size_per_block, 1048576);
        assert_eq!(decoded.max_ref_script_size_per_tx, 204800);
        assert_eq!(decoded.ref_script_cost_stride, 25600);
        assert_eq!(decoded.ref_script_cost_multiplier.numerator, 6);
        assert_eq!(decoded.ref_script_cost_multiplier.denominator, 5);
    }

    /// MUST FIRE: the reply a node actually sent goes back out as the bytes
    /// that came in, all three thousand seven hundred and fifty six of them.
    ///
    /// A decoder that drops a value it read says nothing about having dropped
    /// it, and the value is gone from every consumer downstream. Comparing the
    /// whole reply is what catches that, because a dropped entry, a reordered
    /// one and a re-spelled one all change these bytes, while a round trip
    /// through this crate's own encoder and decoder agrees with itself in every
    /// one of those cases.
    ///
    /// The failure names the first byte that differs and the window around it,
    /// so a break here says which entry lost what rather than that something
    /// somewhere is not equal.
    #[test]
    fn test_dijkstra_protocol_param_reencodes_a_captured_reply_byte_for_byte() {
        let bytes = hex::decode(DIJKSTRA_CAPTURED_REPLY.trim()).expect("the captured reply is hex");

        let decoded: crate::miniprotocols::localstate::queries_v16::DijkstraProtocolParam =
            minicbor::decode(&bytes).expect("decode the captured reply");
        let reencoded = minicbor::to_vec(&decoded).expect("encode");

        if reencoded != bytes {
            let at = bytes
                .iter()
                .zip(reencoded.iter())
                .position(|(a, b)| a != b)
                .unwrap_or_else(|| bytes.len().min(reencoded.len()));
            let window = |v: &[u8]| hex::encode(&v[at.min(v.len())..(at + 24).min(v.len())]);

            panic!(
                "the captured reply does not go back out as it came in: {} bytes in, {} bytes out, first difference at byte {at}\n  wire {}\n  ours {}",
                bytes.len(),
                reencoded.len(),
                window(&bytes),
                window(&reencoded),
            );
        }
    }

    /// MUST FIRE: a cost model entry carrying three languages and no fourth,
    /// which is what a Conway node sends, comes back under the three names and
    /// goes out as the bytes it came in.
    ///
    /// The bytes here are written by hand, so the map header, the key order and
    /// the array form are the wire's claim about the shape rather than this
    /// crate's own encoder agreeing with itself.
    #[test]
    fn test_cost_models_with_three_languages_round_trip() {
        use crate::miniprotocols::localstate::queries_v16::CostModels;

        // a map of three, keys 0, 1 and 2, each an indefinite length array
        let wire = hex::decode("a3009f1a000189b41901a4ff019f1a000189b4ff029f2002ff").expect("hex");

        let models: CostModels = minicbor::decode(&wire).expect("decode three cost models");

        assert_eq!(models.plutus_v1, Some(vec![100788, 420]));
        assert_eq!(models.plutus_v2, Some(vec![100788]));
        assert_eq!(models.plutus_v3, Some(vec![-1, 2]));
        assert_eq!(models.plutus_v4, None);
        assert!(models.unknown.is_empty());

        assert_eq!(
            hex::encode(minicbor::to_vec(&models).expect("encode")),
            hex::encode(&wire)
        );
    }

    /// MUST FIRE: a model under a key none of the named fields covers is
    /// carried by its number and written back, so a language the ledger adds
    /// before this type has a name for it survives a decode and an encode
    /// instead of disappearing between them.
    #[test]
    fn test_a_cost_model_beyond_the_named_languages_round_trips() {
        use crate::miniprotocols::localstate::queries_v16::CostModels;

        // one model at key 4, which no field here is named for
        let wire = hex::decode("a1049f0102ff").expect("hex");

        let models: CostModels = minicbor::decode(&wire).expect("decode an unnamed cost model");

        assert_eq!(models.plutus_v4, None);
        let carried: Vec<(u64, Vec<i64>)> = models.unknown.iter().cloned().collect();
        assert_eq!(carried, vec![(4u64, vec![1i64, 2])]);

        assert_eq!(
            hex::encode(minicbor::to_vec(&models).expect("encode")),
            hex::encode(&wire)
        );
    }

    /// The other side of the pledge leverage rule. When the entry is an
    /// interval rather than a null the field carries the interval, so
    /// [`Nullable::Null`] means the node said null and not that the decoder
    /// gives up on anything it does not recognise.
    #[test]
    fn test_dijkstra_protocol_param_reads_a_set_pledge_leverage() {
        use pallas_codec::utils::Nullable;

        // d81e820902 is #6.30([9, 2]), a max pledge leverage of 4.5.
        let bytes = dijkstra_w36_reply_bytes(("max_pledge_leverage", "d81e820902"));

        let decoded: crate::miniprotocols::localstate::queries_v16::DijkstraProtocolParam =
            minicbor::decode(&bytes).expect("decode a reply with a set pledge leverage");

        match decoded.max_pledge_leverage {
            Nullable::Some(ref interval) => {
                assert_eq!(interval.numerator, 9);
                assert_eq!(interval.denominator, 2);
            }
            ref other => panic!("expected an interval, found {other:?}"),
        }

        // The entry after it is unmoved, so the interval was read as one entry
        // and not as a prefix of the next.
        assert_eq!(decoded.min_pool_margin.numerator, 3);
        assert_eq!(decoded.min_pool_margin.denominator, 200);
        assert_eq!(
            hex::encode(minicbor::to_vec(&decoded).expect("encode")),
            hex::encode(&bytes)
        );
    }

    // TODO: DRY with other decode/encode roundtripss
    // Decode a value of type T, transform it to U and encode that again to form a roundtrip.
    #[cfg(feature = "blueprint")]
    fn roundtrips_with<T, U>(message_str: &str, transform: fn(T) -> U)
    where
        T: for<'b> minicbor::Decode<'b, ()> + std::fmt::Debug,
        U: std::fmt::Debug + minicbor::Encode<()>,
    {
        let bytes = hex::decode(message_str).unwrap_or_else(|e| panic!("bad message file: {e:?}"));

        let value: T =
            minicbor::decode(&bytes[..]).unwrap_or_else(|e| panic!("error decoding cbor: {e:?}"));
        println!("Decoded value: {:#?}", value);

        let result: U = transform(value);
        println!("Transformed to: {:#?}", result);

        let bytes2 =
            minicbor::to_vec(result).unwrap_or_else(|e| panic!("error encoding cbor: {e:?}"));

        assert_eq!(hex::encode(bytes), hex::encode(bytes2));
    }
}
