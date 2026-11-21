//! UTxO replies of the local state query in the Dijkstra era.

use pallas_codec::minicbor::{self, Decode, Decoder, Encode, Encoder, data::Type, decode, encode};
use pallas_codec::utils::{Bytes, CborWrap, KeyValuePairs};

pub use super::{DatumOption, LegacyTransactionOutput, UTxO, Value};
use crate::miniprotocols::localtxsubmission::native_script::impl_native_script;
pub use crate::miniprotocols::localtxsubmission::primitives::{
    AddrKeyhash, PlutusScript, StakeCredential,
};

pub type UTxOByAddress = KeyValuePairs<UTxO, TransactionOutput>;

pub type UTxOByTxin = UTxOByAddress;

pub type UTxOWhole = UTxOByAddress;

/// Transaction output of a Dijkstra UTxO reply, in its map or array form.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TransactionOutput {
    Current(PostAlonsoTransactionOutput),
    Legacy(LegacyTransactionOutput),
}

/// Map form of a Dijkstra transaction output.
#[derive(Debug, Encode, PartialEq, Eq, Clone)]
#[cbor(map)]
pub struct PostAlonsoTransactionOutput {
    #[n(0)]
    pub address: Bytes,

    #[n(1)]
    pub amount: Value,

    #[n(2)]
    pub inline_datum: Option<DatumOption>,

    #[n(3)]
    pub script_ref: Option<CborWrap<ScriptRef>>,
}

/// Script a Dijkstra output holds as its reference script.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ScriptRef {
    NativeScript(NativeScript),
    PlutusV1Script(PlutusScript<1>),
    PlutusV2Script(PlutusScript<2>),
    PlutusV3Script(PlutusScript<3>),
    PlutusV4Script(PlutusScript<4>),
}

/// Native script of the Dijkstra era, the Shelley scripts and a guard credential.
#[derive(Debug)]
pub enum NativeScript {
    ScriptPubkey(AddrKeyhash),
    ScriptAll(Vec<NativeScript>),
    ScriptAny(Vec<NativeScript>),
    ScriptNOfK(i64, Vec<NativeScript>),
    InvalidBefore(u64),
    InvalidHereafter(u64),
    ScriptRequireGuard(StakeCredential),
}

impl_native_script!(NativeScript { 6 => ScriptRequireGuard(StakeCredential) });

impl<'b, C> Decode<'b, C> for TransactionOutput {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, decode::Error> {
        match d.datatype()? {
            Type::Map | Type::MapIndef => Ok(Self::Current(d.decode_with(ctx)?)),
            Type::Array | Type::ArrayIndef => Ok(Self::Legacy(d.decode_with(ctx)?)),
            _ => Err(decode::Error::message(
                "unknown cbor data type for TransactionOutput enum",
            )),
        }
    }
}

impl<C> Encode<C> for TransactionOutput {
    fn encode<W: encode::Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), encode::Error<W::Error>> {
        match self {
            Self::Current(x) => e.encode_with(x, ctx)?,
            Self::Legacy(x) => e.encode_with(x, ctx)?,
        };

        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for PostAlonsoTransactionOutput {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, decode::Error> {
        let len = d.map()?;
        let mut read = 0;
        let mut address = None;
        let mut amount = None;
        let mut inline_datum = None;
        let mut script_ref = None;

        while match len {
            Some(len) => read < len,
            None => d.datatype()? != Type::Break,
        } {
            match d.i64()? {
                0 => address = Some(d.decode_with(ctx)?),
                1 => amount = Some(d.decode_with(ctx)?),
                2 => inline_datum = Some(d.decode_with(ctx)?),
                3 => script_ref = Some(d.decode_with(ctx)?),
                key => {
                    return Err(decode::Error::message(format!(
                        "unknown key for transaction output: {key}"
                    )));
                }
            }
            read += 1;
        }

        if len.is_none() {
            d.skip()?;
        }

        Ok(Self {
            address: address.ok_or_else(|| decode::Error::missing_value(0))?,
            amount: amount.ok_or_else(|| decode::Error::missing_value(1))?,
            inline_datum,
            script_ref,
        })
    }
}

impl<'b, C> Decode<'b, C> for ScriptRef {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, decode::Error> {
        d.array()?;

        match d.u8()? {
            0 => Ok(Self::NativeScript(d.decode_with(ctx)?)),
            1 => Ok(Self::PlutusV1Script(d.decode_with(ctx)?)),
            2 => Ok(Self::PlutusV2Script(d.decode_with(ctx)?)),
            3 => Ok(Self::PlutusV3Script(d.decode_with(ctx)?)),
            4 => Ok(Self::PlutusV4Script(d.decode_with(ctx)?)),
            x => Err(decode::Error::message(format!(
                "invalid variant for script enum: {x}"
            ))),
        }
    }
}

impl<C> Encode<C> for ScriptRef {
    fn encode<W: encode::Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), encode::Error<W::Error>> {
        match self {
            Self::NativeScript(x) => e.encode_with((0, x), ctx)?,
            Self::PlutusV1Script(x) => e.encode_with((1, x), ctx)?,
            Self::PlutusV2Script(x) => e.encode_with((2, x), ctx)?,
            Self::PlutusV3Script(x) => e.encode_with((3, x), ctx)?,
            Self::PlutusV4Script(x) => e.encode_with((4, x), ctx)?,
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::UTxOByAddress;
    use pallas_codec::minicbor;

    const COIN: &str = "011a000f4240";

    fn reply(output: &str) -> Vec<u8> {
        let input = format!("825820{}01", "00".repeat(32));
        hex::decode(format!("a1{input}{output}")).unwrap()
    }

    fn address() -> String {
        format!("00581d61{}", "00".repeat(28))
    }

    fn output_with_script_ref(script_ref: &str) -> String {
        let len = script_ref.len() / 2;
        let header = if len < 24 {
            format!("{:02x}", 0x40 + len)
        } else {
            format!("58{len:02x}")
        };
        format!("a3{}{COIN}03d818{header}{script_ref}", address())
    }

    fn read(bytes: &[u8]) -> (String, String) {
        let reply: UTxOByAddress = minicbor::decode(bytes).unwrap();
        let written = hex::encode(minicbor::to_vec(&reply).unwrap());
        (format!("{reply:?}"), written)
    }

    fn reads_and_reencodes(bytes: &[u8]) -> String {
        let (debug, written) = read(bytes);
        assert_eq!(written, hex::encode(bytes));
        debug
    }

    fn refusal(bytes: &[u8]) -> String {
        minicbor::decode::<UTxOByAddress>(bytes)
            .expect_err("the reply is refused")
            .to_string()
    }

    #[test]
    fn a_reply_with_every_output_key_reads_and_reencodes() {
        let output = format!(
            "a4{}{COIN}0282005820{}03d81849820346450101002499",
            address(),
            "11".repeat(32)
        );

        let debug = reads_and_reencodes(&reply(&output));

        assert!(debug.contains("Hash("), "{debug}");
        assert!(debug.contains("PlutusV3Script"), "{debug}");
    }

    #[test]
    fn a_reply_with_only_the_required_output_keys_reads_and_reencodes() {
        reads_and_reencodes(&reply(&format!("a2{}{COIN}", address())));
    }

    #[test]
    fn a_reply_with_an_array_output_reads_and_reencodes() {
        let output = format!(
            "83581d61{}1a000f42405820{}",
            "00".repeat(28),
            "22".repeat(32)
        );

        let debug = reads_and_reencodes(&reply(&output));

        assert!(debug.contains("Legacy("), "{debug}");
    }

    #[test]
    fn a_reply_with_an_indefinite_output_map_reads() {
        let (_, written) = read(&reply(&format!("bf{}{COIN}ff", address())));

        assert_eq!(
            written,
            hex::encode(reply(&format!("a2{}{COIN}", address())))
        );
    }

    #[test]
    fn a_reply_with_a_repeated_output_key_reads_the_last_value() {
        let (debug, _) = read(&reply(&format!("a3{}{COIN}011a001e8480", address())));

        assert!(debug.contains("2000000"), "{debug}");
    }

    #[test]
    fn a_reply_with_an_unknown_output_key_is_refused() {
        let error = refusal(&reply(&format!("a3{}{COIN}0400", address())));

        assert!(
            error.contains("unknown key for transaction output: 4"),
            "{error}"
        );
    }

    #[test]
    fn a_reply_missing_the_output_amount_is_refused() {
        let error = refusal(&reply(&format!("a1{}", address())));

        assert!(error.contains("missing value"), "{error}");
    }

    #[test]
    fn a_reply_with_every_shelley_native_script_reads_and_reencodes() {
        let native = format!(
            "8201848200581c{}82028083030181820405820509",
            "00".repeat(28)
        );

        let debug = reads_and_reencodes(&reply(&output_with_script_ref(&format!("8200{native}"))));

        for variant in [
            "ScriptAll",
            "ScriptPubkey",
            "ScriptAny",
            "ScriptNOfK",
            "InvalidBefore",
            "InvalidHereafter",
        ] {
            assert!(debug.contains(variant), "{variant} in {debug}");
        }
    }

    #[test]
    fn a_reply_with_a_guard_native_script_reads_and_reencodes() {
        for (credential, read_as) in [
            (
                format!("8200581c{}", "00".repeat(28)),
                "ScriptRequireGuard(AddrKeyhash(",
            ),
            (
                format!("8201581c{}", "11".repeat(28)),
                "ScriptRequireGuard(ScriptHash(",
            ),
        ] {
            let script_ref = format!("82008206{credential}");

            let debug = reads_and_reencodes(&reply(&output_with_script_ref(&script_ref)));

            assert!(debug.contains(read_as), "{debug}");
        }
    }

    #[test]
    fn a_reply_with_a_native_script_variant_no_era_defines_is_refused() {
        let error = refusal(&reply(&output_with_script_ref("8200820700")));

        assert!(
            error.contains("unknown variant id for native script"),
            "{error}"
        );
    }

    #[test]
    fn a_reply_with_a_plutus_v4_script_reads_and_reencodes() {
        let debug = reads_and_reencodes(&reply(&output_with_script_ref("820446450101002499")));

        assert!(debug.contains("PlutusV4Script"), "{debug}");
    }

    #[test]
    fn a_reply_with_a_script_tag_no_era_defines_is_refused() {
        let error = refusal(&reply(&output_with_script_ref("820546450101002499")));

        assert!(
            error.contains("invalid variant for script enum: 5"),
            "{error}"
        );
    }
}
