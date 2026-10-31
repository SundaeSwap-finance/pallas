// Appended to an isolated copy of Dolos's tests/dijkstra_ttl.rs by reproduce-callers.sh.
// Synthetic offline UTxO mutation: the original signed TTL transaction is unchanged.
// The added native reference script is unused; its guard need not be present.
#[test]
fn native_guard_reference_spent_input_reaches_all_dolos_callers() {
    use pallas::codec::{
        minicbor,
        utils::{CborWrap, KeepRaw},
    };
    use pallas::ledger::{
        primitives::{conway as c, dijkstra as n},
        traverse::{MultiEraOutput, OriginalHash},
    };

    let fixture = PathBuf::from(std::env::var_os("PALLAS_GUARD_FIXTURE").unwrap());
    for name in ["direct.hex", "nested.hex", "script-credential.hex"] {
        let (domain, bytes) = fixture_from(&root().join("confirmed-ttl"));
        let original = MultiEraTx::decode_for_era(Era::Dijkstra, &bytes).unwrap();
        let input = &original.as_dijkstra().unwrap().transaction_body.inputs[0];
        let out_ref = TxoRef(input.transaction_id, input.index.try_into().unwrap());
        let original_utxos = domain.state().get_utxos(vec![out_ref.clone()]).unwrap();
        let raw_output = original_utxos.get(&out_ref).unwrap();
        let view = MultiEraOutput::try_from(raw_output.as_ref()).unwrap();
        let raw_script =
            hex::decode(std::fs::read_to_string(fixture.join(name)).unwrap().trim()).unwrap();
        let native: KeepRaw<'_, n::NativeScript> = minicbor::decode(&raw_script).unwrap();
        let expected_hash = native.original_hash();
        let output = n::TransactionOutput::PostAlonzo(
            n::PostAlonzoTransactionOutput {
                address: view.address().unwrap().to_vec().into(),
                value: view.value().into_conway(),
                datum_option: view
                    .datum()
                    .map(|datum| match datum {
                        c::DatumOption::Hash(hash) => c::DatumOption::Hash(hash),
                        c::DatumOption::Data(data) => {
                            c::DatumOption::Data(CborWrap(data.0.unwrap().into()))
                        }
                    })
                    .map(Into::into),
                script_ref: Some(CborWrap(n::ScriptRef::NativeScript(native))),
            }
            .into(),
        );
        let output_bytes = minicbor::to_vec(&output).unwrap();
        let decoded = MultiEraOutput::decode(Era::Dijkstra, &output_bytes).unwrap();
        let script = decoded.multi_era_script_ref().unwrap();
        assert_eq!(script.hash(), expected_hash);
        assert_eq!(script.native_script().unwrap().encode(), raw_script);
        let mut delta = UtxoSetDelta::default();
        delta
            .produced_utxo
            .insert(out_ref, Arc::new(EraCbor(8, output_bytes)));
        let writer = domain.state().start_writer().unwrap();
        writer.apply_utxoset(&delta).unwrap();
        writer.commit().unwrap();
        let utxos = MempoolAwareUtxoStore::<ToyDomain>::new(domain.state(), domain.mempool());
        for report in [
            dolos_cardano::validate::evaluate_tx(&bytes, &utxos).unwrap(),
            dolos_cardano::validate::estimate_tx(&bytes, &utxos).unwrap(),
        ] {
            assert_eq!(report.len(), 1);
            assert!(report[0].success, "{name}: {report:?}");
        }
        let calls = dolos_cardano::validate::estimate_tx_calls(&bytes, &utxos).unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].0.success, "{name}: {calls:?}");
        assert!(!calls[0].1.is_empty());
        // Historical parameters are unchanged, including reference script fees.
        assert!(
            original.fee().unwrap()
                >= dolos_cardano::validate::min_fee(&bytes, &utxos)
                    .unwrap()
                    .unwrap()
        );
        let hash = domain
            .receive_tx(
                "offline native guard reference",
                &domain.read_chain(),
                &bytes,
            )
            .unwrap();
        assert_eq!(hash, original.hash());
        let pending = domain.mempool().peek_pending().remove(0);
        assert_eq!(pending.payload.1, bytes);
    }
}
