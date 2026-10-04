use serde_json::json;
use u5c_chain_oracle::model::RefScript;
use u5c_chain_oracle::node;

const ADDRESS: &str = "addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz";

#[test]
fn a_plutus_reference_script_reads_as_the_bytes_the_node_prints() {
    let entry = json!({
        "address": ADDRESS,
        "value": {"lovelace": 5},
        "referenceScript": {"script": {"type": "PlutusScriptV3", "cborHex": "4401010032"}},
    });
    let out = node::output(&entry);
    assert_eq!(
        out.script,
        Some(RefScript::Plutus(
            3,
            hex::decode("4401010032").expect("hex")
        ))
    );
}

#[test]
fn an_output_without_a_reference_script_reads_as_none() {
    let entry = json!({"address": ADDRESS, "value": {"lovelace": 5}});
    assert_eq!(node::output(&entry).script, None);
}
