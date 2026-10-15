//! UTxO lookup dependencies, distinct from the inputs consumed on ledger.
use pallas_traverse::{Era, MultiEraTx};

fn required(tx: &MultiEraTx<'_>) -> Vec<String> {
    tx.requires()
        .iter()
        .map(|input| input.output_ref().to_string())
        .collect()
}

#[test]
fn requires_preserves_earlier_era_duplicates() {
    let bytes = hex::decode(include_str!("../../test_data/duplicateinput.tx").trim()).unwrap();
    let tx = MultiEraTx::decode_for_era(Era::Alonzo, &bytes).unwrap();
    let input = "4d9cb6bf1c2e349f1bcd454a632d2b721d5badcf687220430c316588f39506ab#1";
    assert_eq!(required(&tx), [input, input]);
    assert_eq!(tx.consumes().len(), 1);
}

#[cfg(feature = "unstable")]
mod dijkstra {
    use super::*;
    use pallas_codec::minicbor;
    use pallas_primitives::dijkstra as n;

    fn input(index: u64) -> n::TransactionInput {
        n::TransactionInput {
            transaction_id: [42; 32].into(),
            index,
        }
    }

    fn indices(tx: &MultiEraTx<'_>) -> Vec<u64> {
        tx.requires().iter().map(|input| input.index()).collect()
    }

    fn batch() -> n::BlockTransaction<'static> {
        // Synthetic bodies only: no claim of signatures or ledger validity.
        let mut parent: n::BlockTransaction =
            minicbor::decode(&[0x84, 0xa3, 0, 0x80, 1, 0x80, 2, 0, 0xa0, 0xf6, 0xf5]).unwrap();
        parent.transaction_body.inputs = vec![input(1)].into();
        parent.transaction_body.reference_inputs = Some(vec![input(2)].try_into().unwrap());
        parent.transaction_body.collateral = Some(vec![input(3)].try_into().unwrap());
        let mut first: n::SubTransaction =
            minicbor::decode(&[0x83, 0xa2, 0, 0x80, 1, 0x80, 0xa0, 0xf6]).unwrap();
        first.sub_transaction_body.inputs = vec![input(4)].into();
        first.sub_transaction_body.reference_inputs =
            Some(vec![input(5), input(2), input(5)].try_into().unwrap());
        let mut second = first.clone();
        second.sub_transaction_body.inputs = vec![input(6)].into();
        second.sub_transaction_body.reference_inputs = Some(vec![input(5)].try_into().unwrap());
        parent.transaction_body.sub_transactions = Some(vec![first, second].try_into().unwrap());
        parent
    }

    #[test]
    fn requires_captured_parent_and_child_dependencies() {
        let bytes = hex::decode(include_str!("../../test_data/dijkstra-subtx.tx").trim()).unwrap();
        let tx = MultiEraTx::decode_for_era(Era::Dijkstra, &bytes).unwrap();
        assert_eq!(
            tx.hash().to_string(),
            "74e2116ca6e0c809f156aa062a9d4ee8b156322618846f1bdea5d9ad7a206a12"
        );
        // The capture repeats both child dependencies in the parent's references.
        // Keep those original bytes and duplicate occurrences intact.
        assert_eq!(
            required(&tx),
            [
                "737549420add1f19d144809aa02e2ae68a89b1761368e3294fbb30ee1467e3e4#12",
                "2ed1285cced47acb5f08502843d980d7231665af9d90ef33fe6751e0f9e0b171#0",
                "c095234678d98a74cd1488bda1971fbd2e9c828acf57f7673c679ec601abf7a6#0",
                "7727ec1dfb0f84f2ffeb51935f35850cf84cfabfca1957e8c74cf8fde871dd34#12",
                "2ed1285cced47acb5f08502843d980d7231665af9d90ef33fe6751e0f9e0b171#0",
                "c095234678d98a74cd1488bda1971fbd2e9c828acf57f7673c679ec601abf7a6#0",
            ]
        );
        assert_eq!(tx.encode(), bytes);
    }

    #[test]
    fn requires_all_children_and_preserves_duplicate_references() {
        for success in [true, false] {
            let mut parent = batch();
            parent.success = success;
            let tx = MultiEraTx::from_dijkstra(&parent);
            assert_eq!(indices(&tx), [1, 2, 3, 4, 5, 2, 5, 6, 5]);
            assert_eq!(tx.inputs().len(), 1, "body accessors stay local");
            assert_eq!(tx.reference_inputs().len(), 1);
            assert_eq!(tx.consumes()[0].index(), if success { 1 } else { 3 });
        }
    }

    #[test]
    fn requires_on_a_child_reads_only_its_own_body() {
        for success in [true, false] {
            let mut parent = batch();
            parent.success = success;
            let tx = MultiEraTx::from_dijkstra(&parent);
            let children = tx.sub_transactions();
            assert_eq!(indices(&children[0]), [4, 5, 2, 5]);
            assert_eq!(indices(&children[1]), [6, 5]);
            assert!(children[0].collateral().is_empty());
        }
    }

    #[test]
    fn requires_without_children_keeps_parent_dependencies() {
        let mut parent = batch();
        parent.transaction_body.sub_transactions = None;
        assert_eq!(indices(&MultiEraTx::from_dijkstra(&parent)), [1, 2, 3]);
        parent.transaction_body.reference_inputs = None;
        parent.transaction_body.collateral = None;
        assert_eq!(indices(&MultiEraTx::from_dijkstra(&parent)), [1]);
    }
}
