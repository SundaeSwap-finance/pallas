//! Native scripts in Dijkstra. These checks use slots, not Plutus time.
use pallas_crypto::hash::Hash;
use pallas_primitives::dijkstra::{NativeScript, StakeCredential};
use std::collections::{BTreeSet, HashSet};

/// The caller passes the guards of the level that needs the script and must verify
/// all vkey signatures against the original body before admission. Explicit frames
/// avoid recursion.
pub(crate) fn evaluate(
    script: &NativeScript,
    keys: &HashSet<Hash<28>>,
    lower: Option<u64>,
    upper: Option<u64>,
    guards: &BTreeSet<StakeCredential>,
) -> bool {
    enum Frame<'a> {
        Visit(&'a NativeScript),
        Combine(usize, usize),
    }
    let mut frames = vec![Frame::Visit(script)];
    let mut results = Vec::new();
    while let Some(frame) = frames.pop() {
        match frame {
            Frame::Combine(count, needed) => {
                let start = results.len() - count;
                let successes = results.drain(start..).filter(|x| *x).count();
                results.push(successes >= needed);
            }
            Frame::Visit(script) => {
                let (children, needed) = match script {
                    NativeScript::ScriptPubkey(key) => {
                        results.push(keys.contains(key));
                        continue;
                    }
                    NativeScript::InvalidBefore(slot) => {
                        results.push(lower.is_some_and(|x| *slot <= x));
                        continue;
                    }
                    NativeScript::InvalidHereafter(slot) => {
                        results.push(upper.is_some_and(|x| x <= *slot));
                        continue;
                    }
                    NativeScript::ScriptRequireGuard(credential) => {
                        results.push(guards.contains(credential));
                        continue;
                    }
                    NativeScript::ScriptAll(xs) => (xs, xs.len()),
                    NativeScript::ScriptAny(xs) => (xs, 1),
                    NativeScript::ScriptNOfK(n, xs) => {
                        (xs, usize::try_from((*n).max(0)).unwrap_or(usize::MAX))
                    }
                };
                frames.push(Frame::Combine(children.len(), needed));
                frames.extend(children.iter().map(Frame::Visit));
            }
        }
    }
    results.pop().unwrap_or(false)
}
