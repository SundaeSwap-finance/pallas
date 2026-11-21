//! Stack-safe script trees used in node-to-client query results and errors.
use super::primitives::NativeScript as Script;
use pallas_codec::{
    minicbor::{self, Decoder, Encoder},
    tree::{
        Arity, MAX_DECODE_DEPTH, TreeDecode, TreeNode, Visit, decode_tree_with_max_depth, eq_tree,
        fold_tree, walk_tree,
    },
};

/// What the tree drivers need from an era's native script enum.
pub(crate) trait NativeScript: TreeNode + Sized {
    /// The node with its fields read and an empty child list, or `None` for a variant the era does not define.
    fn begin<'b, C>(
        variant: u32,
        d: &mut Decoder<'b>,
        ctx: &mut C,
    ) -> Result<Option<Self>, minicbor::decode::Error>;

    /// Writes the array header, the variant index and the fields, with a container's child list header last.
    fn write_header<C, W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>>;

    /// The node rebuilt over `children`.
    fn rebuild(&self, children: Vec<Self>) -> Self;

    /// Whether two nodes hold the same data, children aside.
    fn same_node(&self, other: &Self) -> bool;
}

struct Node<S>(S);

impl<'b, C, S: NativeScript> TreeDecode<'b, C> for Node<S> {
    type Builder = S;
    fn begin(d: &mut Decoder<'b>, ctx: &mut C) -> Result<(S, Arity), minicbor::decode::Error> {
        // Preserve this codec's existing outer-array handling. Child arrays
        // may be definite or indefinite, just as with Vec::decode.
        d.array()?;
        let variant = d.u32()?;
        let mut script = S::begin(variant, d, ctx)?.ok_or_else(|| {
            minicbor::decode::Error::message("unknown variant id for native script")
        })?;
        let arity = if script.children_mut().is_some() {
            d.array()?.into()
        } else {
            Arity::Leaf
        };
        Ok((script, arity))
    }
    fn child(node: &mut S, child: Node<S>) -> Result<(), minicbor::decode::Error> {
        node.children_mut().expect("container").push(child.0);
        Ok(())
    }
    fn end(node: S, _: &mut Decoder<'b>, _: &mut C) -> Result<Node<S>, minicbor::decode::Error> {
        Ok(Node(node))
    }
}

pub(crate) fn decode<'b, C, S: NativeScript>(
    d: &mut Decoder<'b>,
    ctx: &mut C,
) -> Result<S, minicbor::decode::Error> {
    decode_tree_with_max_depth::<C, Node<S>>(d, ctx, MAX_DECODE_DEPTH).map(|node| node.0)
}

pub(crate) fn encode<C, W: minicbor::encode::Write, S: NativeScript>(
    script: &S,
    e: &mut Encoder<W>,
    ctx: &mut C,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    walk_tree(script, |visit| {
        if let Visit::Enter(node) = visit {
            node.write_header(e, ctx)?;
        }
        Ok(())
    })
}

pub(crate) fn clone<S: NativeScript>(script: &S) -> S {
    fold_tree(script, S::rebuild)
}

pub(crate) fn eq<S: NativeScript>(left: &S, right: &S) -> bool {
    eq_tree(left, right, S::same_node)
}

/// Implements an era's native script enum, the six Shelley variants and any era leaves listed with their variant index.
macro_rules! impl_native_script {
    ($script:ident $({ $( $index:literal => $leaf:ident($leaf_ty:ty) ),* $(,)? })?) => {
        impl pallas_codec::tree::TreeNode for $script {
            fn children(&self) -> &[Self] {
                match self {
                    Self::ScriptAll(x) | Self::ScriptAny(x) | Self::ScriptNOfK(_, x) => x,
                    _ => &[],
                }
            }
            fn children_mut(&mut self) -> Option<&mut Vec<Self>> {
                match self {
                    Self::ScriptAll(x) | Self::ScriptAny(x) | Self::ScriptNOfK(_, x) => Some(x),
                    _ => None,
                }
            }
        }

        impl $crate::miniprotocols::localtxsubmission::native_script::NativeScript for $script {
            fn begin<'b, C>(
                variant: u32,
                d: &mut pallas_codec::minicbor::Decoder<'b>,
                ctx: &mut C,
            ) -> Result<Option<Self>, pallas_codec::minicbor::decode::Error> {
                Ok(Some(match variant {
                    0 => Self::ScriptPubkey(d.decode_with(ctx)?),
                    1 => Self::ScriptAll(Vec::new()),
                    2 => Self::ScriptAny(Vec::new()),
                    3 => Self::ScriptNOfK(d.decode_with(ctx)?, Vec::new()),
                    4 => Self::InvalidBefore(d.decode_with(ctx)?),
                    5 => Self::InvalidHereafter(d.decode_with(ctx)?),
                    $($( $index => Self::$leaf(d.decode_with::<C, $leaf_ty>(ctx)?), )*)?
                    _ => return Ok(None),
                }))
            }

            fn write_header<C, W: pallas_codec::minicbor::encode::Write>(
                &self,
                e: &mut pallas_codec::minicbor::Encoder<W>,
                ctx: &mut C,
            ) -> Result<(), pallas_codec::minicbor::encode::Error<W::Error>> {
                match self {
                    Self::ScriptPubkey(x) => {
                        e.array(2)?.u32(0)?.encode_with(x, ctx)?;
                    }
                    Self::ScriptAll(xs) => {
                        e.array(2)?.u32(1)?.array(xs.len() as u64)?;
                    }
                    Self::ScriptAny(xs) => {
                        e.array(2)?.u32(2)?.array(xs.len() as u64)?;
                    }
                    Self::ScriptNOfK(n, xs) => {
                        e.array(3)?
                            .u32(3)?
                            .encode_with(n, ctx)?
                            .array(xs.len() as u64)?;
                    }
                    Self::InvalidBefore(x) => {
                        e.array(2)?.u32(4)?.encode_with(x, ctx)?;
                    }
                    Self::InvalidHereafter(x) => {
                        e.array(2)?.u32(5)?.encode_with(x, ctx)?;
                    }
                    $($( Self::$leaf(x) => {
                        e.array(2)?.u32($index)?.encode_with(x, ctx)?;
                    } )*)?
                }
                Ok(())
            }

            fn rebuild(&self, children: Vec<Self>) -> Self {
                match self {
                    Self::ScriptPubkey(x) => Self::ScriptPubkey(*x),
                    Self::ScriptAll(_) => Self::ScriptAll(children),
                    Self::ScriptAny(_) => Self::ScriptAny(children),
                    Self::ScriptNOfK(n, _) => Self::ScriptNOfK(*n, children),
                    Self::InvalidBefore(x) => Self::InvalidBefore(*x),
                    Self::InvalidHereafter(x) => Self::InvalidHereafter(*x),
                    $($( Self::$leaf(x) => Self::$leaf(x.clone()), )*)?
                }
            }

            fn same_node(&self, other: &Self) -> bool {
                match (self, other) {
                    (Self::ScriptPubkey(a), Self::ScriptPubkey(b)) => a == b,
                    (Self::ScriptAll(_), Self::ScriptAll(_))
                    | (Self::ScriptAny(_), Self::ScriptAny(_)) => true,
                    (Self::ScriptNOfK(a, _), Self::ScriptNOfK(b, _)) => a == b,
                    (Self::InvalidBefore(a), Self::InvalidBefore(b))
                    | (Self::InvalidHereafter(a), Self::InvalidHereafter(b)) => a == b,
                    $($( (Self::$leaf(a), Self::$leaf(b)) => a == b, )*)?
                    _ => false,
                }
            }
        }

        impl $script {
            /// Extracts an all-of child list without cloning, or returns other variants unchanged.
            pub fn into_all(mut self) -> Result<Vec<Self>, Self> {
                match &mut self {
                    Self::ScriptAll(xs) => Ok(std::mem::take(xs)),
                    _ => Err(self),
                }
            }
            /// Extracts an any-of child list without cloning, or returns other variants unchanged.
            pub fn into_any(mut self) -> Result<Vec<Self>, Self> {
                match &mut self {
                    Self::ScriptAny(xs) => Ok(std::mem::take(xs)),
                    _ => Err(self),
                }
            }
            /// Extracts a threshold and its children without cloning, or returns other variants unchanged.
            pub fn into_n_of_k(mut self) -> Result<(i64, Vec<Self>), Self> {
                match &mut self {
                    Self::ScriptNOfK(n, xs) => Ok((*n, std::mem::take(xs))),
                    _ => Err(self),
                }
            }
        }

        impl<'b, C> pallas_codec::minicbor::Decode<'b, C> for $script {
            fn decode(
                d: &mut pallas_codec::minicbor::Decoder<'b>,
                ctx: &mut C,
            ) -> Result<Self, pallas_codec::minicbor::decode::Error> {
                $crate::miniprotocols::localtxsubmission::native_script::decode(d, ctx)
            }
        }

        impl<C> pallas_codec::minicbor::Encode<C> for $script {
            fn encode<W: pallas_codec::minicbor::encode::Write>(
                &self,
                e: &mut pallas_codec::minicbor::Encoder<W>,
                ctx: &mut C,
            ) -> Result<(), pallas_codec::minicbor::encode::Error<W::Error>> {
                $crate::miniprotocols::localtxsubmission::native_script::encode(self, e, ctx)
            }
        }

        impl Clone for $script {
            fn clone(&self) -> Self {
                $crate::miniprotocols::localtxsubmission::native_script::clone(self)
            }
        }

        impl PartialEq for $script {
            fn eq(&self, other: &Self) -> bool {
                $crate::miniprotocols::localtxsubmission::native_script::eq(self, other)
            }
        }

        impl Eq for $script {}
    };
}

impl_native_script!(Script);
