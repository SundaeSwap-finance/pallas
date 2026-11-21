//! Decoding of structs written as a map from integer keys to fields.

/// Implements `Decode` for a struct from a table of each field's key, refusing a key the table lacks.
macro_rules! decode_map_record {
    (@field $d:ident, $ctx:ident) => {
        $d.decode_with($ctx)?
    };
    (@field $d:ident, $ctx:ident, $by:path) => {
        $by($d, $ctx)?
    };
    (
        $name:ident $(<$lt:lifetime>)? $(, tag $tag:literal)?,
        $( $key:literal => $field:ident $(: $by:path)? ),+ $(,)?
    ) => {
        impl<'bytes $(: $lt, $lt)?, Ctx> pallas_codec::minicbor::Decode<'bytes, Ctx>
            for $name $(<$lt>)?
        {
            #[deny(unreachable_patterns)]
            fn decode(
                d: &mut pallas_codec::minicbor::Decoder<'bytes>,
                ctx: &mut Ctx,
            ) -> Result<$name $(<$lt>)?, pallas_codec::minicbor::decode::Error> {
                use pallas_codec::minicbor::{data::Type, decode::Error, Decode};

                $(
                    let tag_at = d.position();
                    let tag = d.tag()?;
                    if tag.as_u64() != $tag {
                        return Err(Error::tag_mismatch(tag)
                            .with_message(format!("expected tag {}", $tag))
                            .at(tag_at));
                    }
                )?

                let start = d.position();
                let len = d.map()?;
                let mut read = 0;
                $( let mut $field = None; )+

                loop {
                    match len {
                        Some(len) if read == len => break,
                        None if d.datatype()? == Type::Break => {
                            d.skip()?;
                            break;
                        }
                        _ => {}
                    }
                    let key_at = d.position();
                    match d.i64()? {
                        $( $key => $field = Some($crate::map_record::decode_map_record!(@field d, ctx $(, $by)?)), )+
                        key => {
                            return Err(Error::message(format!(
                                "unknown key {key} in {}",
                                stringify!($name)
                            ))
                            .at(key_at))
                        }
                    }
                    read += 1;
                }

                Ok($name {
                    $(
                        $field: match $field {
                            Some(value) => value,
                            None => <_ as Decode<'bytes, Ctx>>::nil().ok_or_else(|| {
                                Error::missing_value($key)
                                    .with_message(concat!(stringify!($name), "::", stringify!($field)))
                                    .at(start)
                            })?,
                        },
                    )+
                })
            }
        }
    };
}

pub(crate) use decode_map_record;
