//! The labels that name the rule a Dijkstra refusal breaks.

/// Declares a label enum whose variants print as their texts, and refuses to
/// compile when two of its texts are equal.
macro_rules! labels {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($variant:ident => $text:literal,)*
            $(@nested $nested:ident($inner:ty),)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        $vis enum $name {
            $($variant,)*
            $($nested($inner),)?
        }

        impl $name {
            /// Every label this type declares, in declaration order.
            pub const ALL: &'static [$name] = &[$($name::$variant),*];

            /// The text of the label.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $text,)*
                    $($name::$nested(inner) => inner.as_str(),)?
                }
            }
        }

        const _: () = assert!(
            $crate::labels::distinct(&[$($text),*]),
            concat!("two labels of ", stringify!($name), " share a text")
        );

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Debug::fmt(self.as_str(), f)
            }
        }
    };
}

/// Whether no two of the texts are equal.
pub(crate) const fn distinct(texts: &[&str]) -> bool {
    let mut i = 0;
    while i < texts.len() {
        let mut j = i + 1;
        while j < texts.len() {
            if equal(texts[i].as_bytes(), texts[j].as_bytes()) {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

/// Whether two byte strings are equal.
const fn equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::distinct;

    #[test]
    fn labels_that_differ_are_distinct() {
        assert!(distinct(&["duplicate input", "duplicate inputs", "refund"]));
        assert!(distinct(&[]));
    }

    #[test]
    fn a_text_given_twice_is_not_distinct() {
        assert!(!distinct(&["refund", "registration deposit", "refund"]));
    }
}
