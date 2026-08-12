use std::io::Write as _;

use serde::{Serialize, Serializer, ser::Error as _};

use crate::{
    mihomo::{
        BoundedVec, BuiltinMihomoError, MAX_MIHOMO_OUTPUT_BYTES,
        render_builtin_mihomo_v1_with_limit, serialize_bounded,
    },
    subscription_source::parse_subscription_sources,
};

const SOURCE: &[u8] = b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Boundary";

#[test]
fn rendering_accepts_its_exact_byte_length_and_rejects_one_less() {
    let parsed = parse_subscription_sources(&[SOURCE]).expect("valid subscription source");
    let exact = render_builtin_mihomo_v1_with_limit(parsed, usize::MAX)
        .expect("unbounded representative output");
    let exact_len = exact.config().len();

    let parsed = parse_subscription_sources(&[SOURCE]).expect("valid subscription source");
    let at_limit = render_builtin_mihomo_v1_with_limit(parsed, exact_len)
        .expect("the byte limit is inclusive");
    assert_eq!(at_limit.config(), exact.config());

    let parsed = parse_subscription_sources(&[SOURCE]).expect("valid subscription source");
    assert_eq!(
        render_builtin_mihomo_v1_with_limit(parsed, exact_len - 1),
        Err(BuiltinMihomoError::OutputTooLarge {
            limit_bytes: exact_len - 1,
        })
    );
}

#[test]
fn sixteen_mib_is_inclusive_and_a_crossing_chunk_is_never_partially_written() {
    let mut sink = BoundedVec::new(MAX_MIHOMO_OUTPUT_BYTES);
    let exact = vec![b'x'; MAX_MIHOMO_OUTPUT_BYTES];
    sink.write_all(&exact).expect("exactly 16 MiB is allowed");
    assert_eq!(sink.bytes.len(), MAX_MIHOMO_OUTPUT_BYTES);

    assert!(sink.write_all(b"!").is_err());
    assert_eq!(sink.bytes.len(), MAX_MIHOMO_OUTPUT_BYTES);
    assert!(sink.overflowed);
    assert!(sink.write(b"").is_err(), "overflow is sticky");
}

struct FailsToSerialize;

impl Serialize for FailsToSerialize {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Err(S::Error::custom("deliberate test failure"))
    }
}

#[test]
fn serializer_failures_are_not_misclassified_as_size_failures() {
    assert_eq!(
        serialize_bounded(&FailsToSerialize, 1_024),
        Err(BuiltinMihomoError::Serialization)
    );
}
