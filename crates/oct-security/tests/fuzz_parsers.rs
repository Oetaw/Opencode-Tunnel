use oct_security::{ClientPrelude, HostPrelude, Invite};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_bytes_never_panic_in_security_parsers(bytes in prop::collection::vec(any::<u8>(), 0..=8192)) {
        let _ = ClientPrelude::decode(&bytes);
        let _ = HostPrelude::decode(&bytes);
    }

    #[test]
    fn arbitrary_invite_strings_never_panic(value in ".{0,9000}") {
        let _ = Invite::decode(&value);
    }
}
