use super::*;

#[test]
fn non_ascii_issuer_keys_are_rejected_without_slicing_panic() {
    assert!(decode_key(&format!("€{}", "0".repeat(61))).is_err());
}
