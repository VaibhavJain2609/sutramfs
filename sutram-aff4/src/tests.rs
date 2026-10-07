//! Unit tests for the pure machinery: SHA-256 vectors, the Turtle
//! extractor, percent-decoding and subject→member matching.
//! Container-level tests live in `../tests/forensic.rs`.

use crate::manifest::{
    extract_manifest, pct_decode, subject_matches, HashAlgorithm,
};
use crate::sha256::{sha256_hex, sha256_reader_hex, Sha256};

// -- SHA-256 ---------------------------------------------------------------

#[test]
fn sha256_known_vectors() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    // >64 B forces the multi-block path.
    let long = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    assert_eq!(
        sha256_hex(long),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn sha256_streaming_matches_one_shot() {
    let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    let mut s = Sha256::new();
    for chunk in data.chunks(7) {
        s.update(chunk);
    }
    let mut one = Sha256::new();
    one.update(&data);
    assert_eq!(
        crate::sha256::to_hex(&s.finish()),
        crate::sha256::to_hex(&one.finish())
    );
    // Reader path agrees too.
    assert_eq!(
        sha256_reader_hex(data.as_slice()).unwrap(),
        sha256_hex(&data)
    );
}

// -- Turtle extractor --------------------------------------------------------

const SHA256_EMPTY: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[test]
fn manifest_canonical_statement() {
    let ttl = format!(
        r#"@prefix aff4: <http://aff4.org/Schema#> .
<aff4://1111/file.bin> a aff4:file_image ;
    aff4:hash <aff4:sha256={SHA256_EMPTY}> .
"#
    );
    let p = extract_manifest(&ttl);
    assert_eq!(p.statements, 2);
    let subj = p
        .subjects
        .iter()
        .find(|s| s.subject.contains("file.bin"))
        .expect("subject extracted");
    assert_eq!(subj.hashes.len(), 1);
    assert_eq!(subj.hashes[0].algorithm, HashAlgorithm::Sha256);
    assert_eq!(subj.hashes[0].value, SHA256_EMPTY);
    assert!(!subj.hashes[0].malformed);
}

#[test]
fn manifest_multiline_and_multi_hash() {
    // One statement spread over lines, two hash objects, a second subject.
    let ttl = format!(
        "<aff4://u/f1>\n  aff4:hash <aff4:sha256={0}> ,\n            <aff4:md5=d41d8cd98f00b204e9800998ecf8427e> .\n<aff4://u/f2> aff4:hash <aff4:SHA256={0}> .",
        SHA256_EMPTY
    );
    let p = extract_manifest(&ttl);
    let f1 = p.subjects.iter().find(|s| s.subject.ends_with("f1")).unwrap();
    assert_eq!(f1.hashes.len(), 2);
    assert_eq!(f1.hashes[1].algorithm, HashAlgorithm::Md5);
    // Algorithm name is matched case-insensitively.
    let f2 = p.subjects.iter().find(|s| s.subject.ends_with("f2")).unwrap();
    assert_eq!(f2.hashes[0].algorithm, HashAlgorithm::Sha256);
}

#[test]
fn manifest_literal_with_datatype() {
    let ttl = format!(
        "<aff4://u/f> aff4:hash \"{SHA256_EMPTY}\"^^aff4:sha256 ."
    );
    let p = extract_manifest(&ttl);
    let h = &p.subjects[0].hashes[0];
    assert_eq!(h.algorithm, HashAlgorithm::Sha256);
    assert_eq!(h.value, SHA256_EMPTY);
    assert!(!h.malformed);
}

#[test]
fn manifest_full_iri_predicate() {
    // Predicate written as a full IRI rather than the `aff4:` prefix.
    let ttl = format!(
        "<aff4://u/f> <http://aff4.org/Schema#hash> <aff4:sha256={SHA256_EMPTY}> ."
    );
    let p = extract_manifest(&ttl);
    assert_eq!(p.subjects[0].hashes[0].value, SHA256_EMPTY);
}

#[test]
fn manifest_malformed_is_lenient() {
    // Truncated mid-statement, an unterminated IRI, comment noise — never
    // a panic, partial results kept.
    let ttl = format!(
        "<aff4://u/f> aff4:hash <aff4:sha256={SHA256_EMPTY}> ; # trailing\n  aff4:size 12 .\n<aff4://u/g> aff4:hash <aff4:sha256=zzz"
    );
    let p = extract_manifest(&ttl);
    assert!(!p.notes.is_empty());
    assert!(p.subjects.iter().any(|s| s.subject.ends_with('f')
        && s.hashes.iter().any(|h| h.value == SHA256_EMPTY)));
}

#[test]
fn manifest_garbage_text_yields_nothing() {
    let p = extract_manifest("\x00\x01 not turtle at all !!! <<<>>>");
    // Whatever it scraped, it must not have fabricated a hash.
    assert!(p.subjects.iter().all(|s| s.hashes.is_empty()));
}

#[test]
fn manifest_wrong_length_hex_is_malformed_not_mismatch() {
    let ttl = "<aff4://u/f> aff4:hash <aff4:sha256=deadbeef> .";
    let p = extract_manifest(ttl);
    let h = &p.subjects[0].hashes[0];
    assert_eq!(h.algorithm, HashAlgorithm::Sha256);
    assert!(h.malformed);
}

#[test]
fn manifest_nonhex_object_is_malformed() {
    let ttl = "<aff4://u/f> aff4:hash <aff4:sha256=not-hex-at-all> .";
    let p = extract_manifest(ttl);
    let h = &p.subjects[0].hashes[0];
    assert!(h.malformed);
}

// -- Subject matching / percent decoding ------------------------------------

#[test]
fn pct_decode_basics() {
    assert_eq!(pct_decode("aff4://u/my%20file.txt"), "aff4://u/my file.txt");
    assert_eq!(pct_decode("plain"), "plain");
    assert_eq!(pct_decode("bad%zz"), "bad%zz"); // invalid escapes pass through
    assert_eq!(pct_decode("trailing%"), "trailing%");
}

#[test]
fn subject_matching() {
    assert!(subject_matches("aff4://uuid/evidence.bin", "evidence.bin"));
    assert!(subject_matches("aff4://uuid/dir/e.bin", "dir/e.bin"));
    assert!(subject_matches("evidence.bin", "evidence.bin"));
    assert!(subject_matches("aff4://u/my%20file.txt", "my file.txt"));
    assert!(!subject_matches("aff4://uuid/other.bin", "evidence.bin"));
    // Prefix-boundary check: `xevidence.bin` must NOT match.
    assert!(!subject_matches("aff4://uuid/xevidence.bin", "evidence.bin"));
}
