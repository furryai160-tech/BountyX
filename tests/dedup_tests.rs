use bountyscope::validation::Deduplicator;

#[test]
fn test_finding_fingerprint_consistency() {
    let fp1 = Deduplicator::compute_finding_fingerprint(
        "target_corp",
        "api.target.com",
        "cve-2023-1234",
        Some("status_code"),
        "https://api.target.com/v1/auth",
    );

    let fp2 = Deduplicator::compute_finding_fingerprint(
        "target_corp",
        "api.target.com",
        "cve-2023-1234",
        Some("status_code"),
        "https://api.target.com/v1/auth",
    );

    let fp3 = Deduplicator::compute_finding_fingerprint(
        "target_corp",
        "api.target.com",
        "cve-2024-9999",
        Some("status_code"),
        "https://api.target.com/v1/auth",
    );

    // Identical findings must have identical fingerprints
    assert_eq!(fp1, fp2);
    // Different findings must produce different fingerprints
    assert_ne!(fp1, fp3);
}

#[test]
fn test_string_deduplication() {
    let items = vec![
        "sub1.example.com".to_string(),
        "sub2.example.com".to_string(),
        "sub1.example.com".to_string(),
        "sub3.example.com".to_string(),
        "".to_string(),
    ];

    let deduped = Deduplicator::deduplicate_strings(&items);
    assert_eq!(deduped.len(), 3);
    assert_eq!(deduped, vec!["sub1.example.com", "sub2.example.com", "sub3.example.com"]);
}

#[test]
fn test_url_normalization_for_dedup() {
    let u1 = Deduplicator::normalize_url_for_dedup("https://Example.com:443/api/");
    let u2 = Deduplicator::normalize_url_for_dedup("https://example.com/api");
    assert_eq!(u1, u2);
}
