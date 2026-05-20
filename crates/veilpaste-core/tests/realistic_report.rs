use std::fs;
use std::path::Path;
use veilpaste_core::{scrub, ScrubOptions};

#[derive(Debug, serde::Deserialize)]
struct Manifest {
    cases: Vec<Case>,
}

#[derive(Debug, serde::Deserialize)]
struct Case {
    file: String,
    should_redact: Vec<ExpectedRedaction>,
    should_not_redact: Vec<ProtectedSpan>,
    known_misses: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ExpectedRedaction {
    kind: String,
    contains: String,
    placeholder_prefix: String,
}

#[derive(Debug, serde::Deserialize)]
struct ProtectedSpan {
    contains: String,
    reason: String,
}

#[derive(Debug, serde::Deserialize)]
struct Contract {
    rules: Vec<ContractRule>,
}

#[derive(Debug, serde::Deserialize)]
struct ContractRule {
    rust_kind: String,
    placeholder_prefix: String,
}

fn shared_contract() -> Contract {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/shared-contract/rules.json");
    serde_json::from_str(&fs::read_to_string(path).expect("shared contract should exist"))
        .expect("shared contract should parse")
}

#[test]
fn realistic_coverage_report() {
    let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/realistic");
    let manifest_path = fixture_root.join("manifest.json");
    let manifest: Manifest = serde_json::from_str(
        &fs::read_to_string(&manifest_path).expect("manifest should be readable"),
    )
    .expect("manifest should parse");
    let contract = shared_contract();

    let mut caught = 0;
    let mut missed = Vec::new();
    let mut false_positives = Vec::new();
    let mut protected_total = 0;
    let mut known_miss_total = 0;

    for case in manifest.cases {
        let input = fs::read_to_string(fixture_root.join(&case.file))
            .unwrap_or_else(|_| panic!("{} should be readable", case.file));
        let result = scrub(&input, ScrubOptions::default())
            .unwrap_or_else(|_| panic!("{} should scrub", case.file));

        for expected in case.should_redact {
            let contract_rule = contract
                .rules
                .iter()
                .find(|rule| rule.rust_kind == expected.kind)
                .unwrap_or_else(|| {
                    panic!(
                        "{}: missing shared contract for {}",
                        case.file, expected.kind
                    )
                });
            assert_eq!(
                contract_rule.placeholder_prefix, expected.placeholder_prefix,
                "{}: contract placeholder prefix mismatch for {}",
                case.file, expected.kind
            );

            if result.output.contains(&expected.contains) {
                missed.push(format!(
                    "{}: {} still contains {:?}",
                    case.file, expected.kind, expected.contains
                ));
            } else {
                caught += 1;
            }

            if !result.findings.iter().any(|finding| {
                format!("{:?}", finding.kind) == expected.kind
                    && finding.original.contains(&expected.contains)
            }) {
                missed.push(format!(
                    "{}: missing finding kind {} for {:?}",
                    case.file, expected.kind, expected.contains
                ));
            }

            if !result.mappings.iter().any(|entry| {
                format!("{:?}", entry.kind) == expected.kind
                    && entry.original.contains(&expected.contains)
                    && entry
                        .placeholder
                        .starts_with(&format!("[{}_", expected.placeholder_prefix))
            }) {
                missed.push(format!(
                    "{}: missing {} placeholder for {:?}",
                    case.file, expected.placeholder_prefix, expected.contains
                ));
            }
        }

        for protected in case.should_not_redact {
            protected_total += 1;
            if !result.output.contains(&protected.contains) {
                false_positives.push(format!(
                    "{}: protected span changed {:?} ({})",
                    case.file, protected.contains, protected.reason
                ));
            }
        }

        for known_miss in case.known_misses {
            known_miss_total += 1;
            println!("Known miss: {}: {}", case.file, known_miss);
        }
    }

    println!(
        "Realistic coverage: {} caught, {} missed, {} false positives / {} protected spans, {} known misses",
        caught,
        missed.len(),
        false_positives.len(),
        protected_total,
        known_miss_total
    );

    assert!(
        missed.is_empty(),
        "missed redactions:\n{}",
        missed.join("\n")
    );
    assert!(
        false_positives.is_empty(),
        "false positives:\n{}",
        false_positives.join("\n")
    );
}
