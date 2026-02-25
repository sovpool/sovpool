use sovpool_assess::protocols::*;
use sovpool_assess::{ComparisonReport, Criterion, Score, SovereigntyAssessable};

#[test]
fn comparison_report_all_five_protocols() {
    let reports = vec![
        BitcoinL1.assess(),
        Lightning.assess(),
        Ark.assess(),
        Cashu.assess(),
        CtvPool.assess(),
    ];

    let comparison = ComparisonReport::new(reports);
    assert_eq!(comparison.reports.len(), 5);

    // Verify ordering of scores: L1 = CTV > Lightning > ARK > Cashu
    let scores: Vec<f64> = comparison.reports.iter().map(|r| r.total_score()).collect();
    assert_eq!(scores[0], 6.0); // Bitcoin L1
    assert_eq!(scores[4], 6.0); // CTV Pool
    assert!(scores[1] > scores[2]); // Lightning > ARK
    assert!(scores[2] > scores[3]); // ARK > Cashu
}

#[test]
fn comparison_report_to_markdown() {
    let reports = vec![BitcoinL1.assess(), Lightning.assess(), CtvPool.assess()];

    let comparison = ComparisonReport::new(reports);
    let md = comparison.to_markdown();

    assert!(md.contains("Sovereignty Protocol Comparison"));
    assert!(md.contains("Bitcoin L1"));
    assert!(md.contains("Lightning Network"));
    assert!(md.contains("CTV Payment Pool"));
    assert!(md.contains("Self-Custody"));
    assert!(md.contains("Unilateral Exit"));
    assert!(md.contains("**6.0/6**"));
    assert!(md.contains("**4.5/6**"));
}

#[test]
fn comparison_report_to_json() {
    let reports = vec![BitcoinL1.assess(), CtvPool.assess()];

    let comparison = ComparisonReport::new(reports);
    let json = comparison.to_json().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert!(parsed["reports"].is_array());
    assert_eq!(parsed["reports"].as_array().unwrap().len(), 2);
}

#[test]
fn protocol_report_to_json_roundtrip() {
    let report = BitcoinL1.assess();
    let json = report.to_json().unwrap();
    let deserialized: sovpool_assess::ProtocolReport = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.protocol_name, "Bitcoin L1");
    assert_eq!(deserialized.assessments.len(), 6);
    assert_eq!(deserialized.total_score(), 6.0);
}

#[test]
fn protocol_report_markdown_contains_all_criteria() {
    let report = Ark.assess();
    let md = report.to_markdown();

    for criterion in &Criterion::ALL {
        assert!(
            md.contains(criterion.name()),
            "Markdown should contain criterion: {}",
            criterion.name()
        );
    }
}

#[test]
fn every_protocol_has_six_assessments() {
    let protocols: Vec<Box<dyn SovereigntyAssessable>> = vec![
        Box::new(BitcoinL1),
        Box::new(Lightning),
        Box::new(Ark),
        Box::new(Cashu),
        Box::new(CtvPool),
    ];

    for protocol in &protocols {
        let report = protocol.assess();
        assert_eq!(
            report.assessments.len(),
            6,
            "{} should have exactly 6 assessments",
            report.protocol_name
        );

        // Verify all 6 criteria are represented
        for criterion in &Criterion::ALL {
            assert!(
                report.assessments.iter().any(|a| a.criterion == *criterion),
                "{} missing criterion: {}",
                report.protocol_name,
                criterion
            );
        }
    }
}

#[test]
fn every_assessment_has_nonempty_rationale() {
    let protocols: Vec<Box<dyn SovereigntyAssessable>> = vec![
        Box::new(BitcoinL1),
        Box::new(Lightning),
        Box::new(Ark),
        Box::new(Cashu),
        Box::new(CtvPool),
    ];

    for protocol in &protocols {
        let report = protocol.assess();
        for assessment in &report.assessments {
            assert!(
                !assessment.rationale.is_empty(),
                "{} has empty rationale for {}",
                report.protocol_name,
                assessment.criterion
            );
        }
    }
}

#[test]
fn score_numeric_values() {
    assert_eq!(Score::Pass.numeric(), 1.0);
    assert_eq!(Score::Partial.numeric(), 0.5);
    assert_eq!(Score::Fail.numeric(), 0.0);
}

#[test]
fn empty_comparison_report() {
    let comparison = ComparisonReport::new(vec![]);
    let md = comparison.to_markdown();
    assert!(md.contains("No protocols to compare"));
}
