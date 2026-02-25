//! Sovereignty assessment framework for Bitcoin scaling protocols.
//!
//! Evaluates protocols against six sovereignty criteria to produce
//! comparable, shareable assessment reports.

pub mod protocols;

use serde::{Deserialize, Serialize};
use std::fmt;

/// The six sovereignty criteria for evaluating Bitcoin protocols.
///
/// Framework for assessing whether a Bitcoin scaling solution preserves
/// the sovereignty properties of base-layer Bitcoin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Criterion {
    /// Users hold their own private keys at all times.
    SelfCustody,
    /// Users can withdraw funds without cooperation from any other party.
    UnilateralExit,
    /// No trusted third party is required for protocol operation.
    NoTrustedThirdParty,
    /// Users' transactions cannot be selectively censored by protocol participants.
    CensorshipResistance,
    /// Claims are enforceable through on-chain settlement on the base layer.
    OnChainSettlement,
    /// Protocol does not fail or lose funds if counterparties go offline.
    LivenessIndependence,
}

impl Criterion {
    /// All six criteria in evaluation order.
    pub const ALL: [Criterion; 6] = [
        Criterion::SelfCustody,
        Criterion::UnilateralExit,
        Criterion::NoTrustedThirdParty,
        Criterion::CensorshipResistance,
        Criterion::OnChainSettlement,
        Criterion::LivenessIndependence,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            Criterion::SelfCustody => "Self-Custody",
            Criterion::UnilateralExit => "Unilateral Exit",
            Criterion::NoTrustedThirdParty => "No Trusted Third Party",
            Criterion::CensorshipResistance => "Censorship Resistance",
            Criterion::OnChainSettlement => "On-Chain Settlement",
            Criterion::LivenessIndependence => "Liveness Independence",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Criterion::SelfCustody => "Users hold their own private keys at all times",
            Criterion::UnilateralExit => {
                "Users can withdraw funds without cooperation from any other party"
            }
            Criterion::NoTrustedThirdParty => {
                "No trusted third party is required for protocol operation"
            }
            Criterion::CensorshipResistance => {
                "Transactions cannot be selectively censored by protocol participants"
            }
            Criterion::OnChainSettlement => {
                "Claims are enforceable through on-chain settlement on the base layer"
            }
            Criterion::LivenessIndependence => {
                "Protocol does not fail or lose funds if counterparties go offline"
            }
        }
    }
}

impl fmt::Display for Criterion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Assessment score for a single criterion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Score {
    /// Criterion is fully satisfied.
    Pass,
    /// Criterion is partially satisfied with caveats.
    Partial,
    /// Criterion is not satisfied.
    Fail,
}

impl Score {
    pub fn symbol(&self) -> &'static str {
        match self {
            Score::Pass => "PASS",
            Score::Partial => "PARTIAL",
            Score::Fail => "FAIL",
        }
    }

    pub fn emoji(&self) -> &'static str {
        match self {
            Score::Pass => "✅",
            Score::Partial => "⚠️",
            Score::Fail => "❌",
        }
    }

    pub fn numeric(&self) -> f64 {
        match self {
            Score::Pass => 1.0,
            Score::Partial => 0.5,
            Score::Fail => 0.0,
        }
    }
}

impl fmt::Display for Score {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.symbol())
    }
}

/// Assessment of a single criterion with rationale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assessment {
    pub criterion: Criterion,
    pub score: Score,
    pub rationale: String,
}

/// Full protocol assessment report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolReport {
    pub protocol_name: String,
    pub protocol_description: String,
    pub assessments: Vec<Assessment>,
}

impl ProtocolReport {
    /// Compute the total score (sum of numeric scores).
    pub fn total_score(&self) -> f64 {
        self.assessments.iter().map(|a| a.score.numeric()).sum()
    }

    /// Count of criteria that fully pass.
    pub fn pass_count(&self) -> usize {
        self.assessments
            .iter()
            .filter(|a| a.score == Score::Pass)
            .count()
    }

    /// Render the report as a markdown string.
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str(&format!("# {}\n\n", self.protocol_name));
        md.push_str(&format!("{}\n\n", self.protocol_description));
        md.push_str(&format!(
            "**Score: {:.1}/6** ({} pass, {} partial, {} fail)\n\n",
            self.total_score(),
            self.assessments
                .iter()
                .filter(|a| a.score == Score::Pass)
                .count(),
            self.assessments
                .iter()
                .filter(|a| a.score == Score::Partial)
                .count(),
            self.assessments
                .iter()
                .filter(|a| a.score == Score::Fail)
                .count(),
        ));

        md.push_str("| Criterion | Score | Rationale |\n");
        md.push_str("|-----------|-------|-----------|\n");
        for assessment in &self.assessments {
            md.push_str(&format!(
                "| {} | {} {} | {} |\n",
                assessment.criterion.name(),
                assessment.score.emoji(),
                assessment.score.symbol(),
                assessment.rationale,
            ));
        }
        md
    }

    /// Serialize the report to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Side-by-side comparison of multiple protocol assessments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonReport {
    pub reports: Vec<ProtocolReport>,
}

impl ComparisonReport {
    pub fn new(reports: Vec<ProtocolReport>) -> Self {
        Self { reports }
    }

    /// Render as a markdown comparison table.
    pub fn to_markdown(&self) -> String {
        if self.reports.is_empty() {
            return String::from("No protocols to compare.\n");
        }

        let mut md = String::new();
        md.push_str("# Sovereignty Protocol Comparison\n\n");

        // Header row
        md.push_str("| Criterion |");
        for report in &self.reports {
            md.push_str(&format!(" {} |", report.protocol_name));
        }
        md.push('\n');

        // Separator
        md.push_str("|-----------|");
        for _ in &self.reports {
            md.push_str("--------|");
        }
        md.push('\n');

        // One row per criterion
        for criterion in &Criterion::ALL {
            md.push_str(&format!("| {} |", criterion.name()));
            for report in &self.reports {
                let assessment = report
                    .assessments
                    .iter()
                    .find(|a| a.criterion == *criterion);
                match assessment {
                    Some(a) => md.push_str(&format!(" {} {} |", a.score.emoji(), a.score.symbol())),
                    None => md.push_str(" N/A |"),
                }
            }
            md.push('\n');
        }

        // Total row
        md.push_str("| **Total** |");
        for report in &self.reports {
            md.push_str(&format!(" **{:.1}/6** |", report.total_score()));
        }
        md.push('\n');

        md
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Trait for protocols that can be assessed against the sovereignty criteria.
pub trait SovereigntyAssessable {
    /// Protocol name for display.
    fn protocol_name(&self) -> &str;

    /// Brief protocol description.
    fn protocol_description(&self) -> &str;

    /// Assess self-custody: users hold their own private keys.
    fn assess_self_custody(&self) -> Assessment;

    /// Assess unilateral exit: users can withdraw without cooperation.
    fn assess_unilateral_exit(&self) -> Assessment;

    /// Assess no trusted third party requirement.
    fn assess_no_trusted_third_party(&self) -> Assessment;

    /// Assess censorship resistance within the protocol.
    fn assess_censorship_resistance(&self) -> Assessment;

    /// Assess on-chain settlement enforceability.
    fn assess_on_chain_settlement(&self) -> Assessment;

    /// Assess liveness independence from counterparties.
    fn assess_liveness_independence(&self) -> Assessment;

    /// Generate the full assessment report.
    fn assess(&self) -> ProtocolReport {
        ProtocolReport {
            protocol_name: self.protocol_name().to_string(),
            protocol_description: self.protocol_description().to_string(),
            assessments: vec![
                self.assess_self_custody(),
                self.assess_unilateral_exit(),
                self.assess_no_trusted_third_party(),
                self.assess_censorship_resistance(),
                self.assess_on_chain_settlement(),
                self.assess_liveness_independence(),
            ],
        }
    }
}
