use crate::{Assessment, Criterion, Score, SovereigntyAssessable};

/// Lightning Network — Bitcoin's primary L2 payment network.
///
/// Lightning provides fast, cheap payments but introduces trade-offs
/// around sovereignty, particularly for mobile/LSP-dependent users.
pub struct Lightning;

impl SovereigntyAssessable for Lightning {
    fn protocol_name(&self) -> &str {
        "Lightning Network"
    }

    fn protocol_description(&self) -> &str {
        "Layer 2 payment channel network using HTLCs and penalty-based revocation. \
         Enables instant payments but requires channel management, liquidity, \
         and active monitoring. LSP-dependent users face sovereignty trade-offs."
    }

    fn assess_self_custody(&self) -> Assessment {
        Assessment {
            criterion: Criterion::SelfCustody,
            score: Score::Pass,
            rationale: "Users hold keys to their channel funds. Channel state is \
                        co-signed but keys remain under user control. Custodial \
                        Lightning wallets exist but are not inherent to the protocol."
                .into(),
        }
    }

    fn assess_unilateral_exit(&self) -> Assessment {
        Assessment {
            criterion: Criterion::UnilateralExit,
            score: Score::Pass,
            rationale: "Users can force-close channels unilaterally by broadcasting \
                        the latest commitment transaction. Funds return to the base \
                        layer after a timelock delay. No counterparty cooperation needed."
                .into(),
        }
    }

    fn assess_no_trusted_third_party(&self) -> Assessment {
        Assessment {
            criterion: Criterion::NoTrustedThirdParty,
            score: Score::Partial,
            rationale: "Running a full Lightning node requires no trust. However, \
                        most mobile users depend on Lightning Service Providers (LSPs) \
                        for channel management, liquidity, and routing. LSPs can \
                        refuse service, manipulate fees, or fail to relay payments."
                .into(),
        }
    }

    fn assess_censorship_resistance(&self) -> Assessment {
        Assessment {
            criterion: Criterion::CensorshipResistance,
            score: Score::Partial,
            rationale: "Routing nodes can refuse to forward payments. Well-connected \
                        nodes can observe and selectively block payment flows. While \
                        onion routing provides some privacy, LSP-dependent users can \
                        be censored at the LSP level."
                .into(),
        }
    }

    fn assess_on_chain_settlement(&self) -> Assessment {
        Assessment {
            criterion: Criterion::OnChainSettlement,
            score: Score::Pass,
            rationale: "All Lightning channel states are enforceable on-chain via \
                        commitment transactions and HTLC scripts. The penalty mechanism \
                        (or anchor outputs) ensures honest settlement."
                .into(),
        }
    }

    fn assess_liveness_independence(&self) -> Assessment {
        Assessment {
            criterion: Criterion::LivenessIndependence,
            score: Score::Partial,
            rationale: "Users must monitor the chain for revoked state broadcasts \
                        (or delegate to watchtowers). Extended offline periods risk \
                        counterparty cheating with old states. Channel timeouts can \
                        cause HTLC losses if users are not responsive."
                .into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SovereigntyAssessable;

    #[test]
    fn lightning_scores_correctly() {
        let report = Lightning.assess();
        // 3 Pass (1.0 each) + 3 Partial (0.5 each) = 4.5
        assert_eq!(report.total_score(), 4.5);
        assert_eq!(report.pass_count(), 3);
    }

    #[test]
    fn lightning_self_custody_passes() {
        let assessment = Lightning.assess_self_custody();
        assert_eq!(assessment.score, Score::Pass);
    }

    #[test]
    fn lightning_no_trusted_third_party_partial() {
        let assessment = Lightning.assess_no_trusted_third_party();
        assert_eq!(assessment.score, Score::Partial);
    }

    #[test]
    fn lightning_liveness_partial() {
        let assessment = Lightning.assess_liveness_independence();
        assert_eq!(assessment.score, Score::Partial);
    }
}
