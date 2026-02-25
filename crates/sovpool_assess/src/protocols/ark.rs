use crate::{Assessment, Criterion, Score, SovereigntyAssessable};

/// ARK (Arkade) — off-chain UTXO protocol using an ASP coordinator.
///
/// ARK enables off-chain payments through virtual UTXOs (vTXOs) managed
/// by an Ark Service Provider (ASP). The ASP trust model introduces
/// significant sovereignty trade-offs compared to base-layer Bitcoin.
pub struct Ark;

impl SovereigntyAssessable for Ark {
    fn protocol_name(&self) -> &str {
        "ARK"
    }

    fn protocol_description(&self) -> &str {
        "Off-chain UTXO transfer protocol using virtual UTXOs (vTXOs) and \
         an Ark Service Provider (ASP) coordinator. Enables instant payments \
         without channel management but introduces ASP trust dependency. \
         On-chain redemption requires ASP cooperation or timeout expiry."
    }

    fn assess_self_custody(&self) -> Assessment {
        Assessment {
            criterion: Criterion::SelfCustody,
            score: Score::Pass,
            rationale: "Users hold keys to their vTXOs. The ASP co-signs \
                        transactions but cannot unilaterally spend user funds. \
                        Keys remain under user control at all times."
                .into(),
        }
    }

    fn assess_unilateral_exit(&self) -> Assessment {
        Assessment {
            criterion: Criterion::UnilateralExit,
            score: Score::Partial,
            rationale: "Users can redeem vTXOs on-chain, but the process requires \
                        waiting for a timeout period (typically 4 weeks). During this \
                        window, the ASP's liquidity is locked. If many users exit \
                        simultaneously, on-chain fees may be prohibitive."
                .into(),
        }
    }

    fn assess_no_trusted_third_party(&self) -> Assessment {
        Assessment {
            criterion: Criterion::NoTrustedThirdParty,
            score: Score::Fail,
            rationale: "The ASP is a required coordinator for all off-chain transfers. \
                        The ASP facilitates rounds, provides liquidity, and co-signs \
                        vTXO transfers. If the ASP disappears, users must wait for \
                        timeout to reclaim funds on-chain. The ASP has full visibility \
                        into transaction flows."
                .into(),
        }
    }

    fn assess_censorship_resistance(&self) -> Assessment {
        Assessment {
            criterion: Criterion::CensorshipResistance,
            score: Score::Partial,
            rationale: "The ASP can refuse to include specific users in rounds, \
                        effectively censoring their off-chain payments. Users can \
                        fall back to on-chain redemption but at significant time \
                        and fee cost. Multiple ASPs could mitigate this but the \
                        ecosystem is not there yet."
                .into(),
        }
    }

    fn assess_on_chain_settlement(&self) -> Assessment {
        Assessment {
            criterion: Criterion::OnChainSettlement,
            score: Score::Pass,
            rationale: "vTXOs are backed by on-chain transactions and can be \
                        redeemed to the base layer. The pre-signed transaction \
                        tree ensures on-chain enforceability, though with timeout \
                        delays."
                .into(),
        }
    }

    fn assess_liveness_independence(&self) -> Assessment {
        Assessment {
            criterion: Criterion::LivenessIndependence,
            score: Score::Fail,
            rationale: "If the ASP goes offline, off-chain payments stop entirely. \
                        Users must wait for the vTXO timeout to reclaim funds. \
                        Prolonged ASP downtime means funds are locked and unusable \
                        for the timeout period. Users must refresh vTXOs before \
                        expiry or lose them to the ASP."
                .into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SovereigntyAssessable;

    #[test]
    fn ark_scores_correctly() {
        let report = Ark.assess();
        // 2 Pass (2.0) + 2 Partial (1.0) + 2 Fail (0.0) = 3.0
        assert_eq!(report.total_score(), 3.0);
        assert_eq!(report.pass_count(), 2);
    }

    #[test]
    fn ark_asp_trust_fails() {
        let assessment = Ark.assess_no_trusted_third_party();
        assert_eq!(assessment.score, Score::Fail);
    }

    #[test]
    fn ark_liveness_fails() {
        let assessment = Ark.assess_liveness_independence();
        assert_eq!(assessment.score, Score::Fail);
    }

    #[test]
    fn ark_self_custody_passes() {
        let assessment = Ark.assess_self_custody();
        assert_eq!(assessment.score, Score::Pass);
    }
}
