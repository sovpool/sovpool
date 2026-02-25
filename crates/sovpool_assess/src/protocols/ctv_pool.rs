use crate::{Assessment, Criterion, Score, SovereigntyAssessable};

/// CTV Payment Pool — shared UTXO with covenant-enforced unilateral exit.
///
/// Target: 6/6 on sovereignty criteria. CTV pools use OP_CHECKTEMPLATEVERIFY
/// (BIP-119) to pre-commit exit paths into the UTXO itself, enabling
/// trustless, non-interactive unilateral exit without any coordinator.
pub struct CtvPool;

impl SovereigntyAssessable for CtvPool {
    fn protocol_name(&self) -> &str {
        "CTV Payment Pool"
    }

    fn protocol_description(&self) -> &str {
        "Shared UTXO (payment pool) using BIP-119 OP_CHECKTEMPLATEVERIFY to \
         enforce exit paths via covenants. Multiple participants share a single \
         UTXO with pre-committed unilateral exit transactions. No coordinator, \
         no trusted third party. Each participant can exit independently by \
         broadcasting the CTV-committed exit transaction."
    }

    fn assess_self_custody(&self) -> Assessment {
        Assessment {
            criterion: Criterion::SelfCustody,
            score: Score::Pass,
            rationale: "Each participant holds their own keys. The pool UTXO is locked \
                        under a taproot tree where each leaf contains a CTV-committed \
                        exit path to the participant's withdrawal address. No party \
                        holds custody of another's funds."
                .into(),
        }
    }

    fn assess_unilateral_exit(&self) -> Assessment {
        Assessment {
            criterion: Criterion::UnilateralExit,
            score: Score::Pass,
            rationale: "Exit paths are enforced by CTV covenants embedded in the UTXO \
                        script. Any participant can broadcast their exit transaction \
                        at any time without cooperation from other pool members. The \
                        covenant guarantees the exit transaction's outputs."
                .into(),
        }
    }

    fn assess_no_trusted_third_party(&self) -> Assessment {
        Assessment {
            criterion: Criterion::NoTrustedThirdParty,
            score: Score::Pass,
            rationale: "Pool construction requires an interactive setup phase (all \
                        participants must agree on the CTV tree), but once funded, \
                        no coordinator or third party is needed. Exit is enforced by \
                        consensus rules (OP_CHECKTEMPLATEVERIFY), not trust. \
                        Caveat: a coordinator is required for pool setup and cooperative \
                        updates, but not for unilateral exit."
                .into(),
        }
    }

    fn assess_censorship_resistance(&self) -> Assessment {
        Assessment {
            criterion: Criterion::CensorshipResistance,
            score: Score::Pass,
            rationale: "Exit transactions are standard Bitcoin transactions that any \
                        miner can include. No pool member can prevent another from \
                        exiting. The CTV commitment means exit transactions are \
                        predetermined and cannot be modified or censored at the \
                        protocol level."
                .into(),
        }
    }

    fn assess_on_chain_settlement(&self) -> Assessment {
        Assessment {
            criterion: Criterion::OnChainSettlement,
            score: Score::Pass,
            rationale: "All exit paths settle directly on the Bitcoin base layer. \
                        The CTV covenant is enforced by consensus. Exit transactions \
                        are standard Bitcoin transactions with full on-chain finality."
                .into(),
        }
    }

    fn assess_liveness_independence(&self) -> Assessment {
        Assessment {
            criterion: Criterion::LivenessIndependence,
            score: Score::Pass,
            rationale: "Once the pool is funded, no participant needs to be online for \
                        others to exit. CTV exit paths are non-interactive — they are \
                        determined at pool creation time. Offline participants do not \
                        block others' exits or put funds at risk. \
                        Caveat: cooperative updates require all participants to be online. \
                        Unilateral exit works independently."
                .into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SovereigntyAssessable;

    #[test]
    fn ctv_pool_scores_six_of_six() {
        let report = CtvPool.assess();
        assert_eq!(report.total_score(), 6.0);
        assert_eq!(report.pass_count(), 6);
    }

    #[test]
    fn ctv_pool_all_criteria_pass() {
        let report = CtvPool.assess();
        for assessment in &report.assessments {
            assert_eq!(
                assessment.score,
                Score::Pass,
                "{} should pass for CTV Pool",
                assessment.criterion
            );
        }
    }

    #[test]
    fn ctv_pool_matches_l1_score() {
        use crate::protocols::l1::BitcoinL1;
        let l1_report = BitcoinL1.assess();
        let ctv_report = CtvPool.assess();
        assert_eq!(l1_report.total_score(), ctv_report.total_score());
    }
}
