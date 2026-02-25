use crate::{Assessment, Criterion, Score, SovereigntyAssessable};

/// Bitcoin L1 — the baseline. Should score 6/6 on all sovereignty criteria.
pub struct BitcoinL1;

impl SovereigntyAssessable for BitcoinL1 {
    fn protocol_name(&self) -> &str {
        "Bitcoin L1"
    }

    fn protocol_description(&self) -> &str {
        "Base-layer Bitcoin transactions. The reference standard for sovereignty. \
         Users transact directly on the blockchain with full self-custody, \
         unilateral settlement, and no intermediaries."
    }

    fn assess_self_custody(&self) -> Assessment {
        Assessment {
            criterion: Criterion::SelfCustody,
            score: Score::Pass,
            rationale: "Users hold private keys directly. UTXOs are locked to \
                        user-controlled scripts. No third party ever has custody."
                .into(),
        }
    }

    fn assess_unilateral_exit(&self) -> Assessment {
        Assessment {
            criterion: Criterion::UnilateralExit,
            score: Score::Pass,
            rationale: "On-chain UTXOs are already at the base layer. There is \
                        no second layer to exit from. Users spend directly."
                .into(),
        }
    }

    fn assess_no_trusted_third_party(&self) -> Assessment {
        Assessment {
            criterion: Criterion::NoTrustedThirdParty,
            score: Score::Pass,
            rationale: "Consensus is enforced by the decentralized network of nodes. \
                        No single party can alter rules or block valid transactions \
                        at the protocol level."
                .into(),
        }
    }

    fn assess_censorship_resistance(&self) -> Assessment {
        Assessment {
            criterion: Criterion::CensorshipResistance,
            score: Score::Pass,
            rationale: "Any valid transaction paying sufficient fees will eventually \
                        be mined. Miners compete; censoring transactions is economically \
                        irrational for any individual miner."
                .into(),
        }
    }

    fn assess_on_chain_settlement(&self) -> Assessment {
        Assessment {
            criterion: Criterion::OnChainSettlement,
            score: Score::Pass,
            rationale: "Transactions settle directly on-chain. Finality is achieved \
                        through proof-of-work confirmations. No off-chain state to dispute."
                .into(),
        }
    }

    fn assess_liveness_independence(&self) -> Assessment {
        Assessment {
            criterion: Criterion::LivenessIndependence,
            score: Score::Pass,
            rationale: "No counterparties required. UTXOs persist on-chain regardless \
                        of whether any other party is online. Funds are never at risk \
                        from others' unavailability."
                .into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SovereigntyAssessable;

    #[test]
    fn l1_scores_six_of_six() {
        let report = BitcoinL1.assess();
        assert_eq!(report.total_score(), 6.0);
        assert_eq!(report.pass_count(), 6);
    }

    #[test]
    fn l1_all_criteria_pass() {
        let report = BitcoinL1.assess();
        for assessment in &report.assessments {
            assert_eq!(
                assessment.score,
                Score::Pass,
                "{} should pass for Bitcoin L1",
                assessment.criterion
            );
        }
    }
}
