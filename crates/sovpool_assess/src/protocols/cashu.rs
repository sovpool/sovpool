use crate::{Assessment, Criterion, Score, SovereigntyAssessable};

/// Cashu — ecash mint-based protocol for Bitcoin.
///
/// Cashu provides excellent privacy through blind signatures but is
/// fundamentally custodial. The mint holds all funds and users hold
/// bearer tokens (ecash notes) redeemable at the mint.
pub struct Cashu;

impl SovereigntyAssessable for Cashu {
    fn protocol_name(&self) -> &str {
        "Cashu"
    }

    fn protocol_description(&self) -> &str {
        "Chaumian ecash protocol for Bitcoin. Users deposit sats to a mint \
         and receive blind-signed ecash tokens. Tokens are bearer instruments \
         with excellent privacy but the mint is fully custodial. Redemption \
         requires mint cooperation."
    }

    fn assess_self_custody(&self) -> Assessment {
        Assessment {
            criterion: Criterion::SelfCustody,
            score: Score::Fail,
            rationale: "The mint holds all Bitcoin. Users hold ecash tokens (blind-signed \
                        bearer instruments) but not private keys to on-chain funds. \
                        The mint can rug-pull at any time. This is custodial by design."
                .into(),
        }
    }

    fn assess_unilateral_exit(&self) -> Assessment {
        Assessment {
            criterion: Criterion::UnilateralExit,
            score: Score::Fail,
            rationale: "Users cannot withdraw without mint cooperation. If the mint \
                        goes offline or refuses redemption, ecash tokens become worthless. \
                        There is no on-chain fallback or timeout mechanism."
                .into(),
        }
    }

    fn assess_no_trusted_third_party(&self) -> Assessment {
        Assessment {
            criterion: Criterion::NoTrustedThirdParty,
            score: Score::Fail,
            rationale: "The mint is a fully trusted third party. It holds all funds, \
                        issues tokens, and must cooperate for any redemption. Users \
                        trust the mint not to inflate supply, refuse redemptions, \
                        or disappear with funds."
                .into(),
        }
    }

    fn assess_censorship_resistance(&self) -> Assessment {
        Assessment {
            criterion: Criterion::CensorshipResistance,
            score: Score::Partial,
            rationale: "Token transfers between users are peer-to-peer and private \
                        (blind signatures prevent mint from linking sender/receiver). \
                        However, the mint can refuse to redeem specific tokens or \
                        blacklist denominations. Minting and melting require mint approval."
                .into(),
        }
    }

    fn assess_on_chain_settlement(&self) -> Assessment {
        Assessment {
            criterion: Criterion::OnChainSettlement,
            score: Score::Fail,
            rationale: "Ecash tokens are not enforceable on-chain. There is no \
                        script-based mechanism to force the mint to honor redemptions. \
                        Users rely entirely on mint honesty and availability."
                .into(),
        }
    }

    fn assess_liveness_independence(&self) -> Assessment {
        Assessment {
            criterion: Criterion::LivenessIndependence,
            score: Score::Fail,
            rationale: "If the mint goes offline, all user funds are inaccessible. \
                        There is no timeout, recovery path, or alternative settlement \
                        mechanism. Extended mint downtime means total loss of access."
                .into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SovereigntyAssessable;

    #[test]
    fn cashu_scores_correctly() {
        let report = Cashu.assess();
        // 0 Pass + 1 Partial (0.5) + 5 Fail (0.0) = 0.5
        assert_eq!(report.total_score(), 0.5);
        assert_eq!(report.pass_count(), 0);
    }

    #[test]
    fn cashu_is_custodial() {
        let assessment = Cashu.assess_self_custody();
        assert_eq!(assessment.score, Score::Fail);
    }

    #[test]
    fn cashu_no_unilateral_exit() {
        let assessment = Cashu.assess_unilateral_exit();
        assert_eq!(assessment.score, Score::Fail);
    }

    #[test]
    fn cashu_censorship_partial() {
        // Token transfers are private but mint can refuse redemption
        let assessment = Cashu.assess_censorship_resistance();
        assert_eq!(assessment.score, Score::Partial);
    }

    #[test]
    fn cashu_no_on_chain_settlement() {
        let assessment = Cashu.assess_on_chain_settlement();
        assert_eq!(assessment.score, Score::Fail);
    }
}
