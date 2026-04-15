import Foundation

enum ThreatScoring {
    static func applySystemTrustCredit(totalScore: Int, path: String?) -> Int {
        guard let path else { return totalScore }
        return applySystemTrustCredit(
            totalScore: totalScore,
            isEligible: CodeSignatureService.isAppleSigned(at: path) && !CodeSignatureService.isUnverified(at: path)
        )
    }

    static func applySystemTrustCredit(totalScore: Int, isEligible: Bool) -> Int {
        guard isEligible else { return totalScore }
        return max(0, totalScore - WeightConfig.systemTrustCredit)
    }
}
