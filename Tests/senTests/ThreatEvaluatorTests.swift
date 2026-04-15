import XCTest
@testable import sen

final class ThreatEvaluatorTests: XCTestCase {
    var tempRoot: URL!
    var originalConfig: Configuration!

    override func setUp() {
        super.setUp()
        originalConfig = Configuration.shared
        tempRoot = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: tempRoot, withIntermediateDirectories: true)

        var config = Configuration.shared
        config.customRootDirectory = tempRoot
        Configuration.shared = config
        FindingStore.shared.reset()
    }

    override func tearDown() {
        FindingStore.shared.reset()
        Configuration.shared = originalConfig
        try? FileManager.default.removeItem(at: tempRoot)
        super.tearDown()
    }

    func testEvaluate_WithLowScore_ReturnsNone() {
        let evidence = [
            Evidence(code: .unsignedBinary, description: "Unsigned", source: .process) // Weight 1
        ]
        
        let result = ThreatEvaluator.evaluate(
            category: .rat,
            name: "LowScoreApp",
            evidence: evidence
        )
        
        XCTAssertEqual(result.level, .none)
    }

    func testEvaluate_WithExactObservationThreshold_ReturnsObservation() {
        let evidence = [
            Evidence(code: .hiddenRootItem, description: "Hidden item", source: .process)
        ] // Weight 2

        let result = ThreatEvaluator.evaluate(
            category: .process,
            name: "ExactObservationThreshold",
            evidence: evidence
        )

        XCTAssertEqual(result.level, .observation)
    }
    
    func testEvaluate_WithObservationThreshold_ReturnsObservation() {
        let evidence = [
            Evidence(code: .pathAnomaly, description: "Path anomaly", source: .process) 
        ]
        
        let result = ThreatEvaluator.evaluate(
            category: .rat,
            name: "ObservationApp",
            evidence: evidence
        )
        
        XCTAssertEqual(result.level, .observation)
        if case .observation(let threat) = result {
            XCTAssertEqual(threat.severity, ThreatSeverity.low)
        } else {
            XCTFail("Expected observation")
        }
    }
    
    func testEvaluate_WithAlertThreshold_ReturnsAlert() {
        let evidence = [
            Evidence(code: .tamperingDetected, description: "Tampering!", source: .process) // Weight 10
        ]
        
        let result = ThreatEvaluator.evaluate(
            category: .rat,
            name: "HighRiskApp",
            evidence: evidence
        )
        
        XCTAssertEqual(result.level, .alert)
        if case .alert(let threat) = result {
            XCTAssertEqual(threat.severity, ThreatSeverity.medium)
        } else {
            XCTFail("Expected alert")
        }
    }

    func testEvaluate_WithExactAlertThreshold_ReturnsAlert() {
        let evidence = [
            Evidence(code: .dylibInjection, description: "Injected", source: .process),
            Evidence(code: .pathAnomaly, description: "Path anomaly", source: .process)
        ] // 5 + 3 = 8

        let result = ThreatEvaluator.evaluate(
            category: .process,
            name: "ExactAlertThreshold",
            evidence: evidence
        )

        XCTAssertEqual(result.level, .alert)
    }
    
    func testEvaluate_WithEscalation_ReturnsAlert() {
        let evidence = [
            Evidence(code: .dylibInjection, description: "Dylib", source: .process),    // 5
            Evidence(code: .pathAnomaly, description: "Path", source: .process),         // 3
            Evidence(code: .unverifiedIdentity, description: "Identity", source: .process) // 3
        ] // Total 11
        
        let result = ThreatEvaluator.evaluate(
            category: .rat,
            name: "EscalatedApp",
            evidence: evidence
        )
        
        XCTAssertEqual(result.level, .alert)
        if case .alert(let threat) = result {
            XCTAssertEqual(threat.severity, ThreatSeverity.medium)
            XCTAssertEqual(threat.confidence, ThreatConfidence.moderate)
        }
    }
    
    func testEvaluate_SystemTrustCredit_ReducesScore() {
        XCTAssertEqual(
            ThreatScoring.applySystemTrustCredit(totalScore: 10, isEligible: true),
            4
        )
        XCTAssertEqual(
            ThreatScoring.applySystemTrustCredit(totalScore: 3, isEligible: true),
            0
        )
        XCTAssertEqual(
            ThreatScoring.applySystemTrustCredit(totalScore: 10, isEligible: false),
            10
        )
    }

    func testEvaluate_EvidenceOrderDoesNotChangeDetectionLevel() {
        let evidenceA = [
            Evidence(code: .dylibInjection, description: "Injected", source: .process),
            Evidence(code: .pathAnomaly, description: "Path anomaly", source: .process),
            Evidence(code: .unverifiedIdentity, description: "Unverified", source: .process)
        ]
        let evidenceB = [
            Evidence(code: .unverifiedIdentity, description: "Unverified", source: .process),
            Evidence(code: .dylibInjection, description: "Injected", source: .process),
            Evidence(code: .pathAnomaly, description: "Path anomaly", source: .process)
        ]

        let resultA = ThreatEvaluator.evaluate(
            category: .process,
            name: "OrderedA",
            evidence: evidenceA
        )
        let resultB = ThreatEvaluator.evaluate(
            category: .process,
            name: "OrderedB",
            evidence: evidenceB
        )

        XCTAssertEqual(resultA.level, resultB.level)

        if case .alert(let threatA) = resultA, case .alert(let threatB) = resultB {
            XCTAssertEqual(threatA.severity, threatB.severity)
            XCTAssertEqual(threatA.confidence, threatB.confidence)
        } else {
            XCTFail("Expected alerts for both evidence orderings")
        }
    }

    func testEvaluate_TiedWeights_UsesStableExplanationFromInputOrder() {
        let evidence = [
            Evidence(code: .pathAnomaly, description: "First tied explanation", source: .process),
            Evidence(code: .searchPathExecution, description: "Second tied explanation", source: .process)
        ] // both weight 3

        let result = ThreatEvaluator.evaluate(
            category: .process,
            name: "TiedWeights",
            evidence: evidence
        )

        if case .observation(let threat) = result {
            XCTAssertTrue(threat.explanation.contains("First tied explanation"))
        } else {
            XCTFail("Expected observation")
        }
    }

    func testEvaluate_WithHighSeverityThreshold_ReturnsHighSeverity() {
        let evidence = [
            Evidence(code: .tamperingDetected, description: "Tampering", source: .process),
            Evidence(code: .unverifiedIdentity, description: "Unsigned signer", source: .process),
            Evidence(code: .hiddenRootItem, description: "Hidden path", source: .process)
        ]

        let result = ThreatEvaluator.evaluate(
            category: .process,
            name: "HighSeverityApp",
            evidence: evidence
        )

        if case .alert(let threat) = result {
            XCTAssertEqual(threat.severity, .high)
        } else {
            XCTFail("Expected alert")
        }
    }

    func testEvaluate_WithThreeSignalsAndScoreTwelve_ReturnsStrongConfidence() {
        let evidence = [
            Evidence(code: .dylibInjection, description: "Injected", source: .process),
            Evidence(code: .pathAnomaly, description: "Path anomaly", source: .process),
            Evidence(code: .newPersistence, description: "Persistence", source: .process)
        ]

        let result = ThreatEvaluator.evaluate(
            category: .process,
            name: "ConfidenceApp",
            evidence: evidence
        )

        if case .alert(let threat) = result {
            XCTAssertEqual(threat.confidence, .strong)
        } else {
            XCTFail("Expected alert")
        }
    }

    func testEvaluate_UsesHighestWeightEvidenceForExplanation() {
        let evidence = [
            Evidence(code: .pathAnomaly, description: "Path anomaly", source: .process),
            Evidence(code: .tamperingDetected, description: "Fingerprint mismatch", source: .process)
        ]

        let result = ThreatEvaluator.evaluate(
            category: .process,
            name: "ExplainedApp",
            evidence: evidence
        )

        if case .alert(let threat) = result {
            XCTAssertTrue(threat.explanation.contains("Fingerprint mismatch"))
        } else {
            XCTFail("Expected alert")
        }
    }

    func testEvaluate_DebouncesRepeatAlertIntoObservation() throws {
        let evidence = [
            Evidence(code: .tamperingDetected, description: "Tampering", source: .process)
        ]

        let first = ThreatEvaluator.evaluate(
            category: .process,
            name: "DebouncedApp",
            evidence: evidence
        )
        XCTAssertEqual(first.level, .alert)

        let result = ThreatEvaluator.evaluate(
            category: .process,
            name: "DebouncedApp",
            evidence: evidence
        )

        XCTAssertEqual(result.level, .observation)
    }
}
