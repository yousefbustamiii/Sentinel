import Foundation

enum ProcessEvidenceBuilder {
    static func build(
        name: String,
        path: String,
        processId: Int32,
        context: HeuristicContext
    ) -> [Evidence] {
        var evidence: [Evidence] = []

        if let pathEvidence = HeuristicEngine.checkPathAnomaly(path: path, source: .process, context: context) {
            evidence.append(pathEvidence)
        }

        if let searchPathEvidence = HeuristicEngine.checkSearchPathAnomaly(
            path: path,
            source: .process,
            context: context
        ) {
            evidence.append(searchPathEvidence)
        }

        if let parentEvidence = HeuristicEngine.checkParentAnomaly(source: .process, context: context) {
            evidence.append(parentEvidence)
        }

        if let nameEvidence = HeuristicEngine.checkNameAnomaly(name: name, source: .process, context: context) {
            evidence.append(nameEvidence)
        }

        if CodeSignatureService.isUnverified(pid: processId) {
            evidence.append(Evidence(
                code: .unverifiedIdentity,
                description: "Process identity is unverified or untrusted by system policy.",
                source: .process
            ))
        }

        return evidence
    }
}
