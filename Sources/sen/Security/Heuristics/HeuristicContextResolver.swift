import AppKit
import Darwin
import Foundation

enum HeuristicContextResolver {
    static func processContext(
        category: ThreatCategory,
        name: String,
        pid: Int32,
        path: String,
        uniqueID: String?,
        app: NSRunningApplication
    ) -> HeuristicContext {
        buildContext(
            category: category,
            name: name,
            pid: pid,
            path: path,
            uniqueID: uniqueID,
            isInteractive: app.activationPolicy != .prohibited,
            hasPersistence: PersistenceTargetIndex.shared.hasLaunchTarget(at: path),
            listenerPort: nil
        )
    }

    static func networkContext(
        category: ThreatCategory,
        name: String,
        pid: Int32,
        path: String?,
        uniqueID: String?,
        app: NSRunningApplication?,
        listenerPort: Int?,
        userID: Int?,
        userName: String?,
        isLocalOnlyListener: Bool,
        hasResolvedExecutablePath: Bool,
        isRecurringListener: Bool
    ) -> HeuristicContext {
        buildContext(
            category: category,
            name: name,
            pid: pid,
            path: path,
            uniqueID: uniqueID,
            isInteractive: app?.activationPolicy != .prohibited,
            hasPersistence: path.map { PersistenceTargetIndex.shared.hasLaunchTarget(at: $0) } ?? false,
            listenerPort: listenerPort,
            userID: userID,
            userName: userName,
            isLocalOnlyListener: isLocalOnlyListener,
            hasResolvedExecutablePath: hasResolvedExecutablePath,
            isRecurringListener: isRecurringListener
        )
    }

    static func persistenceContext(
        category: ThreatCategory,
        name: String,
        path: String,
        uniqueID: String?
    ) -> HeuristicContext {
        buildContext(
            category: category,
            name: name,
            pid: nil,
            path: path,
            uniqueID: uniqueID,
            isInteractive: false,
            hasPersistence: true,
            listenerPort: nil
        )
    }

    private static func buildContext(
        category: ThreatCategory,
        name: String,
        pid: Int32?,
        path: String?,
        uniqueID: String?,
        isInteractive: Bool?,
        hasPersistence: Bool,
        listenerPort: Int?,
        userID: Int? = nil,
        userName: String? = nil,
        isLocalOnlyListener: Bool = false,
        hasResolvedExecutablePath: Bool = false,
        isRecurringListener: Bool = false
    ) -> HeuristicContext {
        let ancestry = pid.flatMap(processAncestry(for:)) ?? ProcessAncestrySnapshot(parentName: nil, grandparentName: nil)
        let normalizedPath = path.map { URL(fileURLWithPath: $0).resolvingSymlinksInPath().path }
        let identity = normalizedPath.map { CodeSignatureService.getIdentity(for: URL(fileURLWithPath: $0)) }
        let isSignatureValid = normalizedPath.map { !CodeSignatureService.isUnverified(at: $0) } ??
            pid.map { !CodeSignatureService.isUnverified(pid: $0) } ?? false
        let sightingRecord = FindingStore.shared.existingRecord(
            category: category.rawValue,
            name: name,
            path: normalizedPath,
            uniqueID: uniqueID
        )

        return HeuristicContext(
            path: normalizedPath,
            processName: name,
            parentProcessName: ancestry.parentName,
            grandparentProcessName: ancestry.grandparentName,
            signerTeamID: identity?.teamID,
            bundleID: identity?.bundleID,
            isAppleSigned: identity?.isAppleSigned ?? false,
            isSignatureValid: isSignatureValid,
            isInteractive: isInteractive ?? false,
            hasPersistence: hasPersistence,
            firstSeenAt: sightingRecord?.firstSeen,
            listenerPort: listenerPort,
            userID: userID,
            userName: userName,
            isLocalOnlyListener: isLocalOnlyListener,
            hasResolvedExecutablePath: hasResolvedExecutablePath,
            isRecurringListener: isRecurringListener,
            existingSightingCount: sightingRecord?.count ?? 0
        )
    }

    private static func processAncestry(for pid: Int32) -> ProcessAncestrySnapshot? {
        guard let processDetails = processInfo(for: pid) else { return nil }

        let parentPID = processDetails.kp_eproc.e_ppid
        let parentName = processName(for: parentPID)
        let grandparentPID = self.processInfo(for: parentPID)?.kp_eproc.e_ppid ?? 0
        let grandparentName = grandparentPID > 0 ? processName(for: grandparentPID) : nil

        return ProcessAncestrySnapshot(parentName: parentName, grandparentName: grandparentName)
    }

    private static func processName(for pid: Int32) -> String? {
        guard var processInfo = processInfo(for: pid) else { return nil }

        return withUnsafeBytes(of: &processInfo.kp_proc.p_comm) { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress?.assumingMemoryBound(to: CChar.self) else {
                return nil
            }
            return String(cString: baseAddress)
        }
    }

    private static func processInfo(for pid: Int32) -> kinfo_proc? {
        var processInfo = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]

        let status = sysctl(&mib, u_int(mib.count), &processInfo, &size, nil, 0)
        guard status == 0, size == MemoryLayout<kinfo_proc>.stride else {
            return nil
        }

        return processInfo
    }
}
