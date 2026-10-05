// Nucleon Transfer — F8.1-S6 session refresh tests (Swift Testing).
// Offline only: a fake `SessionAuthAPI` counts refreshes and can hold one
// in flight; a URLProtocol stub stands in for redirecting servers.
import Foundation
import Synchronization
import Testing

@testable import NucleonTransfer

// MARK: - fake auth API

/// Counts refresh calls; each refresh rotates to "access-N"/"refresh-N".
/// With `holdRefresh`, the first refresh blocks until `release()` — the wait
/// is a plain continuation, so cancellation does not end it early.
private final class FakeAuthAPI: SessionAuthAPI {
    private struct State {
        var refreshes: [AuthRefreshRequest] = []
        var deletes = 0
        var waiter: CheckedContinuation<Void, Never>?
        var released = false
    }

    private let state = Mutex(State())
    private let holdRefresh: Bool
    /// Like `holdRefresh`, but the wait is a cancellable sleep: cancelling
    /// the refresh task (replaceSession) ends it with CancellationError.
    private let cancellableHold: Bool

    init(holdRefresh: Bool = false, cancellableHold: Bool = false) {
        self.holdRefresh = holdRefresh
        self.cancellableHold = cancellableHold
    }

    var refreshCount: Int { state.withLock { $0.refreshes.count } }
    var refreshTokensSent: [String] { state.withLock { $0.refreshes.map(\.refreshToken) } }
    var deleteCount: Int { state.withLock { $0.deletes } }

    func release() {
        let waiter = state.withLock { s -> CheckedContinuation<Void, Never>? in
            s.released = true
            defer { s.waiter = nil }
            return s.waiter
        }
        waiter?.resume()
    }

    func authRefresh(_ body: AuthRefreshRequest) async throws -> ProtonAuth {
        let n = state.withLock { s -> Int in
            s.refreshes.append(body)
            return s.refreshes.count
        }
        if cancellableHold {
            try await Task.sleep(for: .seconds(60))
        } else if holdRefresh {
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                let resumeNow = state.withLock { s -> Bool in
                    if s.released { return true }
                    s.waiter = c
                    return false
                }
                if resumeNow { c.resume() }
            }
        } else {
            // Give concurrent 401s time to pile up on the in-flight refresh.
            try await Task.sleep(for: .milliseconds(50))
        }
        let json = #"{"UID":"uid","AccessToken":"access-\#(n)","RefreshToken":"refresh-\#(n)"}"#
        return try JSONDecoder().decode(ProtonAuth.self, from: Data(json.utf8))
    }

    func authDelete(uid: String, accessToken: String) async throws {
        state.withLock { $0.deletes += 1 }
    }
}

private func signedInManager(_ api: FakeAuthAPI) async -> SessionManager {
    let manager = SessionManager(authAPI: api)
    await manager.adopt(ProtonSession(uid: "uid", accessToken: "access-0", refreshToken: "refresh-0"))
    return manager
}

/// Polls until `condition` holds (bounded), for cross-task ordering in tests.
private func waitUntil(_ condition: () -> Bool) async {
    for _ in 0..<500 where !condition() {
        try? await Task.sleep(for: .milliseconds(5))
    }
}

struct SessionRefreshTests {

    @Test func concurrent401sShareOneRefresh() async throws {
        let api = FakeAuthAPI()
        let manager = await signedInManager(api)

        let tokens = try await withThrowingTaskGroup(of: String.self) { group in
            for _ in 0..<10 {
                group.addTask {
                    try await manager.withAuth { _, token in
                        // Only the rotated token is accepted: each op 401s once.
                        guard token != "access-0" else { throw ProtonAPIError.unauthorized }
                        return token
                    }
                }
            }
            var all: [String] = []
            for try await t in group { all.append(t) }
            return all
        }

        #expect(api.refreshCount == 1)
        #expect(api.refreshTokensSent == ["refresh-0"])
        #expect(tokens == Array(repeating: "access-1", count: 10))
        #expect(await manager.credentials()?.refreshToken == "refresh-1")
    }

    @Test func sequentialRefreshesUseRotatedToken() async throws {
        let api = FakeAuthAPI()
        let manager = await signedInManager(api)
        try await manager.refresh()
        try await manager.refresh()
        #expect(api.refreshTokensSent == ["refresh-0", "refresh-1"])
        #expect(await manager.credentials()?.accessToken == "access-2")
    }

    @Test func alreadyRotatedTokenRetriesWithoutRefreshing() async throws {
        let api = FakeAuthAPI()
        let manager = await signedInManager(api)

        let token = try await manager.withAuth { _, token in
            if token == "access-0" {
                // Another caller rotates the tokens before this 401 lands.
                try await manager.refresh()
                throw ProtonAPIError.unauthorized
            }
            return token
        }

        #expect(token == "access-1")
        #expect(api.refreshCount == 1)
    }

    @Test func signOutDuringRefreshKeepsSessionNil() async throws {
        let api = FakeAuthAPI(holdRefresh: true)
        let manager = await signedInManager(api)

        let pending = Task { try await manager.refresh() }
        await waitUntil { api.refreshCount == 1 }
        #expect(api.refreshCount == 1)

        await manager.signOut()
        api.release()   // the server answers after sign-out

        await #expect(throws: (any Error).self) { try await pending.value }
        #expect(await manager.isSignedIn == false)
        #expect(await manager.credentials() == nil)
        #expect(api.deleteCount == 1)
    }

    @Test func refreshAfterReloginIsNotPoisonedByOldOne() async throws {
        let api = FakeAuthAPI(holdRefresh: true)
        let manager = await signedInManager(api)

        let stale = Task { try await manager.refresh() }
        await waitUntil { api.refreshCount == 1 }
        let fresh = ProtonSession(uid: "uid2", accessToken: "new-access", refreshToken: "new-refresh")
        await manager.adopt(fresh)
        api.release()

        await #expect(throws: (any Error).self) { try await stale.value }
        #expect(await manager.credentials() == fresh)
    }

    @Test func opIsNotReplayedWithAnotherSessionsToken() async throws {
        let api = FakeAuthAPI()
        let manager = await signedInManager(api)
        let seen = Mutex([String]())
        let next = ProtonSession(uid: "uid2", accessToken: "new-access", refreshToken: "new-refresh")

        await #expect(throws: ProtonAPIError.unauthorized) {
            try await manager.withAuth { _, token in
                seen.withLock { $0.append(token) }
                if token == "access-0" {
                    // Sign-out + a new session land before this 401.
                    await manager.signOut()
                    await manager.adopt(next)
                    throw ProtonAPIError.unauthorized
                }
                return token
            }
        }
        #expect(seen.withLock { $0 } == ["access-0"])
        #expect(api.refreshCount == 0)
        #expect(await manager.credentials() == next)
    }

    @Test func opIsNotReplayedAfterRefreshOfAReplacedSession() async throws {
        let api = FakeAuthAPI(holdRefresh: true)
        let manager = await signedInManager(api)
        let seen = Mutex([String]())

        let op = Task {
            try await manager.withAuth { _, token in
                seen.withLock { $0.append(token) }
                guard token != "access-0" else { throw ProtonAPIError.unauthorized }
                return token
            }
        }
        await waitUntil { api.refreshCount == 1 }
        await manager.adopt(ProtonSession(uid: "uid2", accessToken: "new-access", refreshToken: "new-refresh"))
        api.release()

        await #expect(throws: ProtonAPIError.unauthorized) { try await op.value }
        #expect(seen.withLock { $0 } == ["access-0"])
    }

    @Test func refreshCancelledBySessionReplacementIsUnauthorized() async throws {
        let api = FakeAuthAPI(cancellableHold: true)
        let manager = await signedInManager(api)

        let starter = Task { try await manager.refresh() }
        await waitUntil { api.refreshCount == 1 }
        let joiner = Task { try await manager.refresh() }
        try await Task.sleep(for: .milliseconds(20))   // let the joiner attach
        await manager.adopt(ProtonSession(uid: "uid2", accessToken: "new-access", refreshToken: "new-refresh"))

        await #expect(throws: ProtonAPIError.unauthorized) { try await starter.value }
        await #expect(throws: ProtonAPIError.unauthorized) { try await joiner.value }
        #expect(api.refreshCount == 1)
    }

    @Test func callerCancellationStillSurfacesAsCancellation() async throws {
        let api = FakeAuthAPI(cancellableHold: true)
        let manager = await signedInManager(api)

        let caller = Task { try await manager.refresh() }
        await waitUntil { api.refreshCount == 1 }
        caller.cancel()   // the caller's own task…
        await manager.adopt(ProtonSession(uid: "uid2", accessToken: "new-access", refreshToken: "new-refresh"))

        await #expect(throws: CancellationError.self) { try await caller.value }
    }

    @Test func withAuthSignedOutThrowsUnauthorized() async {
        let manager = SessionManager(authAPI: FakeAuthAPI())
        await #expect(throws: ProtonAPIError.unauthorized) {
            try await manager.withAuth { _, _ in 1 }
        }
    }
}

// MARK: - redirect safety

private struct RedirectStubState: Sendable {
    var location = ""
    var requests: [URL] = []
}

private let redirectStub = Mutex(RedirectStubState())

/// First request to any URL answers 302 → `location`; a request to
/// `location` itself answers 200 "followed".
private final class RedirectStubProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let url = request.url ?? URL(string: "about:blank")!
        let location = redirectStub.withLock { s in
            s.requests.append(url)
            return s.location
        }
        if url.absoluteString == location {
            let ok = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: nil)!
            client?.urlProtocol(self, didReceive: ok, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data("followed".utf8))
            client?.urlProtocolDidFinishLoading(self)
            return
        }
        let redirect = HTTPURLResponse(url: url, statusCode: 302, httpVersion: "HTTP/1.1",
                                       headerFields: ["Location": location])!
        var next = request
        next.url = URL(string: location)
        // Ask the loading system; if the delegate refuses, the 302 itself
        // becomes the final response.
        client?.urlProtocol(self, wasRedirectedTo: next, redirectResponse: redirect)
        client?.urlProtocol(self, didReceive: redirect, cacheStoragePolicy: .notAllowed)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

private func redirectingClient(to location: String) -> APIClient {
    redirectStub.withLock { $0 = RedirectStubState(location: location, requests: []) }
    let config = APIClient.makeConfiguration()
    config.protocolClasses = [RedirectStubProtocol.self]
    var api = APIClient()
    api.session = URLSession(configuration: config, delegate: RedirectGuard(), delegateQueue: nil)
    return api
}

private func redirectRequests() -> [URL] { redirectStub.withLock { $0.requests } }

@Suite(.serialized)
struct RedirectGuardTests {

    @Test func defaultSessionHasRedirectGuard() {
        #expect(APIClient.defaultSession.delegate is RedirectGuard)
    }

    @Test(arguments: [
        ("https://zrh-storage.proton.me/a", "https://zrh-storage.proton.me/b", true),
        ("https://mail.proton.me/api/x", "https://MAIL.proton.me/api/y", true),
        ("https://zrh-storage.proton.me/a", "https://evil.com/a", false),
        ("https://zrh-storage.proton.me/a", "https://fra-storage.proton.me/a", false),
        ("https://zrh-storage.proton.me/a", "http://zrh-storage.proton.me/a", false),
        ("https://zrh-storage.proton.me/a", "https://zrh-storage.proton.me:8443/a", false),
        ("https://zrh-storage.proton.me/a", "https://u:p@zrh-storage.proton.me/a", false),
    ])
    func policy(_ from: String, _ to: String, _ allowed: Bool) {
        #expect(RedirectGuard.allows(from: URL(string: from), to: URL(string: to)) == allowed)
    }

    @Test func crossHostRedirectIsNotFollowed() async {
        let api = redirectingClient(to: "https://evil.com/steal")
        await #expect {
            _ = try await api.downloadRawBlock(
                bareURL: "https://zrh-storage.proton.me/storage/blocks",
                token: "t", uid: "u", accessToken: "a")
        } throws: { error in
            guard case let .http(status, _, _, _) = error as? ProtonAPIError else { return false }
            return status == 302
        }
        #expect(redirectRequests().map(\.host) == ["zrh-storage.proton.me"])
    }

    @Test func crossHostRedirectOnAPIIsNotFollowed() async {
        let api = redirectingClient(to: "https://evil.com/api/core/v4/users")
        await #expect(throws: (any Error).self) {
            _ = try await api.get(ProtonEnvelope.self, path: "/core/v4/users", uid: "u", accessToken: "a")
        }
        #expect(redirectRequests().allSatisfy { $0.host != "evil.com" })
    }

    @Test func sameHostRedirectIsFollowed() async throws {
        let target = "https://zrh-storage.proton.me/storage/blocks/moved"
        let api = redirectingClient(to: target)
        let data = try await api.downloadRawBlock(
            bareURL: "https://zrh-storage.proton.me/storage/blocks",
            token: "t", uid: "u", accessToken: "a")
        #expect(data == Data("followed".utf8))
        #expect(redirectRequests().map(\.absoluteString).last == target)
    }
}
