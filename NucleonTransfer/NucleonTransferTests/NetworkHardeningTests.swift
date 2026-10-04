// Nucleon Transfer — F8.1-S4 network hardening tests (Swift Testing).
// Offline only: a URLProtocol stub on an injected ephemeral configuration
// stands in for the network. Verifies the hardened session config, the
// storage-host allowlist (nothing sent on rejection) and that non-2xx
// storage statuses survive into the thrown error.
import Foundation
import Synchronization
import Testing

@testable import NucleonTransfer

// MARK: - stub

/// Canned response + request log shared with `StubURLProtocol`.
private struct StubState: Sendable {
    var status = 200
    var body = Data()
    var requests: [URL] = []
}

private let stubState = Mutex(StubState())

private final class StubURLProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let url = request.url ?? URL(string: "about:blank")!
        let (status, body) = stubState.withLock { state in
            state.requests.append(url)
            return (state.status, state.body)
        }
        let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

private func stubbedClient(status: Int, body: Data = Data()) -> APIClient {
    stubState.withLock { $0 = StubState(status: status, body: body, requests: []) }
    let config = APIClient.makeConfiguration()
    config.protocolClasses = [StubURLProtocol.self]
    var api = APIClient()
    api.session = URLSession(configuration: config)
    return api
}

private func sentRequests() -> [URL] { stubState.withLock { $0.requests } }

// Serialized: the stub state is process-global.
@Suite(.serialized)
struct NetworkHardeningTests {

    // MARK: session configuration

    @Test func defaultSessionHasNoDiskCacheOrCookies() {
        let config = APIClient.defaultSession.configuration
        #expect(config.urlCache == nil)
        #expect(config.httpCookieStorage == nil)
        #expect(config.httpShouldSetCookies == false)
        #expect(config.httpCookieAcceptPolicy == .never)
        #expect(config.urlCredentialStorage == nil)
        #expect(config.requestCachePolicy == .reloadIgnoringLocalCacheData)
        #expect(config.timeoutIntervalForRequest == 60)
        #expect(config.timeoutIntervalForResource >= 600)
        #expect(config.httpMaximumConnectionsPerHost == 6)
    }

    @Test func defaultClientUsesSharedHardenedSession() {
        #expect(APIClient().session === APIClient.defaultSession)
        #expect(APIClient().session !== URLSession.shared)
    }

    // MARK: storage host allowlist

    @Test(arguments: [
        "https://zrh-storage.proton.me/storage/blocks",
        "https://fra-storage.proton.me/storage/blocks/tok",
        "https://proton.me/storage/blocks",
        "https://storage.protonmail.ch/blocks",
        "HTTPS://ZRH-STORAGE.PROTON.ME/storage/blocks",
    ])
    func acceptsProtonStorageHosts(_ url: String) throws {
        _ = try APIClient.validatedStorageURL(url)
    }

    @Test(arguments: [
        "http://zrh-storage.proton.me/storage/blocks",   // not https
        "https://evil.com/storage/blocks",
        "https://evilproton.me/storage/blocks",           // suffix without dot
        "https://proton.me.evil.com/storage/blocks",
        "https://user:pw@zrh-storage.proton.me/blocks",   // userinfo
        "ftp://zrh-storage.proton.me/blocks",
        "https:///nohost",
    ])
    func rejectsUntrustedStorageURLs(_ url: String) {
        #expect {
            _ = try APIClient.validatedStorageURL(url)
        } throws: { error in
            guard case .untrustedStorageHost = error as? ProtonAPIError else { return false }
            return true
        }
    }

    @Test func untrustedHostErrorNeverEchoesPathToken() {
        do {
            _ = try APIClient.validatedStorageURL("https://evil.com/storage/blocks/SECRET-TOKEN")
            Issue.record("expected throw")
        } catch {
            #expect(!"\(error)".contains("SECRET-TOKEN"))
            #expect(error as? ProtonAPIError == .untrustedStorageHost("https://evil.com"))
        }
    }

    @Test func downloadToHTTPHostSendsNothing() async {
        let api = stubbedClient(status: 200)
        await #expect(throws: ProtonAPIError.untrustedStorageHost("http://zrh-storage.proton.me")) {
            _ = try await api.downloadRawBlock(
                bareURL: "http://zrh-storage.proton.me/storage/blocks",
                token: "t", uid: "u", accessToken: "a")
        }
        #expect(sentRequests().isEmpty)
    }

    @Test func downloadURLToEvilHostSendsNothing() async {
        let api = stubbedClient(status: 200)
        await #expect(throws: ProtonAPIError.untrustedStorageHost("https://evil.com")) {
            _ = try await api.downloadRawBlockURL(
                url: "https://evil.com/storage/blocks/tok",
                token: "t", uid: "u", accessToken: "a")
        }
        #expect(sentRequests().isEmpty)
    }

    @Test func uploadToEvilHostSendsNothing() async {
        let api = stubbedClient(status: 200)
        await #expect(throws: ProtonAPIError.untrustedStorageHost("https://evil.com")) {
            try await api.uploadRawBlock(
                bareURL: "https://evil.com/storage/blocks",
                token: "t", uid: "u", accessToken: "a",
                body: Data([1, 2, 3]), boundary: "b")
        }
        #expect(sentRequests().isEmpty)
    }

    // MARK: status preservation

    @Test func downloadSuccessReturnsBytes() async throws {
        let api = stubbedClient(status: 200, body: Data([9, 8, 7]))
        let data = try await api.downloadRawBlock(
            bareURL: "https://zrh-storage.proton.me/storage/blocks",
            token: "t", uid: "u", accessToken: "a")
        #expect(data == Data([9, 8, 7]))
        #expect(sentRequests().count == 1)
    }

    @Test func storage503KeepsStatus() async {
        let api = stubbedClient(status: 503)
        await #expect(throws: ProtonAPIError.http(status: 503, code: nil, message: "storage HTTP 503")) {
            _ = try await api.downloadRawBlock(
                bareURL: "https://zrh-storage.proton.me/storage/blocks",
                token: "t", uid: "u", accessToken: "a")
        }
    }

    @Test func storage429KeepsStatusAndEnvelope() async {
        let body = Data(#"{"Code":2028,"Error":"slow down"}"#.utf8)
        let api = stubbedClient(status: 429, body: body)
        await #expect(throws: ProtonAPIError.http(status: 429, code: 2028, message: "slow down")) {
            try await api.uploadRawBlock(
                bareURL: "https://zrh-storage.proton.me/storage/blocks",
                token: "t", uid: "u", accessToken: "a",
                body: Data([1]), boundary: "b")
        }
    }

    @Test func storage401MapsToUnauthorized() async {
        let api = stubbedClient(status: 401)
        await #expect(throws: ProtonAPIError.unauthorized) {
            _ = try await api.downloadRawBlockURL(
                url: "https://zrh-storage.proton.me/storage/blocks/tok",
                token: "", uid: "u", accessToken: "a")
        }
    }

    @Test func apiNon2xxWithoutEnvelopeKeepsStatus() async throws {
        let api = stubbedClient(status: 502, body: Data("<html>bad gateway</html>".utf8))
        await #expect {
            _ = try await api.get(ProtonEnvelope.self, path: "/drive/shares", uid: "u", accessToken: "a")
        } throws: { error in
            guard case let .http(status, code, _) = error as? ProtonAPIError else { return false }
            return status == 502 && code == nil
        }
    }

    // MARK: classification unchanged (non-2xx storage stays permanent until R3)

    @Test func httpErrorClassificationAndMessage() {
        let e = ProtonAPIError.http(status: 503, code: nil, message: "storage HTTP 503")
        guard case .permanent = TransferErrorClassify.classify(e) else {
            Issue.record("expected permanent (pre-R3 behaviour)")
            return
        }
        #expect(UserFacingError.message(for: e).contains("Proton server error (503)"))
    }
}
