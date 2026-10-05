// Nucleon Transfer — minimal Proton REST client.
// Mirrors go-proton-api Manager.r(): base mail.proton.me/api, x-pm-appversion,
// x-pm-uid + Bearer on authed calls, 401 -> single refresh retry (in SessionManager).
// Network hygiene (F8.1-S4): one dedicated ephemeral URLSession (no disk
// cache, no cookie jar); storage URLs are host-checked before credentials go out.
// Redirects (F8.1-S6) are only followed to the same https host — a 3xx can
// never carry a request (and its headers) past `validatedStorageURL`.
import Foundation

struct APIClient: Sendable {
    var baseURL: URL = AppVersion.baseURL
    /// Injectable for tests (URLProtocol stubs); production shares `defaultSession`.
    var session: URLSession = APIClient.defaultSession

    /// One process-wide session so HTTP/2 connections to the API and storage
    /// hosts are reused. Ephemeral + nil cache/cookie storage: authenticated
    /// responses (armored keys, salts, Drive metadata) never land in a
    /// Cache.db and no cookie jar persists — README "nothing on disk".
    /// `RedirectGuard` refuses any redirect that leaves the original host.
    static let defaultSession = URLSession(configuration: makeConfiguration(),
                                           delegate: RedirectGuard(), delegateQueue: nil)

    /// The hardened configuration, exposed so tests can assert it and layer
    /// `protocolClasses` on top of the exact production settings.
    static func makeConfiguration() -> URLSessionConfiguration {
        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.httpCookieStorage = nil
        config.httpCookieAcceptPolicy = .never
        config.httpShouldSetCookies = false
        config.urlCredentialStorage = nil
        config.timeoutIntervalForRequest = 60
        // 4 MiB blocks on slow links: generous whole-transfer ceiling.
        config.timeoutIntervalForResource = 15 * 60
        config.httpMaximumConnectionsPerHost = 6
        return config
    }

    /// Validates a server-supplied storage URL (block BareURL / URL) BEFORE
    /// any credential is attached: https only, no userinfo, and a host equal
    /// to or under one of `AppVersion.storageHostSuffixes`. A hostile or
    /// buggy API response must not be able to redirect Bearer/UID/storage
    /// tokens to an arbitrary host.
    static func validatedStorageURL(_ string: String) throws -> URL {
        guard !string.isEmpty,
              let comps = URLComponents(string: string),
              let url = comps.url
        else {
            throw ProtonAPIError.transport(URLError(.badURL))
        }
        let host = (comps.host ?? "").lowercased()
        guard comps.scheme?.lowercased() == "https",
              comps.user == nil, comps.password == nil,
              !host.isEmpty,
              AppVersion.storageHostSuffixes.contains(where: { host == $0 || host.hasSuffix("." + $0) })
        else {
            let shown = host.isEmpty ? "<none>" : host
            throw ProtonAPIError.untrustedStorageHost("\(comps.scheme ?? "?")://\(shown)")
        }
        return url
    }

    func request(
        _ path: String,
        method: String = "POST",
        uid: String? = nil,
        accessToken: String? = nil,
        query: [String: String]? = nil,
        body: (any Encodable & Sendable)? = nil
    ) throws -> URLRequest {
        var url = baseURL.appendingPathComponent(path)
        if let query, !query.isEmpty {
            var comps = URLComponents(url: url, resolvingAgainstBaseURL: false)!
            comps.queryItems = query.map { URLQueryItem(name: $0.key, value: $0.value) }
            url = comps.url!
        }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue(AppVersion.headerValue, forHTTPHeaderField: "x-pm-appversion")
        if let uid { req.setValue(uid, forHTTPHeaderField: "x-pm-uid") }
        if let accessToken { req.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization") }
        if let body {
            req.httpBody = try JSONEncoder().encode(AnyEncodable(body))
        }
        return req
    }

    func authInfo(username: String) async throws -> AuthInfo {
        let req = try request("/auth/v4/info", body: AuthInfoRequest(username: username))
        return try await decode(AuthInfoResponse.self, request: req).authInfo
    }

    func auth(_ body: AuthRequest) async throws -> AuthResponse {
        let req = try request("/auth/v4", body: body)
        return try await decode(AuthResponse.self, request: req)
    }

    func auth2FA(code: String, uid: String, accessToken: String) async throws {
        let req = try request("/auth/v4/2fa", uid: uid, accessToken: accessToken,
                              body: Auth2FARequest(twoFACode: code))
        _ = try await data(for: req)
    }

    func authRefresh(_ body: AuthRefreshRequest) async throws -> ProtonAuth {
        let req = try request("/auth/v4/refresh", body: body)
        return try await decode(AuthResponse.self, request: req).auth
    }

    /// Server-side logout: `DELETE /auth/v4` with x-pm-uid + Bearer
    /// (go-proton-api `auth.go` — `func (c *Client) AuthDelete`). Decoding
    /// the envelope surfaces non-1000/1001 codes; callers treat it as
    /// best-effort (local sign-out always wins).
    func authDelete(uid: String, accessToken: String) async throws {
        let req = try request("/auth/v4", method: "DELETE", uid: uid, accessToken: accessToken)
        _ = try await decode(ProtonEnvelope.self, request: req)
    }

    /// Authenticated GET with query params (Drive API style).
    func get<T: Decodable>(
        _ type: T.Type,
        path: String,
        uid: String,
        accessToken: String,
        query: [String: String]? = nil
    ) async throws -> T {
        let req = try request(path, method: "GET", uid: uid, accessToken: accessToken, query: query)
        return try await decode(T.self, request: req)
    }

    /// Authenticated POST with a JSON body (folder creation, trash/delete).
    func post<T: Decodable, B: Encodable & Sendable>(
        _ type: T.Type,
        path: String,
        uid: String,
        accessToken: String,
        body: B
    ) async throws -> T {
        let req = try request(path, method: "POST", uid: uid, accessToken: accessToken, body: body)
        return try await decode(T.self, request: req)
    }

    /// Authenticated PUT with a JSON body (revision commit).
    func put<T: Decodable, B: Encodable & Sendable>(
        _ type: T.Type,
        path: String,
        uid: String,
        accessToken: String,
        body: B
    ) async throws -> T {
        let req = try request(path, method: "PUT", uid: uid, accessToken: accessToken, body: body)
        return try await decode(T.self, request: req)
    }

    /// Raw encrypted-block POST to a runtime storage host (UploadLinks
    /// BareURL — never hardcoded). Single multipart part name "Block"
    /// filename "blob", token in the Pm-Storage-Token header (log parity).
    func uploadRawBlock(
        bareURL: String,
        token: String,
        uid: String,
        accessToken: String,
        body: Data,
        boundary: String
    ) async throws {
        let url = try Self.validatedStorageURL(bareURL)
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        req.setValue(token, forHTTPHeaderField: "Pm-Storage-Token")
        req.setValue(AppVersion.headerValue, forHTTPHeaderField: "x-pm-appversion")
        req.setValue(uid, forHTTPHeaderField: "x-pm-uid")
        req.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        req.httpBody = body
        let (data, response) = try await data(for: req)
        try Self.checkStorageResponse(response, data: data)
        let env = try JSONDecoder().decode(ProtonEnvelope.self, from: data)
        guard env.code == 1000 || env.code == 1001 else {
            throw ProtonAPIError.api(code: env.code, message: env.error ?? "storage upload failed")
        }
    }

    /// Raw encrypted-block GET from a runtime storage host (revision
    /// Blocks BareURL — never hardcoded; rclone-captured /tmp/f5ref:
    /// `GET /storage/blocks` on the storage host with the block Token in
    /// the Pm-Storage-Token header, Bearer + X-Pm-Uid auth, and the
    /// honest x-pm-appversion). Returns the raw encrypted SED tag-18 packet
    /// (octet-stream, NOT JSON — no envelope decoding here).
    func downloadRawBlock(
        bareURL: String,
        token: String,
        uid: String,
        accessToken: String
    ) async throws -> Data {
        let req = try blockDownloadRequest(bareURL: bareURL, token: token, uid: uid, accessToken: accessToken)
        let (data, response) = try await data(for: req)
        try Self.checkStorageResponse(response, data: data)
        return data
    }

    /// Same as downloadRawBlock but against a full block URL (the revision
    /// Block `URL` embeds the token in-path; the header token is still
    /// sent for parity).
    func downloadRawBlockURL(
        url: String,
        token: String,
        uid: String,
        accessToken: String
    ) async throws -> Data {
        let req = try blockDownloadURLRequest(url: url, token: token, uid: uid, accessToken: accessToken)
        let (data, response) = try await data(for: req)
        try Self.checkStorageResponse(response, data: data)
        return data
    }

    /// Builds the storage-host block GET for a BareURL. Header parity with
    /// ProtonDriveApps/sdk `StorageApiClient.GetBlobStreamAsync`
    /// (client/cs/src/Proton.Drive.Sdk/Api/Storage/StorageApiClient.cs):
    /// the SDK sends only `pm-storage-token`; we additionally send Bearer +
    /// x-pm-uid (upload parity) and the honest x-pm-appversion — never a
    /// foreign client string.
    func blockDownloadRequest(
        bareURL: String,
        token: String,
        uid: String,
        accessToken: String
    ) throws -> URLRequest {
        // BareURL has no path suffix in the capture (token selects the
        // blob); the full Block URL embeds the same JWT in-path and also
        // resolves. Prefer BareURL + header (upload parity).
        let url = try Self.validatedStorageURL(bareURL)
        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        req.setValue(token, forHTTPHeaderField: "Pm-Storage-Token")
        req.setValue(AppVersion.headerValue, forHTTPHeaderField: "x-pm-appversion")
        req.setValue(uid, forHTTPHeaderField: "x-pm-uid")
        req.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        return req
    }

    /// Builds the storage-host block GET for a full block URL (the token is
    /// embedded in-path; the header token is still sent for parity when
    /// non-empty). Same honest headers as `blockDownloadRequest`.
    func blockDownloadURLRequest(
        url: String,
        token: String,
        uid: String,
        accessToken: String
    ) throws -> URLRequest {
        let reqURL = try Self.validatedStorageURL(url)
        var req = URLRequest(url: reqURL)
        req.httpMethod = "GET"
        if !token.isEmpty {
            req.setValue(token, forHTTPHeaderField: "Pm-Storage-Token")
        }
        req.setValue(AppVersion.headerValue, forHTTPHeaderField: "x-pm-appversion")
        req.setValue(uid, forHTTPHeaderField: "x-pm-uid")
        req.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        return req
    }

    // MARK: - plumbing

    func decode<T: Decodable>(_ type: T.Type, request: URLRequest) async throws -> T {
        let (data, response) = try await data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw ProtonAPIError.transport(URLError(.badServerResponse))
        }
        if http.statusCode == 401 { throw ProtonAPIError.unauthorized }
        // Proton nests payloads; envelope check for human-verification / 2FA signals
        if let env = try? JSONDecoder().decode(ProtonEnvelope.self, from: data), env.code != 1000, env.code != 1001 {
            switch env.code {
            case 9001: throw ProtonAPIError.humanVerificationRequired
            case 2011, 2021: throw ProtonAPIError.needs2FA
            case 2028: throw ProtonAPIError.rateLimited
            default: throw ProtonAPIError.api(code: env.code, message: env.error ?? "unknown")
            }
        }
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            // surface nested API error if present, else the decoding error
            // WITH a raw body prefix (decode mysteries are otherwise opaque —
            // e.g. a commit response that carries Code 1000 in odd framing).
            // Credential-shaped fields are redacted: error strings surface
            // verbatim in the UI AND persist in the queue JSON — a malformed
            // auth envelope must never echo AccessToken/RefreshToken.
            let body = redactedBodyPrefix(data)
            if !(200..<300).contains(http.statusCode) {
                // Keep the HTTP status (retry classification needs it).
                let env = try? JSONDecoder().decode(ProtonEnvelope.self, from: data)
                throw ProtonAPIError.http(status: http.statusCode, code: env?.code,
                                          message: env?.error ?? "body=\(body)")
            }
            if let env = try? JSONDecoder().decode(ProtonEnvelope.self, from: data) {
                throw ProtonAPIError.api(code: env.code, message: "\(env.error ?? error.localizedDescription) body=\(body)")
            }
            throw ProtonAPIError.transport(DecodingError.dataCorrupted(
                DecodingError.Context(codingPath: [], debugDescription:
                    "\(error.localizedDescription) body=\(body)")))
        }
    }

    /// Storage-host status check: 2xx passes; 401 maps to `.unauthorized`
    /// (so `SessionManager.withAuth` refreshes once); any other status is
    /// surfaced as `.http` with the status preserved (plus the envelope
    /// Code/Error when the storage host returned one).
    static func checkStorageResponse(_ response: URLResponse, data: Data) throws {
        guard let http = response as? HTTPURLResponse else {
            throw ProtonAPIError.transport(URLError(.badServerResponse))
        }
        let status = http.statusCode
        if (200..<300).contains(status) { return }
        if status == 401 { throw ProtonAPIError.unauthorized }
        let env = try? JSONDecoder().decode(ProtonEnvelope.self, from: data)
        throw ProtonAPIError.http(status: status, code: env?.code,
                                  message: env?.error ?? "storage HTTP \(status)")
    }

    /// First 600 bytes of a response body for decode-error diagnostics, with
    /// credential-shaped JSON fields (`"AccessToken":"…"` etc.) redacted.
    private func redactedBodyPrefix(_ data: Data) -> String {
        let raw = String(data: data.prefix(600), encoding: .utf8) ?? "<binary>"
        return raw.replacingOccurrences(
            of: #""(AccessToken|RefreshToken|Token|UID|SessionID|Password|Passphrase|Secret|PrivateKey)"\s*:\s*"[^"]*""#,
            with: #""$1":"[redacted]""#,
            options: [.regularExpression, .caseInsensitive]
        )
    }

    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        do {
            return try await session.data(for: request)
        } catch {
            throw ProtonAPIError.transport(error)
        }
    }
}

/// Session delegate that allows an HTTP redirect only when it stays on the
/// original request's host over https (same port). Anything else — another
/// host, a downgrade to http, userinfo — is refused: URLSession then
/// completes with the 3xx response itself, which callers surface as
/// `.http(status:)`. Same-host is the strictest rule that covers both
/// policies: API requests stay on the API host, and a storage request
/// already passed `validatedStorageURL` for exactly that host.
final class RedirectGuard: NSObject, URLSessionTaskDelegate, Sendable {
    // Completion-handler form on purpose: the async overload's @objc thunk
    // crashes swift-frontend 6.4 under the app target's concurrency settings.
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        let origin = task.originalRequest?.url
        completionHandler(Self.allows(from: origin, to: request.url) ? request : nil)
    }

    static func allows(from origin: URL?, to target: URL?) -> Bool {
        guard let origin, let target,
              origin.scheme?.lowercased() == "https", target.scheme?.lowercased() == "https",
              target.user == nil, target.password == nil,
              let host = origin.host?.lowercased(), !host.isEmpty,
              target.host?.lowercased() == host,
              (origin.port ?? 443) == (target.port ?? 443)
        else { return false }
        return true
    }
}

// Response wrappers (Proton nests under capitalized keys in some endpoints)
struct AuthInfoResponse: Decodable, Sendable {
    var authInfo: AuthInfo
    // /auth/v4/info returns fields flat; be liberal:
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if let nested = try? c.nestedContainer(keyedBy: AuthInfo.CodingKeys.self, forKey: .authInfo) {
            authInfo = AuthInfo(
                version: try nested.decode(Int.self, forKey: .version),
                modulus: try nested.decode(String.self, forKey: .modulus),
                salt: try nested.decode(String.self, forKey: .salt),
                serverEphemeral: try nested.decode(String.self, forKey: .serverEphemeral),
                srpSession: try nested.decode(String.self, forKey: .srpSession)
            )
        } else {
            authInfo = try AuthInfo(from: decoder)
        }
    }
    enum CodingKeys: String, CodingKey { case authInfo = "AuthInfo" }
}

struct AuthResponse: Decodable, Sendable {
    var auth: ProtonAuth
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if (try? c.nestedContainer(keyedBy: ProtonAuth.CodingKeys.self, forKey: .auth)) != nil {
            auth = try c.decode(ProtonAuth.self, forKey: .auth)
        } else {
            auth = try ProtonAuth(from: decoder)
        }
    }
    enum CodingKeys: String, CodingKey { case auth = "Auth" }
}

/// Type-erase Encodable for generic request builder.
private struct AnyEncodable: Encodable {
    var base: any Encodable
    init(_ base: any Encodable & Sendable) { self.base = base }
    func encode(to encoder: Encoder) throws { try base.encode(to: encoder) }
}
