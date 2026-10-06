import Foundation

/// A normalized Snaplink HTTP request.
///
/// This is the shape the cross-language transport contract compares: two SDKs
/// building the same call must produce byte-identical requests, so header names
/// are canonicalized, form keys are ordered, and a JSON body carries no
/// trailing newline.
public struct SnaplinkHTTPRequest: Sendable, Equatable {
    public enum Body: Sendable, Equatable {
        case form([String: String])
        case json(Data)
    }

    public let method: String
    public let url: URL
    public let headers: [String: String]
    public let body: Body?

    /// Header names that must never be logged or echoed, matched
    /// case-insensitively.
    public static let sensitiveHeaderNames: Set<String> = [
        "authorization", "dpop", "proxy-authorization", "cookie", "set-cookie"
    ]

    /// Form fields whose values are credentials and must never be logged.
    public static let sensitiveFormFields: Set<String> = [
        "code", "code_verifier", "client_secret", "refresh_token", "password",
        "license_key", "invitation_code", "activation_ticket", "assertion"
    ]

    public init(
        method: String,
        url: URL,
        headers: [String: String] = [:],
        body: Body? = nil
    ) throws {
        self.method = method.uppercased()
        self.url = url
        self.headers = Self.canonicalize(headers)
        self.body = try Self.normalize(body)
    }

    /// The query fields, decoded. Query order is not significant for behaviour
    /// but is preserved for byte-comparable output.
    public var queryFields: [String: String] {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return [:] }
        var fields: [String: String] = [:]
        for item in components.queryItems ?? [] {
            fields[item.name] = item.value ?? ""
        }
        return fields
    }

    /// The decoded form fields, or nil for a non-form body.
    public var formFields: [String: String]? {
        guard case .form(let fields) = body else { return nil }
        return fields
    }

    /// The decoded JSON object, or nil for a non-JSON body.
    public var jsonFields: [String: String]? {
        guard case .json(let data) = body else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: String]
    }

    /// A stable, byte-comparable rendering.
    ///
    /// Deliberately includes only the request line, sorted headers, and the body
    /// bytes: two SDKs agree on this string or they disagree about the call.
    public var canonical: String {
        var lines = ["\(method) \(url.absoluteString)"]
        for name in headers.keys.sorted() {
            lines.append("\(name): \(headers[name]!)")
        }
        lines.append("")
        switch body {
        case .form(let fields): lines.append(Self.encodeForm(fields))
        case .json(let data): lines.append(String(decoding: data, as: UTF8.self))
        case nil: break
        }
        return lines.joined(separator: "\n")
    }

    /// A rendering safe to put in a log: header values and credential form
    /// fields are redacted, and nothing else is.
    public var redactedDescription: String {
        var lines = ["\(method) \(url.absoluteString)"]
        for name in headers.keys.sorted() {
            let redacted = Self.sensitiveHeaderNames.contains(name.lowercased()) ? "<redacted>" : headers[name]!
            lines.append("\(name): \(redacted)")
        }
        switch body {
        case .form(let fields):
            let redacted = fields
                .map { Self.sensitiveFormFields.contains($0.key.lowercased()) ? ($0.key, "<redacted>") : $0 }
                .sorted { $0.0 < $1.0 }
            lines.append(contentsOf: redacted.map { "\($0.0)=\($0.1)" })
        case .json:
            lines.append("<redacted json body>")
        case nil:
            break
        }
        return lines.joined(separator: "\n")
    }

    /// Percent-encodes an OAuth form body with deterministic key ordering.
    ///
    /// `+` is escaped before spaces are folded, so a literal plus in a code or
    /// verifier survives the round trip.
    public static func encodeForm(_ fields: [String: String]) -> String {
        var components = URLComponents()
        components.queryItems = fields.keys.sorted().map { URLQueryItem(name: $0, value: fields[$0] ?? "") }
        return (components.percentEncodedQuery ?? "")
            .replacingOccurrences(of: "+", with: "%2B")
            .replacingOccurrences(of: "%20", with: "+")
    }

    /// Canonical header names: a fixed casing, applied case-insensitively so two
    /// SDKs that spell a header differently still agree.
    private static func canonicalize(_ headers: [String: String]) -> [String: String] {
        var canonical: [String: String] = [:]
        for (name, value) in headers {
            canonical[canonicalName(name)] = value
        }
        return canonical
    }

    private static func canonicalName(_ name: String) -> String {
        let lowercased = name.lowercased()
        for known in [
            "Accept", "Authorization", "Cache-Control", "Content-Type", "Pragma"
        ] where known.lowercased() == lowercased {
            return known
        }
        return name
    }

    private static func normalize(_ body: Body?) throws -> Body? {
        switch body {
        case .none, .form:
            return body
        case .json(let data):
            // A JSON body is UTF-8 with no trailing newline; anything else is a
            // caller bug rather than something to silently repair on the wire.
            guard String(data: data, encoding: .utf8) != nil else {
                throw SnaplinkAuthError(code: "invalid_request", message: "the request body is not valid UTF-8")
            }
            guard data.last != UInt8(ascii: "\n") else {
                throw SnaplinkAuthError(code: "invalid_request", message: "the JSON body must not end with a newline")
            }
            return .json(data)
        }
    }
}

/// A normalized Snaplink HTTP response.
public struct SnaplinkHTTPResponse: Sendable, Equatable {
    public let status: Int
    public let headers: [String: String]
    public let body: Data

    public init(status: Int, headers: [String: String] = [:], body: Data = Data()) {
        self.status = status
        self.headers = headers
        self.body = body
    }

    public var isSuccess: Bool { (200..<300).contains(status) }
}

/// Builds Snaplink requests: a pure function of its inputs, performing no I/O,
/// so redirect and endpoint construction is testable without a transport.
public enum SnaplinkRequestBuilder {
    /// Joins a path onto the issuer base URL without I/O.
    public static func endpoint(baseURL: URL, path: String) -> URL {
        var url = baseURL
        for component in path.split(separator: "/") {
            url.appendPathComponent(String(component))
        }
        return url
    }

    /// A credential-endpoint request: form body, no-store, no cookies.
    ///
    /// `Cache-Control: no-store` is applied here rather than per call site so a
    /// credential cannot be issued with a cacheable request by omission.
    public static func credentialForm(
        baseURL: URL,
        path: String,
        fields: [String: String],
        basicAuthorization: String? = nil
    ) throws -> SnaplinkHTTPRequest {
        var headers = noStoreHeaders
        headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
        if let basicAuthorization {
            headers["Authorization"] = basicAuthorization
        }
        return try SnaplinkHTTPRequest(
            method: "POST",
            url: endpoint(baseURL: baseURL, path: path),
            headers: headers,
            body: .form(fields)
        )
    }

    /// A JSON request, optionally authenticated with a bearer token.
    public static func json(
        method: String,
        baseURL: URL,
        path: String,
        query: [URLQueryItem] = [],
        fields: [String: String] = [:],
        bearer: String? = nil
    ) throws -> SnaplinkHTTPRequest {
        var url = endpoint(baseURL: baseURL, path: path)
        if !query.isEmpty {
            guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
                throw SnaplinkAuthError(code: "invalid_request", message: "could not construct the request URL")
            }
            components.queryItems = query
            guard let resolved = components.url else {
                throw SnaplinkAuthError(code: "invalid_request", message: "could not construct the request URL")
            }
            url = resolved
        }
        var headers = noStoreHeaders
        headers["Content-Type"] = "application/json"
        if let bearer, !bearer.isEmpty {
            headers["Authorization"] = "Bearer \(bearer)"
        }
        let body: SnaplinkHTTPRequest.Body? = fields.isEmpty && method == "GET"
            ? nil
            : .json(try encodeJSON(fields))
        return try SnaplinkHTTPRequest(method: method, url: url, headers: headers, body: body)
    }

    /// A bearer-authenticated read with no request body.
    public static func bearerRead(
        baseURL: URL,
        path: String,
        query: [URLQueryItem] = [],
        bearer: String
    ) throws -> SnaplinkHTTPRequest {
        var headers: [String: String] = ["Accept": "application/json"]
        if !bearer.isEmpty { headers["Authorization"] = "Bearer \(bearer)" }
        headers.merge(noStoreHeaders) { _, new in new }
        return try SnaplinkHTTPRequest(
            method: "GET",
            url: endpoint(baseURL: baseURL, path: path),
            headers: headers
        )
    }

    public static let noStoreHeaders: [String: String] = [
        "Accept": "application/json",
        "Cache-Control": "no-store",
        "Pragma": "no-cache"
    ]

    private static func encodeJSON(_ fields: [String: String]) throws -> Data {
        do {
            // sortedKeys keeps the body byte-identical across runs and SDKs.
            return try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
        } catch {
            throw SnaplinkAuthError(code: "invalid_request", message: "could not encode the request body")
        }
    }
}
