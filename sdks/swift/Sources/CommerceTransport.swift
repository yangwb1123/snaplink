import Foundation

/// A prepared one-time activation, returned by the activation endpoint.
public struct SnaplinkActivationPreparation: Sendable, Equatable {
    public let ticket: String
    public let productID: String
    public let expiresIn: TimeInterval

    public init(ticket: String, productID: String, expiresIn: TimeInterval) {
        self.ticket = ticket
        self.productID = productID
        self.expiresIn = expiresIn
    }
}

/// Server-derived product, tenant, entitlement, and quota information.
///
/// Clients cannot submit or override these fields.
public struct SnaplinkAccountContext: Decodable, Sendable, Equatable {
    public let productID: String
    public let tenantID: String
    public let entitlement: SnaplinkEntitlement?

    public init(productID: String, tenantID: String, entitlement: SnaplinkEntitlement?) {
        self.productID = productID
        self.tenantID = tenantID
        self.entitlement = entitlement
    }

    /// Classifies the context's entitlement, treating an absent one as
    /// not-activated.
    ///
    /// This is the single entry point the shared entitlement contract expects:
    /// a context with no entitlement and a context whose entitlement is
    /// unusable are different states, and both are reachable without the
    /// caller branching on `nil` first.
    public func licenseState(at now: Date) -> SnaplinkLicenseState {
        entitlement?.state(at: now) ?? SnaplinkLicenseState(kind: .notActivated)
    }

    private enum CodingKeys: String, CodingKey {
        case productID = "product_id"
        case tenantID = "tenant_id"
        case entitlement
    }
}

/// A paid-product or invitation activation prepared before hosted login.
///
/// The credential is sent only in the HTTPS request body of
/// ``SnaplinkAuthClient/setup(_:)``; the login transaction carries just the
/// short-lived ticket, which is claimed with the bearer after the code
/// exchange. Never place a license key or invitation code in a URL or in OAuth
/// `state`.
public struct SnaplinkSetupOptions: Sendable {
    public let productID: String
    public let licenseKey: String?
    public let invitationCode: String?
    public let tenantHint: String?
    public let locale: String?
    public let appVersion: String?

    public init(
        productID: String,
        licenseKey: String? = nil,
        invitationCode: String? = nil,
        tenantHint: String? = nil,
        locale: String? = nil,
        appVersion: String? = nil
    ) {
        self.productID = productID
        self.licenseKey = licenseKey
        self.invitationCode = invitationCode
        self.tenantHint = tenantHint
        self.locale = locale
        self.appVersion = appVersion
    }
}

struct SnaplinkActivationPrepareRequest: Sendable {
    let clientID: String
    let productID: String
    let licenseKey: String?
    let invitationCode: String?
    let tenantHint: String?
    let locale: String?
    let appVersion: String?

    /// Flattened JSON fields, omitting absent optionals so the request never
    /// carries an empty credential field the server would read as a real one.
    var jsonFields: [String: String] {
        var fields = ["client_id": clientID, "product_id": productID]
        for (name, value) in [
            ("license_key", licenseKey),
            ("invitation_code", invitationCode),
            ("tenant_hint", tenantHint),
            ("locale", locale),
            ("app_version", appVersion)
        ] {
            if let value, !value.isEmpty { fields[name] = value }
        }
        return fields
    }
}

struct SnaplinkActivationClaimRequest: Sendable {
    let ticket: String
    let productID: String

    var jsonFields: [String: String] {
        ["activation_ticket": ticket, "product_id": productID]
    }
}

struct SnaplinkActivationContextResponse: Decodable {
    let context: SnaplinkAccountContext
}

struct SnaplinkActivationPrepareResponse: Decodable {
    let activationTicket: String
    let productID: String
    let expiresIn: Int64

    enum CodingKeys: String, CodingKey {
        case activationTicket = "activation_ticket"
        case productID = "product_id"
        case expiresIn = "expires_in"
    }
}

private struct SnaplinkPreferenceUpdateResponse: Decodable {
    let status: String
}

protocol SnaplinkCommerceTransport: Sendable {
    func prepareActivation(
        _ request: SnaplinkActivationPrepareRequest
    ) async throws -> SnaplinkActivationPreparation
    func claimActivation(
        ticket: String,
        productID: String,
        bearer: String
    ) async throws -> SnaplinkAccountContext
    func accountContext(
        productID: String,
        bearer: String
    ) async throws -> SnaplinkAccountContext
    func myPreferences(bearer: String) async throws -> Data
    func putMyPreferences(_ body: [String: String], bearer: String) async throws
}

struct URLSessionCommerceTransport: SnaplinkCommerceTransport {
    private let configuration: SnaplinkConfiguration
    private let sender: SnaplinkHTTPSender

    init(configuration: SnaplinkConfiguration, session: URLSession? = nil) {
        self.configuration = configuration
        self.sender = SnaplinkHTTPSender(session: session)
    }

    func prepareActivation(
        _ request: SnaplinkActivationPrepareRequest
    ) async throws -> SnaplinkActivationPreparation {
        // The credential travels only in this JSON body: it must never reach an
        // authorization URL, OAuth state, or SDK storage.
        let data = try await sender.send(try jsonRequest(
            method: "POST",
            path: "api/v1/activation/prepare",
            fields: request.jsonFields
        ))
        let response = try decode(SnaplinkActivationPrepareResponse.self, from: data)
        let ticket = response.activationTicket.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !ticket.isEmpty, response.productID == request.productID, response.expiresIn > 0 else {
            throw SnaplinkAuthError(
                code: "invalid_response",
                message: "the activation endpoint returned an invalid ticket"
            )
        }
        return SnaplinkActivationPreparation(
            ticket: ticket,
            productID: response.productID,
            expiresIn: TimeInterval(response.expiresIn)
        )
    }

    func claimActivation(
        ticket: String,
        productID: String,
        bearer: String
    ) async throws -> SnaplinkAccountContext {
        let fields = SnaplinkActivationClaimRequest(ticket: ticket, productID: productID).jsonFields
        let data = try await sender.send(try jsonRequest(
            method: "POST",
            path: "api/v1/me/activation/claim",
            fields: fields,
            bearer: bearer
        ))
        return try decodeContext(data)
    }

    func accountContext(
        productID: String,
        bearer: String
    ) async throws -> SnaplinkAccountContext {
        let request = try SnaplinkRequestBuilder.json(
            method: "GET",
            baseURL: configuration.issuerBaseURL,
            path: "api/v1/me/account-context",
            query: [URLQueryItem(name: "product_id", value: productID)],
            bearer: bearer
        )
        return try decodeContext(try await sender.send(request))
    }

    /// Reads the caller's allowlisted presentation preferences. The response is
    /// a default-deny projection, so the raw document is handed back for the
    /// codec that owns the wire keys rather than decoded into a private type.
    func myPreferences(bearer: String) async throws -> Data {
        let request = try SnaplinkRequestBuilder.bearerRead(
            baseURL: configuration.issuerBaseURL,
            path: "me/preferences",
            bearer: bearer
        )
        return try await sender.send(request)
    }

    /// Merges allowlisted preferences. An empty object is an accepted no-op, so
    /// only a transport-level failure is reported.
    func putMyPreferences(_ body: [String: String], bearer: String) async throws {
        let data = try await sender.send(try jsonRequest(
            method: "PUT",
            path: "me/preferences",
            fields: body,
            bearer: bearer
        ))
        let response = try decode(SnaplinkPreferenceUpdateResponse.self, from: data)
        guard response.status == Self.updateStatus else {
            throw SnaplinkAuthError(
                code: "invalid_response",
                message: "Snaplink returned an unexpected preferences update status"
            )
        }
    }

    private func jsonRequest(
        method: String,
        path: String,
        fields: [String: String],
        bearer: String? = nil
    ) throws -> SnaplinkHTTPRequest {
        try SnaplinkRequestBuilder.json(
            method: method,
            baseURL: configuration.issuerBaseURL,
            path: path,
            fields: fields,
            bearer: bearer
        )
    }

    private func decodeContext(_ data: Data) throws -> SnaplinkAccountContext {
        let context = try decode(SnaplinkActivationContextResponse.self, from: data).context
        guard !context.productID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !context.tenantID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw SnaplinkAuthError(
                code: "invalid_response",
                message: "Snaplink returned an incomplete account context"
            )
        }
        return context
    }

    private func decode<Value: Decodable>(_ type: Value.Type, from data: Data) throws -> Value {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw SnaplinkAuthError(
                code: "invalid_response",
                message: "Snaplink returned a malformed activation response"
            )
        }
    }

    private static let updateStatus = "ok"
}
