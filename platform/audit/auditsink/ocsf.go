package auditsink

import (
	"encoding/json"
	"io"

	"github.com/yangwb1123/snaplink/platform/audit/auditspi"
)

// ocsfSchemaVersion is the OCSF schema version this formatter's class/
// activity mapping targets (https://schema.ocsf.io/1.1.0/).
const ocsfSchemaVersion = "1.1.0"

const (
	ocsfVendorName  = "Snaplink"
	ocsfProductName = "SSO"
)

// OCSF category_uid values from the public OCSF categories catalog.
// ocsfCategoryUnmapped is an SDK-local placeholder (0), used only by the
// generic fallback below.
const (
	ocsfCategoryIAM         = 3 // Identity & Access Management
	ocsfCategoryAppActivity = 6 // Application Activity
	ocsfCategoryUnmapped    = 0
)

// OCSF class_uid values. AccountChange/Authentication/AuthorizeSession/
// APIActivity are real classes from the public OCSF catalog.
// ocsfClassPlatformEvent and ocsfClassUnmapped are SDK-local extensions
// (outside the standard catalog's numeric range) for event types — bootstrap,
// snapshot, release, signing-key, CAEP/SSF, cluster lifecycle — that have no
// canonical OCSF System Activity subclass.
const (
	ocsfClassAccountChange    = 3001
	ocsfClassAuthentication   = 3002
	ocsfClassAuthorizeSession = 3003
	ocsfClassAPIActivity      = 6003
	ocsfClassPlatformEvent    = 100001
	ocsfClassUnmapped         = 100000
)

// ocsfActivity is one EventType's OCSF classification: which class/category
// it belongs to and which activity within that class it represents.
// activityID follows the real OCSF enum for a class where one exists
// (Authentication: 1=Logon, 2=Logoff; Account Change: 1=Create, 4=Password
// Reset, 6=Delete, 7=Attach Policy, 8=Detach Policy, 9=Add Group, 10=Remove
// Group, 12=Unlock; API Activity: 1=Create, 2=Read, 4=Delete); 99=Other
// covers everything without a closer real-enum fit, with activityName
// carrying the specific meaning OCSF's coarse numeric enum can't.
type ocsfActivity struct {
	classUID     int
	categoryUID  int
	activityID   int
	activityName string
}

// ocsfGenericActivity is the safe fallback for any EventType not in
// ocsfEventActivities — including custom/future types — so FormatOCSF never
// emits a zero-value class_uid/category_uid for an unrecognized type.
var ocsfGenericActivity = ocsfActivity{
	classUID: ocsfClassUnmapped, categoryUID: ocsfCategoryUnmapped, activityID: 99, activityName: "Other",
}

// ocsfEventActivities curates the OCSF classification for every EventType
// this SDK's own emitters produce, grouped to mirror auditspi/event_types*.go.
// The conformance test in platform/audit/siem_conformance_test.go asserts
// every const currently defined has an explicit entry here.
var ocsfEventActivities = map[auditspi.EventType]ocsfActivity{
	// core auth + token lifecycle
	auditspi.EventLogin:           {ocsfClassAuthentication, ocsfCategoryIAM, 1, "Logon"},
	auditspi.EventLoginFailure:    {ocsfClassAuthentication, ocsfCategoryIAM, 1, "Logon"},
	auditspi.EventLogout:          {ocsfClassAuthentication, ocsfCategoryIAM, 2, "Logoff"},
	auditspi.EventTokenIssued:     {ocsfClassAuthentication, ocsfCategoryIAM, 99, "Token Issued"},
	auditspi.EventTokenRevoked:    {ocsfClassAuthentication, ocsfCategoryIAM, 99, "Token Revoked"},
	auditspi.EventCodeSent:        {ocsfClassAuthentication, ocsfCategoryIAM, 99, "Verification Code Sent"},
	auditspi.EventCallbackFailure: {ocsfClassAuthentication, ocsfCategoryIAM, 99, "OAuth Callback Failure"},
	auditspi.EventClientAccess:    {ocsfClassAPIActivity, ocsfCategoryAppActivity, 2, "Read"},
	auditspi.EventPermissionQuery: {ocsfClassAPIActivity, ocsfCategoryAppActivity, 2, "Read"},
	auditspi.EventPermissionCheck: {ocsfClassAPIActivity, ocsfCategoryAppActivity, 3, "Authorize"},
	// DCR
	auditspi.EventClientRegistered: {ocsfClassAccountChange, ocsfCategoryIAM, 1, "Create"},
	auditspi.EventClientUpdated:    {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Update"},
	auditspi.EventClientDeleted:    {ocsfClassAccountChange, ocsfCategoryIAM, 6, "Delete"},
	// network policy
	auditspi.EventNetPolicyApply:  {ocsfClassAPIActivity, ocsfCategoryAppActivity, 1, "Create"},
	auditspi.EventNetPolicyDelete: {ocsfClassAPIActivity, ocsfCategoryAppActivity, 4, "Delete"},
	// back-channel logout + partial revoke
	auditspi.EventLogoutNotified:       {ocsfClassAuthentication, ocsfCategoryIAM, 2, "Logoff"},
	auditspi.EventPartialRevokeFailure: {ocsfClassAuthentication, ocsfCategoryIAM, 99, "Partial Token Revoke Failure"},
	// tenant + lockout
	auditspi.EventTenantTokensRevoked:   {ocsfClassAuthentication, ocsfCategoryIAM, 99, "Tenant Tokens Revoked"},
	auditspi.EventTenantSessionsRevoked: {ocsfClassAuthentication, ocsfCategoryIAM, 99, "Tenant Sessions Revoked"},
	auditspi.EventAccountLocked:         {ocsfClassAccountChange, ocsfCategoryIAM, 5, "Disable"},
	// MFA + anomaly
	auditspi.EventMFARequired:     {ocsfClassAuthentication, ocsfCategoryIAM, 99, "MFA Challenge"},
	auditspi.EventMFASuccess:      {ocsfClassAuthentication, ocsfCategoryIAM, 99, "MFA Success"},
	auditspi.EventMFAFailure:      {ocsfClassAuthentication, ocsfCategoryIAM, 99, "MFA Failure"},
	auditspi.EventAnomalyDetected: {ocsfClassAuthentication, ocsfCategoryIAM, 99, "Anomaly Detected"},
	// webauthn
	auditspi.EventWebAuthnRegistered:        {ocsfClassAccountChange, ocsfCategoryIAM, 1, "Create"},
	auditspi.EventWebAuthnAttestationDenied: {ocsfClassAuthentication, ocsfCategoryIAM, 99, "WebAuthn Attestation Denied"},
	// password reset + TOTP enroll
	auditspi.EventPasswordResetRequested:   {ocsfClassAccountChange, ocsfCategoryIAM, 4, "Password Reset"},
	auditspi.EventPasswordResetCompleted:   {ocsfClassAccountChange, ocsfCategoryIAM, 4, "Password Reset"},
	auditspi.EventPasswordResetFailed:      {ocsfClassAccountChange, ocsfCategoryIAM, 4, "Password Reset"},
	auditspi.EventPasswordChanged:          {ocsfClassAccountChange, ocsfCategoryIAM, 2, "Password Change"},
	auditspi.EventTOTPEnrolled:             {ocsfClassAccountChange, ocsfCategoryIAM, 1, "Create"},
	auditspi.EventTOTPEnrollFailed:         {ocsfClassAccountChange, ocsfCategoryIAM, 99, "TOTP Enrollment Failed"},
	auditspi.EventRecoveryCodesRegenerated: {ocsfClassAccountChange, ocsfCategoryIAM, 99, "MFA Recovery Codes Regenerated"},
	// consent (Authorize Session)
	auditspi.EventConsentGranted: {ocsfClassAuthorizeSession, ocsfCategoryIAM, 1, "Grant"},
	auditspi.EventConsentRevoked: {ocsfClassAuthorizeSession, ocsfCategoryIAM, 2, "Revoke"},
	auditspi.EventConsentDenied:  {ocsfClassAuthorizeSession, ocsfCategoryIAM, 99, "Deny"},
	// self-service + email change
	auditspi.EventSelfRegistered:       {ocsfClassAccountChange, ocsfCategoryIAM, 1, "Create"},
	auditspi.EventSubjectDataExported:  {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Subject Data Exported"},
	auditspi.EventSubjectSelfErased:    {ocsfClassAccountChange, ocsfCategoryIAM, 6, "Delete"},
	auditspi.EventEmailChangeRequested: {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Email Change Requested"},
	auditspi.EventEmailChanged:         {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Update"},
	// org membership
	auditspi.EventOrgLeft:                  {ocsfClassAccountChange, ocsfCategoryIAM, 10, "Remove Group"},
	auditspi.EventOrgMemberAutoProvisioned: {ocsfClassAccountChange, ocsfCategoryIAM, 9, "Add Group"},
	auditspi.EventInvitationSent:           {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Invitation Sent"},
	auditspi.EventInvitationAccepted:       {ocsfClassAccountChange, ocsfCategoryIAM, 9, "Add Group"},
	auditspi.EventInvitationRevoked:        {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Invitation Revoked"},
	// credential health + SPIFFE + FAPI
	auditspi.EventPasswordWeak:            {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Weak Password Detected"},
	auditspi.EventPasswordCompromised:     {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Compromised Password Detected"},
	auditspi.EventSPIFFEJWTSVIDAccepted:   {ocsfClassAuthentication, ocsfCategoryIAM, 99, "SPIFFE JWT-SVID Accepted"},
	auditspi.EventFAPIComplianceViolation: {ocsfClassAuthentication, ocsfCategoryIAM, 99, "FAPI Compliance Violation"},
	// refresh rotation + token lifecycle
	auditspi.EventRefreshTokenReuse:               {ocsfClassAuthentication, ocsfCategoryIAM, 99, "Refresh Token Reuse Detected"},
	auditspi.EventRefreshRotationVelocityExceeded: {ocsfClassAuthentication, ocsfCategoryIAM, 99, "Refresh Rotation Velocity Exceeded"},
	auditspi.EventRefreshTokenIssued:              {ocsfClassAuthentication, ocsfCategoryIAM, 99, "Refresh Token Issued"},
	auditspi.EventIDTokenIssued:                   {ocsfClassAuthentication, ocsfCategoryIAM, 99, "ID Token Issued"},
	auditspi.EventDeviceCodeIssued:                {ocsfClassAuthentication, ocsfCategoryIAM, 99, "Device Code Issued"},
	auditspi.EventDeviceCodeApproved:              {ocsfClassAuthentication, ocsfCategoryIAM, 99, "Device Code Approved"},
	auditspi.EventDeviceCodeDenied:                {ocsfClassAuthentication, ocsfCategoryIAM, 99, "Device Code Denied"},
	// CIBA + native SSO
	auditspi.EventCIBAAuthRequest:          {ocsfClassAuthentication, ocsfCategoryIAM, 99, "CIBA Authentication Request"},
	auditspi.EventCIBAApproved:             {ocsfClassAuthentication, ocsfCategoryIAM, 99, "CIBA Approved"},
	auditspi.EventCIBADenied:               {ocsfClassAuthentication, ocsfCategoryIAM, 99, "CIBA Denied"},
	auditspi.EventCIBAPingFailed:           {ocsfClassAuthentication, ocsfCategoryIAM, 99, "CIBA Ping Failed"},
	auditspi.EventNativeSSOExchange:        {ocsfClassAuthentication, ocsfCategoryIAM, 99, "Native SSO Exchange"},
	auditspi.EventNativeSSOExchangeFailure: {ocsfClassAuthentication, ocsfCategoryIAM, 99, "Native SSO Exchange Failure"},
	// admin control-plane (event_types_admin.go)
	auditspi.EventAdminClientCreated:              {ocsfClassAccountChange, ocsfCategoryIAM, 1, "Create"},
	auditspi.EventAdminClientUpdated:              {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Update"},
	auditspi.EventAdminClientDeleted:              {ocsfClassAccountChange, ocsfCategoryIAM, 6, "Delete"},
	auditspi.EventAdminClientSecretRotated:        {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Client Secret Rotated"},
	auditspi.EventAdminClientApproved:             {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Client Approved"},
	auditspi.EventAdminClientRejected:             {ocsfClassAccountChange, ocsfCategoryIAM, 6, "Client Rejected"},
	auditspi.EventAdminUserCreated:                {ocsfClassAccountChange, ocsfCategoryIAM, 1, "Create"},
	auditspi.EventAdminUserUpdated:                {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Update"},
	auditspi.EventAdminUserDeleted:                {ocsfClassAccountChange, ocsfCategoryIAM, 6, "Delete"},
	auditspi.EventAdminTokenRevoked:               {ocsfClassAuthentication, ocsfCategoryIAM, 99, "Admin Token Revoked"},
	auditspi.EventAdminTempTokenIssued:            {ocsfClassAuthentication, ocsfCategoryIAM, 99, "Admin Temp Token Issued"},
	auditspi.EventAdminConsentRevoked:             {ocsfClassAuthorizeSession, ocsfCategoryIAM, 2, "Revoke"},
	auditspi.EventAdminMFAFactorRemoved:           {ocsfClassAccountChange, ocsfCategoryIAM, 6, "Delete"},
	auditspi.EventAdminRecoveryCodesReset:         {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Admin Recovery Codes Reset"},
	auditspi.EventAdminPasswordReset:              {ocsfClassAccountChange, ocsfCategoryIAM, 4, "Password Reset"},
	auditspi.EventAdminDeviceSecretsRevoked:       {ocsfClassAuthentication, ocsfCategoryIAM, 99, "Admin Device Secrets Revoked"},
	auditspi.EventAdminPasswordResetTokensRevoked: {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Password Reset Tokens Revoked"},
	auditspi.EventAdminEmailChangeTokensRevoked:   {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Email Change Tokens Revoked"},
	auditspi.EventAdminUserEmailChanged:           {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Update"},
	auditspi.EventAdminAccountUnlocked:            {ocsfClassAccountChange, ocsfCategoryIAM, 12, "Unlock"},
	auditspi.EventAdminConnectionUpserted:         {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Update"},
	auditspi.EventAdminConnectionDeleted:          {ocsfClassAccountChange, ocsfCategoryIAM, 6, "Delete"},
	auditspi.EventAdminTenantMemberAdded:          {ocsfClassAccountChange, ocsfCategoryIAM, 9, "Add Group"},
	auditspi.EventAdminTenantMemberRemoved:        {ocsfClassAccountChange, ocsfCategoryIAM, 10, "Remove Group"},
	auditspi.EventAdminRoleAdded:                  {ocsfClassAccountChange, ocsfCategoryIAM, 1, "Create"},
	auditspi.EventAdminRoleUpdated:                {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Update"},
	auditspi.EventAdminRoleRemoved:                {ocsfClassAccountChange, ocsfCategoryIAM, 6, "Delete"},
	auditspi.EventAdminRoleAssigned:               {ocsfClassAccountChange, ocsfCategoryIAM, 7, "Attach Policy"},
	auditspi.EventAdminRoleUnassigned:             {ocsfClassAccountChange, ocsfCategoryIAM, 8, "Detach Policy"},
	auditspi.EventAdminMenusUpdated:               {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Menus Updated"},
	auditspi.EventAdminResourceRegistered:         {ocsfClassAccountChange, ocsfCategoryIAM, 1, "Resource Registered"},
	auditspi.EventAdminResourceRemoved:            {ocsfClassAccountChange, ocsfCategoryIAM, 2, "Resource Removed"},
	auditspi.EventAdminTenantCreated:              {ocsfClassAccountChange, ocsfCategoryIAM, 1, "Create"},
	auditspi.EventAdminTenantUpdated:              {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Update"},
	auditspi.EventAdminTenantDeleted:              {ocsfClassAccountChange, ocsfCategoryIAM, 6, "Delete"},
	auditspi.EventAdminTenantStatusChanged:        {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Tenant Status Changed"},
	auditspi.EventAdminDomainCreated:              {ocsfClassAccountChange, ocsfCategoryIAM, 1, "Create"},
	auditspi.EventAdminDomainUpdated:              {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Update"},
	auditspi.EventAdminDomainDeleted:              {ocsfClassAccountChange, ocsfCategoryIAM, 6, "Delete"},
	auditspi.EventAdminSubjectExported:            {ocsfClassAccountChange, ocsfCategoryIAM, 99, "Admin Subject Exported"},
	auditspi.EventAdminSubjectErased:              {ocsfClassAccountChange, ocsfCategoryIAM, 6, "Delete"},
	auditspi.EventAdminGRPCCalled:                 {ocsfClassAPIActivity, ocsfCategoryAppActivity, 99, "gRPC Call"},
	// system / platform (event_types_system.go) — SDK-local class, see
	// ocsfClassPlatformEvent doc.
	auditspi.EventBootstrapStepApplied:           {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 1, "Bootstrap Step Applied"},
	auditspi.EventBootstrapStepSkipped:           {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 2, "Bootstrap Step Skipped"},
	auditspi.EventBootstrapStepFailed:            {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 3, "Bootstrap Step Failed"},
	auditspi.EventBootstrapLockAcquired:          {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 1, "Bootstrap Lock Acquired"},
	auditspi.EventBootstrapLockReleased:          {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 2, "Bootstrap Lock Released"},
	auditspi.EventBootstrapLockLost:              {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 3, "Bootstrap Lock Lost"},
	auditspi.EventBootstrapLockContended:         {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 99, "Bootstrap Lock Contended"},
	auditspi.EventSnapshotExported:               {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 1, "Snapshot Exported"},
	auditspi.EventSnapshotRestored:               {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 2, "Snapshot Restored"},
	auditspi.EventSnapshotDeleted:                {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 99, "Snapshot Deleted"},
	auditspi.EventReleaseRegistered:              {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 1, "Release Registered"},
	auditspi.EventReleasePinned:                  {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 1, "Release Pinned"},
	auditspi.EventReleaseRolledBack:              {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 2, "Release Rolled Back"},
	auditspi.EventReleaseDeleted:                 {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 99, "Release Deleted"},
	auditspi.EventSigningKeyRotated:              {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 1, "Signing Key Rotated"},
	auditspi.EventSigningKeyAggregationDegraded:  {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 3, "Signing Key Aggregation Degraded"},
	auditspi.EventSigningKeyAggregationRecovered: {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 2, "Signing Key Aggregation Recovered"},
	auditspi.EventSigningKeyRotationCoordinated:  {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 1, "Signing Key Rotation Coordinated"},
	auditspi.EventSigningKeyAdoptionErrorsTotal:  {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 3, "Signing Key Adoption Errors"},
	auditspi.EventCAEPSetSent:                    {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 1, "CAEP SET Sent"},
	auditspi.EventSSFSetReceived:                 {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 1, "SSF SET Received"},
	auditspi.EventInvalidationBusDegraded:        {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 3, "Invalidation Bus Degraded"},
	auditspi.EventInvalidationBusReconnected:     {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 2, "Invalidation Bus Reconnected"},
	auditspi.EventTenantQuotaStoreFailure:        {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 3, "Tenant Quota Store Failure"},
	auditspi.EventClientSecretExpiring:           {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 3, "Client Secret Expiring"},
	auditspi.EventAuditChainCheckpoint:           {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 3, "Audit Chain Checkpoint"},
	auditspi.EventTenantQuotaProjectionApplied:   {ocsfClassPlatformEvent, ocsfCategoryUnmapped, 1, "Tenant Quota Projection Applied"},
}

// ocsfActivityFor returns t's curated classification, or ocsfGenericActivity
// for any type absent from ocsfEventActivities.
func ocsfActivityFor(t auditspi.EventType) ocsfActivity {
	if a, ok := ocsfEventActivities[t]; ok {
		return a
	}
	return ocsfGenericActivity
}

var ocsfSeverityNames = map[int]string{
	1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical", 6: "Fatal",
}

// ocsfStatus projects Outcome onto OCSF's status_id/status pair
// (1=Success, 2=Failure — this SDK never needs 0=Unknown or 99=Other since
// every Event carries an explicit Outcome).
func ocsfStatus(o auditspi.Outcome) (id int, name string) {
	if o == auditspi.OutcomeFailure {
		return 2, "Failure"
	}
	return 1, "Success"
}

type ocsfEvent struct {
	ActivityID   int               `json:"activity_id"`
	ActivityName string            `json:"activity_name"`
	CategoryUID  int               `json:"category_uid"`
	ClassUID     int               `json:"class_uid"`
	TypeUID      int               `json:"type_uid"`
	SeverityID   int               `json:"severity_id"`
	Severity     string            `json:"severity"`
	StatusID     int               `json:"status_id"`
	Status       string            `json:"status"`
	Time         int64             `json:"time"`
	Message      string            `json:"message,omitempty"`
	Metadata     ocsfMetadata      `json:"metadata"`
	Actor        *ocsfActor        `json:"actor,omitempty"`
	SrcEndpoint  *ocsfEndpoint     `json:"src_endpoint,omitempty"`
	Unmapped     map[string]string `json:"unmapped,omitempty"`
}

type ocsfMetadata struct {
	Version string      `json:"version"`
	Product ocsfProduct `json:"product"`
	UID     string      `json:"uid,omitempty"`
}

type ocsfProduct struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
}

type ocsfActor struct {
	User ocsfUser `json:"user"`
}

type ocsfUser struct {
	UID string `json:"uid,omitempty"`
}

type ocsfEndpoint struct {
	IP string `json:"ip,omitempty"`
}

// ocsfUnmapped carries Event fields with no dedicated OCSF slot into the
// schema's "unmapped" escape hatch, plus every Metadata entry prefixed
// "meta." so it can't collide with a named field added here later.
// encoding/json sorts map[string]string keys alphabetically on Marshal, so
// output is deterministic without an explicit sort step.
func ocsfUnmapped(e *auditspi.Event) map[string]string {
	m := map[string]string{}
	set := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	set("tenant_id", e.TenantID)
	set("client_id", e.ClientID)
	set("session_id", e.SessionID)
	set("request_id", e.RequestID)
	set("trace_id", e.TraceID)
	set("token_id", e.TokenID)
	set("provider", e.Provider)
	set("token_strategy", e.TokenStrategy)
	set("server_version", e.ServerVersion)
	for k, v := range e.Metadata {
		set("meta."+k, v)
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// FormatOCSF returns a Formatter emitting one OCSF JSON object per Event
// (WriterSink appends the trailing '\n', i.e. NDJSON framing). Required
// OCSF envelope fields (activity_id/class_uid/category_uid/type_uid/
// severity_id/status_id/time/metadata) are always populated; ActorID/
// ActorIP populate the optional actor/src_endpoint objects only when
// present. The returned closure is a pure, transport-independent []byte
// encoder — roadmap item 19 (Kafka/NATS) reuses it unchanged.
func FormatOCSF() Formatter {
	return func(e *auditspi.Event) ([]byte, error) {
		act := ocsfActivityFor(e.Type)
		sevID := toOCSFSeverityID(eventSeverity(e))
		statusID, status := ocsfStatus(e.Outcome)
		out := ocsfEvent{
			ActivityID: act.activityID, ActivityName: act.activityName,
			CategoryUID: act.categoryUID, ClassUID: act.classUID,
			TypeUID:    act.classUID*100 + act.activityID,
			SeverityID: sevID, Severity: ocsfSeverityNames[sevID],
			StatusID: statusID, Status: status,
			Time: e.Timestamp.UnixMilli(), Message: e.Reason,
			Metadata: ocsfMetadata{
				Version: ocsfSchemaVersion,
				Product: ocsfProduct{Name: ocsfProductName, VendorName: ocsfVendorName},
				UID:     e.ID,
			},
			Unmapped: ocsfUnmapped(e),
		}
		if e.ActorID != "" {
			out.Actor = &ocsfActor{User: ocsfUser{UID: e.ActorID}}
		}
		if e.ActorIP != "" {
			out.SrcEndpoint = &ocsfEndpoint{IP: e.ActorIP}
		}
		return json.Marshal(out)
	}
}

// NewOCSFSink is a thin WriterSink constructor pairing FormatOCSF with a
// concrete output target.
func NewOCSFSink(w io.Writer) *WriterSink {
	return NewWriterSink(w, WithWriterFormat(FormatOCSF()))
}
