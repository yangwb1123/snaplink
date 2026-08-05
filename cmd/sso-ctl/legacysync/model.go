package legacysync

import "time"

const (
	legacyProvider  = "sv_sso"
	activeAttr      = "scim:active"
	legacyRoleLabel = "legacy"
)

type legacyUser struct {
	LegacyID  string
	UUID      string
	LoginID   string
	Hash      string
	Name      string
	Email     string
	Avatar    string
	Gender    string
	Lang      string
	HomePath  string
	Status    int
	CreatedAt time.Time
	UpdatedAt time.Time
}

type legacyRole struct {
	AppCode     string
	ID          string
	ParentID    string
	Code        string
	Name        string
	Status      int
	Permissions []string
}

type legacyGrant struct {
	AppCode   string
	LoginID   string
	RoleID    string
	RoleRowID string
}

type legacyOverride struct {
	AppCode   string
	LoginID   string
	RoleRowID string
	ActionID  string
	Action    string
	MenuID    string
}

type legacyData struct {
	Users     []legacyUser
	Roles     []legacyRole
	Grants    []legacyGrant
	Overrides []legacyOverride
}

type plannedUser struct {
	ID         string
	ExternalID string
	Email      string
	Name       string
	Hash       string
	Attributes map[string]string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type plannedRole struct {
	ClientID    string
	Code        string
	Name        string
	Description string
	Permissions []string
}

type assignmentKey struct {
	UserID   string
	ClientID string
}

type syncPlan struct {
	Users           []plannedUser
	Roles           []plannedRole
	Assignments     map[assignmentKey][]string
	ManagedPrefixes map[string][]string
	MappedClients   map[string]struct{}
	UserIDs         map[string]string
	Source          sourceSummary
}

type sourceSummary struct {
	Users       int
	Active      int
	Inactive    int
	Roles       int
	Grants      int
	Overrides   int
	IgnoredApps int
}

type syncReport struct {
	Source          sourceSummary
	CreateUsers     int
	UpdateUsers     int
	DeactivateUsers int
	Credentials     int
	Roles           int
	Assignments     int
	Mode            string
}
