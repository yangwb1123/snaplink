package adminuser

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// Deps is the interface the admin user CRUD service functions need.
// *sso.Server satisfies it via accessor methods. All methods are optional —
// nil-check before use — so the functions degrade gracefully when a backing
// store is not wired.
type Deps interface {
	UserProvider() core.UserProvider
	PasswordCredentialStore() core.PasswordCredentialStore
	Auditor() *audit.Recorder
	Logger() spi.Logger
	Metrics() *metrics.Metrics
	ActorFromContext(ctx context.Context) (userID, clientID string, ok bool)
}

// CreateUserRequest contains the fields required to create a new user.
type CreateUserRequest struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name,omitempty"`
	Password    string `json:"password"`
}

// UpdateUserRequest contains the modifiable user fields.
type UpdateUserRequest struct {
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

// UserResponse is the API response body for a single user.
// It deliberately excludes the password hash and any internal attributes.
type UserResponse struct {
	ID          string            `json:"id"`
	Username    string            `json:"username,omitempty"`
	Email       string            `json:"email,omitempty"`
	Name        string            `json:"name,omitempty"`
	DisplayName string            `json:"display_name,omitempty"`
	ExternalID  string            `json:"external_id,omitempty"`
	Provider    string            `json:"provider,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// PaginatedUsersResponse is the API response body for the list endpoint.
type PaginatedUsersResponse struct {
	Users []UserResponse `json:"users"`
	Total int            `json:"total"`
	Page  int            `json:"page"`
	Limit int            `json:"limit"`
}

// userToResponse converts a core.User to a safe API response body.
func userToResponse(u *core.User) UserResponse {
	if u == nil {
		return UserResponse{}
	}
	return UserResponse{
		ID:          u.ID,
		Username:    u.Username,
		Email:       u.Email,
		Name:        u.Name,
		DisplayName: u.DisplayName,
		ExternalID:  u.ExternalID,
		Provider:    u.Provider,
		Attributes:  u.Attributes,
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
	}
}

// mapUsersToResponse converts a slice of core.User to UserResponse slice.
func mapUsersToResponse(users []*core.User) []UserResponse {
	out := make([]UserResponse, 0, len(users))
	for _, u := range users {
		out = append(out, userToResponse(u))
	}
	return out
}

// resolveUserProvider type-asserts the UserProvider to find optional extensions.
func resolveUserProvider[T any](d Deps) (T, bool) {
	var zero T
	if d == nil || d.UserProvider() == nil {
		return zero, false
	}
	svc, ok := d.UserProvider().(T)
	return svc, ok
}

// checkUsernameUniqueness checks username availability via optional provider.
func checkUsernameUniqueness(ctx context.Context, deps Deps, username string) error {
	checker, ok := resolveUserProvider[core.UsernameCheckProvider](deps)
	if !ok {
		return nil
	}
	exists, err := checker.UsernameExists(ctx, username)
	if err != nil {
		deps.Logger().Error("adminuser: username check failed", "error", err)
		return err
	}
	if exists {
		return core.ErrUserExists
	}
	return nil
}

// checkEmailUniqueness checks email availability via optional provider.
func checkEmailUniqueness(ctx context.Context, deps Deps, email string) error {
	if email == "" {
		return nil
	}
	checker, ok := resolveUserProvider[core.EmailCheckProvider](deps)
	if !ok {
		return nil
	}
	exists, err := checker.EmailExists(ctx, email)
	if err != nil {
		deps.Logger().Error("adminuser: email check failed", "error", err)
		return err
	}
	if exists {
		return core.ErrUserExists
	}
	return nil
}

// createUserRecord persists the user and sets their password.
func createUserRecord(ctx context.Context, deps Deps, user *core.User, password string) error {
	if err := deps.UserProvider().CreateOrUpdate(ctx, user); err != nil {
		deps.Logger().Error("adminuser: create user failed", "error", err)
		return err
	}
	if deps.PasswordCredentialStore() != nil {
		if err := deps.PasswordCredentialStore().SetPassword(ctx, user.ID, password); err != nil {
			deps.Logger().Error("adminuser: set password failed, rolling back", "user_id", user.ID, "error", err)
			if rbErr := deps.UserProvider().Delete(ctx, user.ID); rbErr != nil {
				deps.Logger().Error("adminuser: rollback failed", "user_id", user.ID, "error", rbErr)
			}
			return err
		}
	}
	return nil
}

// CreateUser creates a new user with the given request. Returns the created
// user on success. On uniqueness conflict, returns core.ErrUserExists.
func CreateUser(ctx context.Context, deps Deps, req *CreateUserRequest) (*core.User, error) {
	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)
	req.DisplayName = strings.TrimSpace(req.DisplayName)

	if err := ValidateUsername(req.Username); err != nil {
		return nil, err
	}
	if err := ValidateEmail(req.Email); err != nil {
		return nil, err
	}
	if err := ValidatePassword(req.Password); err != nil {
		return nil, err
	}
	if err := checkUsernameUniqueness(ctx, deps, req.Username); err != nil {
		return nil, err
	}
	if err := checkEmailUniqueness(ctx, deps, req.Email); err != nil {
		return nil, err
	}

	user := &core.User{
		ID:          newUserID(),
		Username:    req.Username,
		Email:       req.Email,
		DisplayName: req.DisplayName,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := createUserRecord(ctx, deps, user, req.Password); err != nil {
		return nil, err
	}
	return user, nil
}

// GetUser retrieves a user by ID. Returns core.ErrNoSuchUser when not found.
func GetUser(ctx context.Context, deps Deps, userID string) (*UserResponse, error) {
	if userID == "" {
		return nil, errors.New("adminuser: user ID is required")
	}
	u, err := deps.UserProvider().GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	resp := userToResponse(u)
	return &resp, nil
}

// applyEmailChange updates the email field if changed, with uniqueness check.
func applyEmailChange(ctx context.Context, deps Deps, u *core.User, newEmail string) (bool, error) {
	newEmail = strings.TrimSpace(newEmail)
	if newEmail == u.Email {
		return false, nil
	}
	if err := ValidateEmail(newEmail); err != nil {
		return false, err
	}
	if err := checkEmailUniqueness(ctx, deps, newEmail); err != nil {
		return false, err
	}
	u.Email = newEmail
	return true, nil
}

// UpdateUser updates a user's mutable fields (email, display_name).
// Username and password are NOT modifiable through this path.
func UpdateUser(ctx context.Context, deps Deps, userID string, req *UpdateUserRequest) (*UserResponse, error) {
	if userID == "" {
		return nil, errors.New("adminuser: user ID is required")
	}
	u, err := deps.UserProvider().GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	changed := false
	if req.Email != "" {
		changed, err = applyEmailChange(ctx, deps, u, req.Email)
		if err != nil {
			return nil, err
		}
	}
	if req.DisplayName != "" {
		dn := strings.TrimSpace(req.DisplayName)
		if dn != u.DisplayName {
			u.DisplayName = dn
			changed = true
		}
	}
	if !changed {
		resp := userToResponse(u)
		return &resp, nil
	}
	u.UpdatedAt = time.Now().UTC()
	if err := deps.UserProvider().CreateOrUpdate(ctx, u); err != nil {
		deps.Logger().Error("adminuser: update user failed", "user_id", userID, "error", err)
		return nil, err
	}
	resp := userToResponse(u)
	return &resp, nil
}

// DeleteUser deletes a user by ID. Missing users return nil (idempotent).
func DeleteUser(ctx context.Context, deps Deps, userID string) error {
	if userID == "" {
		return errors.New("adminuser: user ID is required")
	}
	if err := deps.UserProvider().Delete(ctx, userID); err != nil {
		deps.Logger().Error("adminuser: delete user failed", "user_id", userID, "error", err)
		return err
	}
	deleteUserPasswordCredential(ctx, deps, userID)
	return nil
}

// deleteUserPasswordCredential best-effort removes userID's password
// credential when the wired PasswordCredentialStore supports it (the
// OPTIONAL core.PasswordCredentialDeleter extension). The user row is
// already gone by the time this runs, so a missing extension or a store
// error here must never fail the delete request — it only means the
// credential hash is left behind, orphaned and unreachable (the userID it
// was keyed on no longer resolves to a user).
func deleteUserPasswordCredential(ctx context.Context, deps Deps, userID string) {
	store := deps.PasswordCredentialStore()
	if store == nil {
		return
	}
	deleter, ok := store.(core.PasswordCredentialDeleter)
	if !ok {
		return
	}
	if err := deleter.DeletePassword(ctx, userID); err != nil {
		deps.Logger().Error("adminuser: delete password credential failed", "user_id", userID, "error", err)
	}
}

// fetchPaginatedUsers uses the pagination provider when available, else falls
// back to listing all users and slicing client-side.
func fetchPaginatedUsers(ctx context.Context, deps Deps, offset, limit int) ([]*core.User, int, error) {
	if lister, ok := resolveUserProvider[core.UserPaginationProvider](deps); ok {
		return lister.ListPaginated(ctx, offset, limit)
	}
	all, err := deps.UserProvider().List(ctx)
	if err != nil {
		return nil, 0, err
	}
	total := len(all)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return all[offset:end], total, nil
}

// ListUsers returns a paginated list of users. Page is 1-indexed; limit is
// clamped to [1, 100].
func ListUsers(ctx context.Context, deps Deps, page, limit int) (*PaginatedUsersResponse, error) {
	if page < 1 {
		page = 1
	}
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	offset := (page - 1) * limit

	users, total, err := fetchPaginatedUsers(ctx, deps, offset, limit)
	if err != nil {
		deps.Logger().Error("adminuser: list users failed", "error", err)
		return nil, err
	}
	if users == nil {
		users = []*core.User{}
	}
	return &PaginatedUsersResponse{
		Users: mapUsersToResponse(users),
		Total: total,
		Page:  page,
		Limit: limit,
	}, nil
}

// newUserID generates a unique user ID using a UUID v4 string.
func newUserID() string {
	return audit.NewEventID()
}
