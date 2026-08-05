package legacysync

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var loginIDPattern = regexp.MustCompile(`^[A-Za-z0-9_]{3,50}$`)

func buildPlan(data legacyData, appMap, roleMap, userMap map[string]string) (syncPlan, error) {
	plan := syncPlan{
		Assignments:     map[assignmentKey][]string{},
		ManagedPrefixes: map[string][]string{},
		MappedClients:   map[string]struct{}{},
		UserIDs:         map[string]string{},
		Source:          sourceSummary{Users: len(data.Users)},
	}
	if err := planUsers(&plan, data.Users, userMap); err != nil {
		return syncPlan{}, err
	}
	roleByID := map[string]plannedRole{}
	for _, role := range data.Roles {
		clientID := appMap[role.AppCode]
		if clientID == "" || role.Status != 1 {
			plan.Source.IgnoredApps++
			continue
		}
		planned := makePlannedRole(role, clientID)
		plan.Roles = append(plan.Roles, planned)
		roleByID[role.AppCode+":"+role.ID] = planned
		plan.Source.Roles++
		addManagedPrefix(&plan, clientID, managedPrefix(role.AppCode))
	}
	if err := planGrants(&plan, data.Grants, roleByID, roleMap); err != nil {
		return syncPlan{}, err
	}
	if err := planOverrides(&plan, data.Overrides, appMap); err != nil {
		return syncPlan{}, err
	}
	for app, clientID := range appMap {
		plan.MappedClients[clientID] = struct{}{}
		addManagedPrefix(&plan, clientID, managedPrefix(app))
	}
	sortPlan(&plan)
	return plan, nil
}

func planUsers(plan *syncPlan, users []legacyUser, userMap map[string]string) error {
	seen := map[string]struct{}{}
	for _, u := range users {
		targetID := u.LoginID
		if mapped := userMap[u.LoginID]; mapped != "" {
			targetID = mapped
		}
		folded := strings.ToLower(targetID)
		if !loginIDPattern.MatchString(targetID) {
			return fmt.Errorf("legacy login_id does not meet Snaplink constraints")
		}
		if _, ok := seen[folded]; ok {
			return fmt.Errorf("legacy login_id is not case-insensitively unique")
		}
		seen[folded] = struct{}{}
		if _, err := bcrypt.Cost([]byte(u.Hash)); err != nil {
			return fmt.Errorf("legacy user %s has an invalid bcrypt hash", u.LegacyID)
		}
		attrs := legacyUserAttributes(u)
		if targetID != u.LoginID {
			attrs["sv_sso:login_id"] = u.LoginID
		}
		plan.UserIDs[u.LoginID] = targetID
		plan.Users = append(plan.Users, plannedUser{ID: targetID, ExternalID: u.UUID,
			Email: u.Email, Name: u.Name, Hash: u.Hash, Attributes: attrs,
			CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt})
		if u.Status == 1 {
			plan.Source.Active++
		} else {
			plan.Source.Inactive++
		}
	}
	return validateUserMap(plan.UserIDs, userMap)
}

func validateUserMap(planned, configured map[string]string) error {
	for source := range configured {
		if planned[source] == "" {
			return fmt.Errorf("--user-map references unknown legacy login_id %q", source)
		}
	}
	return nil
}

func legacyUserAttributes(u legacyUser) map[string]string {
	attrs := map[string]string{
		"sv_sso:legacy_id": u.LegacyID,
		"sv_sso:gender":    u.Gender,
		"sv_sso:lang":      u.Lang,
		activeAttr:         fmt.Sprint(u.Status == 1),
	}
	setNonEmpty(attrs, "sv_sso:avatar", u.Avatar)
	setNonEmpty(attrs, "sv_sso:home_path", u.HomePath)
	return attrs
}

func makePlannedRole(role legacyRole, clientID string) plannedRole {
	description := "Imported from sv_auth role " + role.ID
	if role.ParentID != "0" {
		description += "; parent=" + role.ParentID
	}
	return plannedRole{ClientID: clientID, Code: legacyRoleCode(role.AppCode, role.Code),
		Name: role.Name, Description: description, Permissions: uniqueSorted(role.Permissions)}
}

func planGrants(plan *syncPlan, grants []legacyGrant, roles map[string]plannedRole, roleMap map[string]string) error {
	for _, grant := range grants {
		role, ok := roles[grant.AppCode+":"+grant.RoleID]
		if !ok {
			continue
		}
		userID := plan.UserIDs[grant.LoginID]
		if userID == "" {
			return fmt.Errorf("legacy grant references unknown user %q", grant.LoginID)
		}
		key := assignmentKey{UserID: userID, ClientID: role.ClientID}
		plan.Assignments[key] = append(plan.Assignments[key], role.Code)
		if mapped := roleMap[grant.AppCode+":"+sourceRoleCode(role.Code)]; mapped != "" {
			plan.Assignments[key] = append(plan.Assignments[key], mapped)
		}
		plan.Source.Grants++
	}
	return nil
}

func planOverrides(plan *syncPlan, overrides []legacyOverride, appMap map[string]string) error {
	byCode := map[string]int{}
	for _, override := range overrides {
		clientID := appMap[override.AppCode]
		if clientID == "" {
			continue
		}
		code := managedPrefix(override.AppCode) + "override:" + override.RoleRowID
		permission := overridePermission(override)
		if index, ok := byCode[clientID+":"+code]; ok {
			plan.Roles[index].Permissions = uniqueSorted(append(plan.Roles[index].Permissions, permission))
		} else {
			byCode[clientID+":"+code] = len(plan.Roles)
			plan.Roles = append(plan.Roles, plannedRole{ClientID: clientID, Code: code,
				Name: "Legacy user action override", Description: "Imported from sv_auth role_user " + override.RoleRowID,
				Permissions: []string{permission}})
		}
		userID := plan.UserIDs[override.LoginID]
		if userID == "" {
			return fmt.Errorf("legacy override references unknown user %q", override.LoginID)
		}
		key := assignmentKey{UserID: userID, ClientID: clientID}
		plan.Assignments[key] = append(plan.Assignments[key], code)
		plan.Source.Overrides++
	}
	return nil
}

func sortPlan(plan *syncPlan) {
	sort.Slice(plan.Users, func(i, j int) bool { return plan.Users[i].ID < plan.Users[j].ID })
	sort.Slice(plan.Roles, func(i, j int) bool {
		return plan.Roles[i].ClientID+plan.Roles[i].Code < plan.Roles[j].ClientID+plan.Roles[j].Code
	})
	for key, roles := range plan.Assignments {
		plan.Assignments[key] = uniqueSorted(roles)
	}
	for clientID, prefixes := range plan.ManagedPrefixes {
		plan.ManagedPrefixes[clientID] = uniqueSorted(prefixes)
	}
}

func addManagedPrefix(plan *syncPlan, clientID, prefix string) {
	if !slices.Contains(plan.ManagedPrefixes[clientID], prefix) {
		plan.ManagedPrefixes[clientID] = append(plan.ManagedPrefixes[clientID], prefix)
	}
}

func managedPrefix(app string) string        { return legacyRoleLabel + ":" + app + ":" }
func legacyRoleCode(app, role string) string { return managedPrefix(app) + role }

func sourceRoleCode(planned string) string {
	parts := strings.SplitN(planned, ":", 3)
	if len(parts) != 3 {
		return planned
	}
	return parts[2]
}

func menuPermission(menuID, action string) string {
	return "legacy:menu:" + menuID + ":" + action
}

func overridePermission(override legacyOverride) string {
	if override.MenuID != "" {
		return menuPermission(override.MenuID, strings.ToLower(override.Action))
	}
	return "legacy:action:" + override.ActionID + ":" + strings.ToLower(override.Action)
}

func uniqueSorted(values []string) []string {
	slices.Sort(values)
	return slices.Compact(values)
}

func setNonEmpty(attrs map[string]string, key, value string) {
	if value != "" {
		attrs[key] = value
	}
}
