package model

const (
	RoleReader = "reader"
	RoleWriter = "writer"
	RoleAdmin  = "admin"

	PermissionRead  = "read"
	PermissionWrite = "write"
	PermissionAdmin = "admin"
)

var rolePermissions = map[string][]string{
	RoleReader: {PermissionRead},
	RoleWriter: {PermissionRead, PermissionWrite},
	RoleAdmin:  {PermissionRead, PermissionWrite, PermissionAdmin},
}

// RolePermissions returns the bridge-side permission set for a grant role.
func RolePermissions(role string) ([]string, bool) {
	perms, ok := rolePermissions[role]
	if !ok {
		return nil, false
	}
	return append([]string(nil), perms...), true
}

func IsKnownRole(role string) bool {
	_, ok := rolePermissions[role]
	return ok
}

func RoleAllows(role, action string) bool {
	perms, ok := RolePermissions(role)
	if !ok {
		return false
	}
	for _, perm := range perms {
		if perm == action {
			return true
		}
	}
	return false
}

// TokenPermissionsForRole returns permissions safe to emit in Lore authz JWTs.
// Bridge admin is intentionally not mapped to Lore's "admin" permission.
func TokenPermissionsForRole(role string) ([]string, bool) {
	if role == RoleAdmin {
		return []string{PermissionRead, PermissionWrite}, true
	}
	return RolePermissions(role)
}
