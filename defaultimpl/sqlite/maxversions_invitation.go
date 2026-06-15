package sqlite

// InvitationsMaxVersion returns the highest migration version declared for the
// invitations store (org-membership invitation tokens). ensureSchema-backed, so
// there is exactly one migration (v1 = the baseline CREATE TABLE block).
func InvitationsMaxVersion() int { return 1 }
