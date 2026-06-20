package permissions

// FilterMenuTree returns a copy of in pruned to only the items the
// supplied permission set grants visibility to. The original tree
// is left untouched. Used by every Provider implementation —
// extracted here so memory + sqlite + future backends share the
// same wire shape for the filtered tree.
//
// Rules (recursive, depth-first):
//   - An item with no Permission is always visible.
//   - An item with Permission is visible iff [Matches] returns true.
//   - Children are filtered first. An invisible item whose every
//     child was pruned is itself dropped (no empty branches in the
//     output).
//   - An invisible item with at least one surviving child is kept
//     as a "container" — operators want the parent's navigation
//     label even when the parent's own action is gated.
//   - Buttons are filtered per FilterButtons.
func FilterMenuTree(in MenuTree, perms []Permission) MenuTree {
	out := make(MenuTree, 0, len(in))
	for _, item := range in {
		var kept []MenuItem
		if len(item.Children) > 0 {
			kept = FilterMenuTree(item.Children, perms)
		}
		ownAllowed := item.Permission == "" || Matches(perms, item.Permission)
		if !ownAllowed && len(kept) == 0 {
			continue
		}
		out = append(out, MenuItem{
			ID:         item.ID,
			Name:       item.Name,
			Path:       item.Path,
			Icon:       item.Icon,
			Permission: item.Permission,
			Buttons:    FilterButtons(item.Buttons, perms),
			Children:   kept,
		})
	}
	return out
}

// FilterButtons returns a copy of in pruned to only the buttons
// the supplied permission set grants. Returns nil (not an empty
// slice) when no buttons survive — the response JSON omits the
// field entirely so clients don't have to handle "[]" vs missing.
func FilterButtons(in []Button, perms []Permission) []Button {
	if len(in) == 0 {
		return nil
	}
	out := make([]Button, 0, len(in))
	for _, b := range in {
		if b.Permission == "" || Matches(perms, b.Permission) {
			out = append(out, b)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
