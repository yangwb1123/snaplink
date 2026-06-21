package federation

import "github.com/snaplink/sso/domains/federation/metadatapolicy"

// rpMetadataType is the metadata type whose policy the resolver applies. Slice
// 2 resolves RPs, so only openid_relying_party is enforced; other types (e.g.
// openid_provider) are carried but not applied here.
const rpMetadataType = "openid_relying_party"

// applyPolicy merges the metadata_policy from every Subordinate Statement in
// the chain (top-down) and applies the merged openid_relying_party policy to
// the leaf's RP metadata, returning the policy-applied metadata. A merge
// conflict or a leaf-metadata violation returns an error (the resolver maps it
// to ErrTrustChainInvalid).
//
// links is the canonical leaf-first chain: links[0] = leaf config, links[len-1]
// = anchor config; links[1..len-2] are the Subordinate Statements SS_1..SS_n
// (SS_1 just above the leaf, SS_n just below the anchor). To merge TOP-DOWN we
// walk the SS from the anchor end (SS_n) toward the leaf (SS_1): the highest
// authority's policy seeds the merge, lower ones combine in.
func (r *TrustChainResolver) applyPolicy(links []chainLink) (map[string]any, error) {
	// Collect Subordinate Statement policies in TOP-DOWN order (anchor-most
	// first). i runs len-2 (SS_n, just below the anchor config) down to 1 (SS_1,
	// just above the leaf config), so the first appended is the anchor-most
	// policy → top-down. The iss==sub guard is a defensive backstop (the
	// canonical chain has no self-signed link in this range).
	var policies []map[string]map[string]any
	for i := len(links) - 2; i >= 1; i-- {
		l := links[i]
		if l.claims.Iss == l.claims.Sub {
			continue
		}
		if pol, ok := l.claims.MetadataPolicy[rpMetadataType]; ok && len(pol) > 0 {
			policies = append(policies, pol)
		}
	}

	merged, err := metadatapolicy.MergePolicies(policies)
	if err != nil {
		return nil, err
	}

	// The leaf RP metadata (a copy so we never mutate the parsed statement).
	leaf := links[0]
	var rp map[string]any
	if leaf.claims.Metadata != nil && leaf.claims.Metadata.RP != nil {
		rp = metadatapolicy.CloneMetadata(leaf.claims.Metadata.RP)
	} else {
		rp = map[string]any{}
	}

	if err := metadatapolicy.EnforcePolicy(merged, rp); err != nil {
		return nil, err
	}
	if len(rp) == 0 {
		return nil, nil
	}
	return rp, nil
}
