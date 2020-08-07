package model

func (x *Resource) HasScope(scope string) bool {
	if x.Scopes == nil || len(x.Scopes) == 0 {
		return false
	}

	for _, allowedScope := range x.Scopes {
		if scope == allowedScope {
			return true
		}
	}
	return false
}
func (x *Resource) HasAnyScopes(scopes []string) bool {
	if x.Scopes == nil || len(x.Scopes) == 0 {
		return false
	}

	for _, scope := range scopes {
		if x.HasScope(scope) {
			return true
		}
	}
	return false
}

func (x *Resource) HasIssuer(issuer string) bool {
	if x.Scopes == nil || len(x.Scopes) == 0 {
		return false
	}

	for _, allowedIssuer := range x.Issuers {
		if issuer == allowedIssuer {
			return true
		}
	}
	return false
}

func (x *Resource) HasAnyIssuers(issuers []string) bool {
	if x.Issuers == nil || len(x.Issuers) == 0 {
		return false
	}

	for _, issuer := range issuers {
		if x.HasIssuer(issuer) {
			return true
		}
	}
	return false
}
