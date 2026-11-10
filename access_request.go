// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

type AccessRequest struct {
	GrantTypes       Arguments `json:"grantTypes" gorethink:"grantTypes"`
	HandledGrantType Arguments `json:"handledGrantType" gorethink:"handledGrantType"`

	Request
}

func NewAccessRequest(session Session) *AccessRequest {
	r := &AccessRequest{
		GrantTypes:       Arguments{},
		HandledGrantType: Arguments{},
		Request:          *NewRequest(),
	}
	r.Session = session
	return r
}

func (a *AccessRequest) GetGrantTypes() Arguments {
	return a.GrantTypes
}

func (a *AccessRequest) SetGrantedScopes(scopes Arguments) {
	a.GrantedScope = scopes
}

func (a *AccessRequest) SetGrantedAuthorizationDetails(types []RFC9396AuthorizationDetailsType) {
	a.GrantedAuthorizationDetails = types
}

func (a *AccessRequest) SanitizeRestoreRefreshTokenOriginalRequester(requester Requester) Requester {
	r := a.Sanitize(nil).(*Request)

	ar := &AccessRequest{
		Request: *r,
	}

	ar.SetID(requester.GetID())

	ar.SetRequestedScopes(requester.GetRequestedScopes())
	ar.SetGrantedScopes(requester.GetGrantedScopes())

	if rfc9396Requester, ok := requester.(RFC9396Requester); ok {
		ar.SetGrantedAuthorizationDetails(rfc9396Requester.GetGrantedAuthorizationDetails())
		ar.SetRequestedAuthorizationDetails(rfc9396Requester.GetRequestedAuthorizationDetails())
	}

	return ar
}
