// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc9396

import (
	"context"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
)

var _ fosite.TokenEndpointHandler = (*TokenResponseHandler)(nil)

type TokenResponseHandler struct {
	Config fosite.RFC9396ConfigProvider
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-4.1.3 (everything) and
// https://tools.ietf.org/html/rfc7523#section-2.1 (everything)
func (h *TokenResponseHandler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	return nil
}

func (h *TokenResponseHandler) PopulateTokenEndpointResponse(ctx context.Context, request fosite.AccessRequester, response fosite.AccessResponder) error {
	if !h.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	req, ok := request.(fosite.RFC9396Requester)
	if !ok {
		return nil
	}

	// marshal the authorization details that are granted
	granted := fosite.SanitizeAuthorizationDetailTypes(req.GetGrantedAuthorizationDetails())
	if len(granted) > 0 {
		response.SetExtra("authorization_details", granted)
	}

	return nil
}

func (h *TokenResponseHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	// different handlers manage the client auth requirement
	return true
}

func (h *TokenResponseHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	// this handler is for all grant types
	return true
}
