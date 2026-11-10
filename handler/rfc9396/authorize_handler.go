// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc9396

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
)

var _ fosite.AuthorizeEndpointValidationHandler = (*AuthorizeHandler)(nil)
var _ fosite.DeviceAuthorizeEndpointValidationHandler = (*AuthorizeHandler)(nil)
var _ fosite.AuthorizeEndpointHandler = (*AuthorizeHandler)(nil)

const (
	defaultMaximumPerRequest int   = 5
	defaultMaximumJSONSize   int64 = 2048
	defaultMaximumJSONDepth  int   = 5
)

// AuthorizeHandler validates the authorization_details provided in the request and updates
// the responder with the appropriate granted authorization_details.
type AuthorizeHandler struct {
	Config fosite.RFC9396ConfigProvider
}

// ValidateAuthorizeEndpointRequest validates and enriches an authorize endpoint request. This mirrors TokenEndpointHandler's
// HandleTokenEndpointRequest, which is used for the same purpose.
func (h *AuthorizeHandler) ValidateAuthorizeEndpointRequest(ctx context.Context, requester fosite.AuthorizeRequester) error {
	return validateAndEnrichRequester(ctx, requester.GetClient(), requester, h.Config)
}

// ValidateDeviceAuthorizeEndpointRequest validates and enriches an authorize endpoint request. This mirrors TokenEndpointHandler's
// HandleTokenEndpointRequest, which is used for the same purpose.
func (h *AuthorizeHandler) ValidateDeviceAuthorizeEndpointRequest(ctx context.Context, requester fosite.DeviceAuthorizeRequester) error {
	return validateAndEnrichRequester(ctx, requester.GetClient(), requester, h.Config)
}

func (h *AuthorizeHandler) HandleAuthorizeEndpointRequest(ctx context.Context, ar fosite.AuthorizeRequester, resp fosite.AuthorizeResponder) error {
	// check if the token is issued in the authorize endpoint response
	if !ar.GetResponseTypes().Has("token") {
		return nil
	}

	req, ok := ar.(fosite.RFC9396Requester)
	if !ok {
		return nil
	}

	// check if the client is configured correctly. This isn't actually needed because other handlers would cover this
	// but this has been added for completeness.
	if !ar.GetClient().GetGrantTypes().Has("implicit") {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant 'implicit'."))
	}

	// marshal the authorization details that are granted
	granted := fosite.SanitizeAuthorizationDetailTypes(req.GetGrantedAuthorizationDetails())
	if len(granted) > 0 {
		b, err := json.Marshal(granted)
		if err != nil {
			return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHint("Invalid authorization details value").WithWrap(err))
		}

		resp.AddParameter("authorization_details", string(b))
	}

	return nil
}

func validateAndEnrichRequester(ctx context.Context, c fosite.Client, requester fosite.Requester, config fosite.RFC9396ConfigProvider) error {
	param := requester.GetRequestForm().Get("authorization_details")
	if len(param) == 0 {
		return nil
	}

	// check requester type
	req, ok := requester.(fosite.RFC9396Requester)
	if !ok {
		return nil
	}

	limits := setDefaultLimits(config.GetAuthorizationDetailsLimits(ctx))

	ads, err := fosite.DecodeJSONArrayWithLimits(strings.NewReader(param), limits)
	if err != nil {
		if errors.Is(err, fosite.DecodeErrorMaxArrayElementsExceeded) {
			return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHintf(
				"Maximum %d authorization details are allowed in a request.", limits.MaxArrayElements))
		} else if errors.Is(err, fosite.DecodeErrorMaxSizePerObjectExceeded) {
			return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHintf(
				"Each authorization detail JSON should not exceed %d bytes.", limits.MaxSizePerObject))
		} else if errors.Is(err, fosite.DecodeErrorMaxDepthExceeded) {
			return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHintf(
				"Objects in authorization detail JSON should not be nested more than %d depth.", limits.MaxDepth))
		} else {
			return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHint("Invalid authorization_details value.").WithWrap(err))
		}
	}

	client, _ := c.(fosite.RFC9396Client)
	strategy := config.GetAuthorizationDetailsStrategy(ctx)
	typeHandlers := config.GetAuthorizationDetailTypeHandlers(ctx)
	for _, ad := range ads {
		t := fosite.RFC9396AuthorizationDetailsType(ad)

		adType := t.GetType()
		if len(adType) == 0 {
			return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHint("Missing 'type' in the authorization details object."))
		}

		// Find the type handler
		th, ok := typeHandlers[adType]
		if th == nil || !ok {
			th = config.GetDefaultAuthorizationDetailTypeHandler(ctx)
		}

		// Call validate - to check the JSON properties (may or may not base on JSON schema)
		if err := th.Validate(t); err != nil {
			return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHintf(
				"Authorization detail JSON of type '%s' does not conform to the expected schema.", adType))
		}

		// Calculate the ID early and set it into the authorization detail map
		if id, err := th.GetID(t); err == nil {
			t.SetID(id)
		}

		// Call Handle to perform any processing necessary
		if skip, err := th.Handle(ctx, requester, t); err != nil {
			return err
		} else if skip {
			// When skip, the authorization detail is not added to requested authorization detail
			continue
		}

		// Last, check against client configuration
		if strategy != nil && client != nil {
			if skip, err := strategy(client, adType); skip {
				continue // skip authorization detail type, do not process further
			} else if err != nil {
				return err
			}
		}

		req.AppendRequestedAuthorizationDetail(t)
	}

	return nil
}

// setDefaultLimits set the default JSON limits if the value is not set
func setDefaultLimits(limits *fosite.JSONLimits) *fosite.JSONLimits {
	if limits == nil {
		limits = &fosite.JSONLimits{}
	}
	if limits.MaxArrayElements <= 0 {
		limits.MaxArrayElements = defaultMaximumPerRequest
	}
	if limits.MaxSizePerObject <= 0 {
		limits.MaxSizePerObject = defaultMaximumJSONSize
	}
	if limits.MaxDepth <= 0 {
		limits.MaxDepth = defaultMaximumJSONDepth
	}
	return limits
}
