// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc9396

import (
	"context"
	"encoding/json"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
)

var _ fosite.AuthorizeEndpointValidationHandler = (*AuthorizeHandler)(nil)
var _ fosite.DeviceAuthorizeEndpointValidationHandler = (*AuthorizeHandler)(nil)
var _ fosite.AuthorizeEndpointHandler = (*AuthorizeHandler)(nil)

const (
	defaultMaximumPerRequest int = 5
	defaultMaximumJSONSize   int = 2048
	defaultMaximumJSONDepth  int = 5
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

	// deserialize the authorization details
	ads := []fosite.RFC9396AuthorizationDetailsType{}
	if err := json.Unmarshal([]byte(param), &ads); err != nil {
		return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHint("Invalid 'authorization_details' value.").WithWrap(err))
	}

	ignoreUnknownAuthorizationDetailsType := config.GetIgnoreUnknownAuthorizationDetailsType(ctx)
	restrictAuthorizationDetailsType := config.ShouldRestrictAuthorizationDetailsType(ctx)
	limits := setDefaultLimits(config.GetAuthorizationDetailsLimits(ctx))

	// Check maximum authorization detail JSON per request
	if len(ads) > limits.MaximumPerRequest {
		return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHintf(
			"Maximum %d authorization details are allowed in a request.", limits.MaximumPerRequest))
	}

	client, _ := c.(fosite.RFC9396Client)
	strategy := config.GetAuthorizationDetailsStrategy(ctx)
	typeHandlers := config.GetAuthorizationDetailTypeHandlers(ctx)
	for _, ad := range ads {

		adType := ad.GetType()
		if len(adType) == 0 {
			return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHint("Missing 'type' in the authorization details object."))
		}

		// Check the limits
		var data interface{}
		if b, err := ad.MarshalJSON(); err != nil { // This should not happen for proper JSON
			return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHint("Invalid 'authorization_details' value.").WithWrap(err))
		} else if len(b) > limits.MaximumJSONSize {
			return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHintf(
				"Each authorization detail JSON should not exceed %d bytes.", limits.MaximumJSONSize))
		} else if err := json.Unmarshal(b, &data); err != nil { // This should not happen for proper JSON
			return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHint("Invalid 'authorization_details' value.").WithWrap(err))
		} else if depth := findMaxDepth(data); depth > limits.MaximumJSONDepth {
			return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHintf(
				"Objects in authorization detail JSON should not be nested more than %d depth.", limits.MaximumJSONDepth))
		}

		// Find the type handler
		th, ok := typeHandlers[adType]
		if th == nil || !ok {
			th = config.GetDefaultAuthorizationDetailTypeHandler(ctx)
		}

		// Call validate - to check the JSON properties (probably based on JSON schema)
		if err := th.Validate(ad); err != nil {
			return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHintf(
				"Authorization detail JSON of type '%s' does not conform to the expected schema.", adType))
		}

		// Calculate the ID early and set it into the authorization detail map
		if id, err := th.GetID(ad); err == nil {
			ad.SetID(id)
		}

		// Call Handle to perform any processing necessary
		if skip, err := th.Handle(ctx, requester, ad); err != nil {
			return err
		} else if skip {
			// When skip, the authorization detail is not added to requested authorization detail
			continue
		}

		if restrictAuthorizationDetailsType {

			if strategy != nil && client != nil && !strategy(client.GetAuthorizationDetailTypes(), adType) {
				if ignoreUnknownAuthorizationDetailsType {
					continue
				}
				// if not ignoring unknown type, throw error
				return errorsx.WithStack(fosite.ErrInvalidAuthorizationDetails.WithHintf(
					"Request for authorization detail of type '%s' is not allowed.", adType))
			}

		}

		req.AppendRequestedAuthorizationDetail(ad)
	}

	return nil
}

// setDefaultLimits set the default limits if the value is not set
func setDefaultLimits(limits *fosite.RFC9396AuthorizationDetailsLimits) *fosite.RFC9396AuthorizationDetailsLimits {
	if limits == nil {
		limits = &fosite.RFC9396AuthorizationDetailsLimits{}
	}
	if limits.MaximumPerRequest <= 0 {
		limits.MaximumPerRequest = defaultMaximumPerRequest
	}
	if limits.MaximumJSONSize <= 0 {
		limits.MaximumJSONSize = defaultMaximumJSONSize
	}
	if limits.MaximumJSONDepth <= 0 {
		limits.MaximumJSONDepth = defaultMaximumJSONDepth
	}
	return limits
}

// findMaxDepth recursively calculates the maximum nesting depth of an arbitrary 'any'.
func findMaxDepth(data any) int {
	switch v := data.(type) {
	case map[string]any:
		depth := 0
		for _, value := range v { // find depth of each value
			childDepth := findMaxDepth(value)
			if childDepth > depth {
				depth = childDepth
			}
		}
		return depth + 1
	case []any:
		depth := 0
		for _, value := range v { // find depth of each value
			childDepth := findMaxDepth(value)
			if childDepth > depth {
				depth = childDepth
			}
		}
		return depth + 1
	default:
		return 0 // Non-structured types (string, int, bool, etc.) have a depth of 0
	}
}
