// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc9396_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/rfc9396"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	limits = &fosite.JSONLimits{
		MaxDepth:         2,
		MaxArrayElements: 2,
		MaxSizePerObject: 100,
	}

	configs = map[string]*fosite.Config{
		"optional-config": {
			AuthorizationDetailTypesSupported: []string{"payment_initiation", "data_access", "emr_authorization"},
			AuthorizationDetailsTypeHandlers: map[string]fosite.RFC9396AuthorizationDetailsTypeHandler{
				"payment_initiation": &PaymentInitiationTypeHandler{},
			},
			AuthorizationDetailsStrategy: fosite.OptionalRFC9396AuthorizationDetailsStrategy,
			AuthorizationDetailsLimits:   limits,
		},
		"default-config": {
			AuthorizationDetailTypesSupported: []string{"payment_initiation", "data_access", "subscriber", "emr_authorization"},
			AuthorizationDetailsTypeHandlers: map[string]fosite.RFC9396AuthorizationDetailsTypeHandler{
				"payment_initiation": &PaymentInitiationTypeHandler{},
			},
			AuthorizationDetailsStrategy: fosite.RFC9396DefaultAuthorizationDetailsStrategy,
			AuthorizationDetailsLimits:   limits,
		},
	}

	clients = map[string]fosite.Client{
		"no-restriction-client": &fosite.DefaultOptionalRFC9396Client{
			DefaultRFC9396Client: &fosite.DefaultRFC9396Client{
				DefaultClient:        &fosite.DefaultClient{},
				AuthorizationDetails: fosite.Arguments{"payment_initiation", "data_access", "subscriber"},
			},
			RestrictAuthorizationDetailTypes:     false,
			IgnoreUnknownAuthorizationDetailType: true,
		},
		"restrict-error-client": &fosite.DefaultOptionalRFC9396Client{
			DefaultRFC9396Client: &fosite.DefaultRFC9396Client{
				DefaultClient:        &fosite.DefaultClient{},
				AuthorizationDetails: fosite.Arguments{"payment_initiation", "data_access", "subscriber"},
			},
			RestrictAuthorizationDetailTypes:     true,
			IgnoreUnknownAuthorizationDetailType: false,
		},
		"restrict-ignore-client": &fosite.DefaultOptionalRFC9396Client{
			DefaultRFC9396Client: &fosite.DefaultRFC9396Client{
				DefaultClient:        &fosite.DefaultClient{},
				AuthorizationDetails: fosite.Arguments{"payment_initiation", "data_access", "subscriber"},
			},
			RestrictAuthorizationDetailTypes:     true,
			IgnoreUnknownAuthorizationDetailType: true,
		},
		"default-client": &fosite.DefaultRFC9396Client{
			DefaultClient:        &fosite.DefaultClient{},
			AuthorizationDetails: fosite.Arguments{"payment_initiation", "data_access", "subscriber"},
		},
	}
)

func TestAuthorizationDetails(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		clientName            string
		configName            string
		authorization_details string
		expectLen             int
		expectErr             string
	}{
		{
			name:       "all authorization_details accepted",
			clientName: "default-client",
			configName: "default-config",
			authorization_details: `[{"type":"data_access","locations":["https://example.com"]},
			                         {"type":"subscriber","email":"bob@sg.ibm.com"}]`,
			expectLen: 2,
			expectErr: "",
		},
		{
			name:                  "invalid JSON",
			clientName:            "default-client",
			configName:            "default-config",
			authorization_details: `[{"type":"payment_initiation",instructedAmount":{"currency":"EUR","amount":"123.50"}}]`,
			expectLen:             0,
			expectErr:             "Invalid authorization_details value.",
		},
		{
			name:                  "pass schema validation",
			clientName:            "default-client",
			configName:            "default-config",
			authorization_details: `[{"type":"payment_initiation","instructedAmount":{"currency":"EUR","amount":"123.50"}}]`,
			expectLen:             1,
			expectErr:             "",
		},
		{
			name:                  "fail schema validation",
			clientName:            "default-client",
			configName:            "default-config",
			authorization_details: `[{"type":"payment_initiation","locations":["https://example.com/payments"]}]`,
			expectLen:             0,
			expectErr:             "Authorization detail JSON of type 'payment_initiation' does not conform to the expected schema.",
		},
		{
			name:                  "exceed maximum bytes",
			clientName:            "default-client",
			configName:            "default-config",
			authorization_details: `[{"type":"payment_initiation","locations":["https://example.com/payments"],"instructedAmount":{"currency":"EUR","amount":"123.50"}}]`,
			expectLen:             0,
			expectErr:             "Each authorization detail JSON should not exceed 100 bytes.",
		},
		{
			name:                  "too deep",
			clientName:            "default-client",
			configName:            "default-config",
			authorization_details: `[{"type":"subscriber","address":{"location":{"city":"SimCity"}}}]`,
			expectLen:             0,
			expectErr:             "Objects in authorization detail JSON should not be nested more than 2 depth.",
		},
		{
			name:       "too many authorization_details",
			clientName: "default-client",
			configName: "default-config",
			authorization_details: `[{"type":"data_access","locations":["https://example.com"]},
			                         {"type":"subscriber","email":"bob@sg.ibm.com"},
									 {"type":"data_access","locations":["https://server.com"]}]`,
			expectLen: 0,
			expectErr: "Maximum 2 authorization details are allowed in a request.",
		},
		{
			name:                  "unknown authorization detail type",
			clientName:            "default-client",
			configName:            "default-config",
			authorization_details: `[{"type":"unknown_type","locations":["https://example.com"]}]`,
			expectLen:             0,
			expectErr:             "Request for authorization detail of type 'unknown_type' is not allowed.",
		},
		{
			name:                  "unknown authorization detail type - no restriction",
			clientName:            "no-restriction-client",
			configName:            "optional-config",
			authorization_details: `[{"type":"unknown_type","locations":["https://example.com"]}]`,
			expectLen:             1,
			expectErr:             "",
		},
		{
			name:                  "unknown authorization detail type - strictly restrict",
			clientName:            "restrict-error-client",
			configName:            "optional-config",
			authorization_details: `[{"type":"unknown_type","locations":["https://example.com"]}]`,
			expectLen:             0,
			expectErr:             "Request for authorization detail of type 'unknown_type' is not allowed.",
		},
		{
			name:                  "unknown authorization detail type - restrict and ignore",
			clientName:            "restrict-ignore-client",
			configName:            "optional-config",
			authorization_details: `[{"type":"unknown_type","locations":["https://example.com"]}]`,
			expectLen:             0,
			expectErr:             "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			handler := &rfc9396.AuthorizeHandler{
				Config: configs[tc.configName],
			}
			requester := &fosite.AuthorizeRequest{
				Request: fosite.Request{
					Client: clients[tc.clientName],
					Form: url.Values{
						"authorization_details": []string{tc.authorization_details},
					},
				},
			}
			err := handler.ValidateAuthorizeEndpointRequest(ctx, requester)
			if tc.expectErr != "" {
				require.Error(t, err)
				rfcerr := fosite.ErrorToRFC6749Error(err)
				assert.Contains(t, rfcerr.GetDescription(), tc.expectErr, "Expecting %s error, found: '%v'", tc.expectErr, err)
				assert.EqualValues(t, rfcerr.ErrorField, "invalid_authorization_details", "Expecting %s error, found: '%v'", "invalid_authorization_details", rfcerr.ErrorField)
				return
			}
			require.NoError(t, err)
			requestedAD := requester.GetRequestedAuthorizationDetails()
			assert.Len(t, requestedAD, tc.expectLen, "Expecting %d authorization_details accepted.", tc.expectLen)
		})
	}
}
