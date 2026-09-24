// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc9396_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/rfc9396"
	"github.com/stretchr/testify/suite"
)

type AuthorizeHandlerTestSuite struct {
	suite.Suite
	config  fosite.RFC9396ConfigProvider
	handler *rfc9396.AuthorizeHandler
}

// Setup before each test in the suite.
func (s *AuthorizeHandlerTestSuite) SetupSuite() {}

// Will run after all the tests in the suite have been run.
func (s *AuthorizeHandlerTestSuite) TearDownSuite() {
}

// Will run after each test in the suite.
func (s *AuthorizeHandlerTestSuite) TearDownTest() {

}

// Setup before each test.
func (s *AuthorizeHandlerTestSuite) SetupTest() {
	s.config = &fosite.Config{
		AuthorizationDetailTypesSupported: []string{"payment_initiation", "data_access", "emr_authorization"},
		AuthorizationDetailsTypeHandlers: map[string]fosite.RFC9396AuthorizationDetailsTypeHandler{
			"payment_initiation": &PaymentInitiationTypeHandler{},
		},
		AuthorizationDetailsStrategy:          fosite.RFC9396ExactAuthorizationDetailsStrategy,
		IgnoreUnknownAuthorizationDetailsType: true,
	}

	s.handler = &rfc9396.AuthorizeHandler{
		Config: s.config,
	}
}

// In order for 'go test' to run this suite, we need to create
// a normal test function and pass our suite to suite.Run.
func TestAuthorizeHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(AuthorizeHandlerTestSuite))
}

func (s *AuthorizeHandlerTestSuite) TestUnknownAuthorizationDetail() {
	ctx := context.Background()
	requester := &fosite.AuthorizeRequest{
		Request: fosite.Request{
			Client: &fosite.DefaultRFC9396Client{
				DefaultClient:        &fosite.DefaultClient{},
				AuthorizationDetails: fosite.Arguments{"payment_initiation", "data_access"},
			},
			Form: url.Values{
				"authorization_details": []string{`[{
					"type": "unknown_type"
				}]`},
			},
		},
	}

	err := s.handler.ValidateAuthorizeEndpointRequest(ctx, requester)

	s.Nil(err, "error is not nil; %+v", err)
	requestedAD := requester.GetRequestedAuthorizationDetails()
	s.EqualValues(0, len(requestedAD), "Expected number of authorization details is 0; found %+v", requestedAD)
}

func (s *AuthorizeHandlerTestSuite) TestUnknownAuthorizationDetailWithStricterConfig() {
	ctx := context.Background()
	requester := &fosite.AuthorizeRequest{
		Request: fosite.Request{
			Client: &fosite.DefaultRFC9396Client{
				DefaultClient:        &fosite.DefaultClient{},
				AuthorizationDetails: fosite.Arguments{"payment_initiation", "data_access"},
			},
			Form: url.Values{
				"authorization_details": []string{`[{
					"type": "unknown_type"
				}]`},
			},
		},
	}

	config := &fosite.Config{
		AuthorizationDetailTypesSupported: []string{"payment_initiation", "data_access", "emr_authorization"},
		AuthorizationDetailsTypeHandlers: map[string]fosite.RFC9396AuthorizationDetailsTypeHandler{
			"payment_initiation": nil,
		},
		AuthorizationDetailsStrategy: fosite.RFC9396ExactAuthorizationDetailsStrategy,
	}

	handler := &rfc9396.AuthorizeHandler{
		Config: config,
	}

	err := handler.ValidateAuthorizeEndpointRequest(ctx, requester)

	s.NotNil(err, "error is nil")
	expectedErr := fosite.ErrInvalidAuthorizationDetails.WithHintf("Unknown authorization detail type %s", "unknown_type")
	receivedErr := fosite.ErrorToRFC6749Error(err)
	s.EqualValues(expectedErr.GetDescription(), receivedErr.GetDescription(), "error does not match")
	s.EqualValues(expectedErr.ErrorField, receivedErr.ErrorField, "error does not match")
	requestedAD := requester.GetRequestedAuthorizationDetails()
	s.EqualValues(0, len(requestedAD), "Expected number of authorization details is 0; found %+v", requestedAD)
}

func (s *AuthorizeHandlerTestSuite) TestValidAuthorizationDetail() {
	ctx := context.Background()
	requester := &fosite.AuthorizeRequest{
		Request: fosite.Request{
			Client: &fosite.DefaultRFC9396Client{
				DefaultClient:        &fosite.DefaultClient{},
				AuthorizationDetails: fosite.Arguments{"payment_initiation", "data_access"},
			},
			Form: url.Values{
				"authorization_details": []string{`[{
   "type": "payment_initiation",
   "locations": [
      "https://example.com/payments"
   ],
   "instructedAmount": {
      "currency": "EUR",
      "amount": "123.50"
   },
   "creditorName": "Merchant A",
   "creditorAccount": {
      "bic":"ABCIDEFFXXX",
      "iban": "DE02100100109307118603"
   },
   "remittanceInformationUnstructured": "Ref Number Merchant"
}]`},
			},
		},
	}

	err := s.handler.ValidateAuthorizeEndpointRequest(ctx, requester)

	s.Nil(err, "error is not nil; %+v", err)
	requestedAD := requester.GetRequestedAuthorizationDetails()
	s.EqualValues(1, len(requestedAD), "Expected number of authorization details is 0; found %+v", requestedAD)

	instructedAmount := fosite.Map(requestedAD[0]).SafeMap("instructedAmount", nil)
	amount := fosite.Map(instructedAmount).SafeString("amount", "")
	s.EqualValues("123.50", amount, "Amount doesn't match.")
}

func (s *AuthorizeHandlerTestSuite) TestInvalidAuthorizationDetailData() {
	ctx := context.Background()
	requester := &fosite.AuthorizeRequest{
		Request: fosite.Request{
			Client: &fosite.DefaultRFC9396Client{
				DefaultClient:        &fosite.DefaultClient{},
				AuthorizationDetails: fosite.Arguments{"payment_initiation", "data_access"},
			},
			Form: url.Values{
				"authorization_details": []string{`[{
   "type": "payment_initiation",
   "locations": [
      "https://example.com/payments"
   ],
   "creditorName": "Merchant A",
   "creditorAccount": {
      "bic":"ABCIDEFFXXX",
      "iban": "DE02100100109307118603"
   },
   "remittanceInformationUnstructured": "Ref Number Merchant"
}]`},
			},
		},
	}

	err := s.handler.ValidateAuthorizeEndpointRequest(ctx, requester)

	s.NotNil(err, "error is nil")
	s.EqualError(err, "instructedAmount is required.")
}
