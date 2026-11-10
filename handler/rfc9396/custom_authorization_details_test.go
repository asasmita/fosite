// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc9396_test

import (
	"context"
	"fmt"

	"github.com/ory/fosite"
)

type PaymentInitiationTypeHandler struct {
	fosite.RFC9396DefaultAuthorizationDetailsTypeHandler
}

func (h *PaymentInitiationTypeHandler) GetID(t fosite.RFC9396AuthorizationDetailsType) (string, error) {
	return h.RFC9396DefaultAuthorizationDetailsTypeHandler.GetID(t)
}

func (h *PaymentInitiationTypeHandler) Validate(t fosite.RFC9396AuthorizationDetailsType) error {
	instructedAmount := fosite.Map(t).SafeMap("instructedAmount", nil)
	if instructedAmount == nil {
		return fmt.Errorf("instructedAmount is required.")
	}

	if fosite.Map(instructedAmount).SafeString("currency", "") == "" {
		return fmt.Errorf("instructedAmount.currency is required.")
	}

	if fosite.Map(instructedAmount).SafeString("amount", "") == "" {
		return fmt.Errorf("instructedAmount.amount is required.")
	}

	return h.RFC9396DefaultAuthorizationDetailsTypeHandler.Validate(t)
}

func (h *PaymentInitiationTypeHandler) Handle(ctx context.Context, req fosite.Requester,
	t fosite.RFC9396AuthorizationDetailsType) (bool, error) {
	return false, nil
}
