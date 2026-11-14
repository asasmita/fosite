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

func (h *PaymentInitiationTypeHandler) GetID(ctx context.Context, t fosite.RFC9396AuthorizationDetailsType) (string, error) {
	return h.RFC9396DefaultAuthorizationDetailsTypeHandler.GetID(ctx, t)
}

func (h *PaymentInitiationTypeHandler) Validate(ctx context.Context, t fosite.RFC9396AuthorizationDetailsType) error {
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

	return h.RFC9396DefaultAuthorizationDetailsTypeHandler.Validate(ctx, t)
}
