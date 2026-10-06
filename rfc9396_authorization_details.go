// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/ory/x/errorsx"
)

const internal_id = "___id___"

// RFC9396AuthorizationDetailsLimits defines the authorization details limits
type RFC9396AuthorizationDetailsLimits struct {
	MaximumPerRequest int
	MaximumJSONSize   int
	MaximumJSONDepth  int
}

// RFC9396AuthorizationDetailsType is a map that holds authorization detail
type RFC9396AuthorizationDetailsType map[string]any

// SetID assign the calculated internal ID to the RFC9396AuthorizationDetailsType map
func (ad RFC9396AuthorizationDetailsType) SetID(id string) {
	ad[internal_id] = id
}

// GetID returns internal_id property if exists, otherwise return empty string
func (ad RFC9396AuthorizationDetailsType) GetID() string {
	return ad.GetPropertyAsString(internal_id)
}

// GetType return the 'type' property
func (ad RFC9396AuthorizationDetailsType) GetType() string {
	return ad.GetPropertyAsString("type")
}

// GetPropertyAsString return the specified property as a string
func (ad RFC9396AuthorizationDetailsType) GetPropertyAsString(name string) string {
	return Map(ad).SafeString(name, "")
}

// GetPropertyAsStringList return the specified property as a string list
func (ad RFC9396AuthorizationDetailsType) GetPropertyAsStringList(name string) []string {
	return Map(ad).SafeStringSlice(name, nil)
}

// Perform Equals
func (ad RFC9396AuthorizationDetailsType) Equals(cmp RFC9396AuthorizationDetailsType) bool {
	if ad == nil && cmp == nil {
		return true
	}

	if ad == nil || cmp == nil {
		return false
	}

	if ad.GetType() != cmp.GetType() {
		return false
	}
	return ad.getIDOrDefault() == cmp.getIDOrDefault()
}

func (ad RFC9396AuthorizationDetailsType) getIDOrDefault() string {
	if id := ad.GetID(); len(id) > 0 {
		return id
	}
	// internal ID has not been calculated - for Equals, lets use a default strategy to differentiate
	// hopefully this never happen as we calculate the internal ID when the request is received
	// this can be detected in the tests when two authorization details of same type doesn't match although they suppose to match
	dfltID, _ := RFC9396GetAuthorizationDetailsTypeIDJSONHashStrategy(ad)
	return dfltID
}

func (ad RFC9396AuthorizationDetailsType) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any(ad))
}

func (ad RFC9396AuthorizationDetailsType) String() string {
	if ad == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%+v", map[string]any(ad))
}

// WithoutInternalID returns copy of the map without internal ID
// This should be called when outputting authorization detail in the response
func (ad RFC9396AuthorizationDetailsType) WithoutInternalID() RFC9396AuthorizationDetailsType {
	m := RFC9396AuthorizationDetailsType{}

	for k, v := range ad {
		if k == internal_id {
			continue
		}
		m[k] = v
	}

	return m
}

// SanitizeAuthorizationDetailTypes returns authorization details without internal ID that added during processing
func SanitizeAuthorizationDetailTypes(adts []RFC9396AuthorizationDetailsType) []RFC9396AuthorizationDetailsType {
	if len(adts) == 0 {
		return adts
	}

	result := []RFC9396AuthorizationDetailsType{}
	for _, ad := range adts {
		result = append(result, ad.WithoutInternalID())
	}
	return result
}

// RFC9396AuthorizationDetailsTypeHandler handles validation, ID calculation and other processing
type RFC9396AuthorizationDetailsTypeHandler interface {
	// Validate should check the JSON properties of the authorization detail object, possibly using JSON schema
	Validate(t RFC9396AuthorizationDetailsType) error

	// GetID returns internal ID calculated using RFC9396GetAuthorizationDetailsIDStrategy or script
	GetID(t RFC9396AuthorizationDetailsType) (string, error)

	// Handle is used to do extra processing for a particular authorization detail type
	// Return true if this authorization detail is meaningless to indicate any fine-grained authorization
	Handle(ctx context.Context, req Requester, t RFC9396AuthorizationDetailsType) (bool, error)
}

type RFC9396DefaultAuthorizationDetailsTypeHandler struct {
	RFC9396GetAuthorizationDetailsIDStrategy
}

// Validate validates the common properties.
func (h *RFC9396DefaultAuthorizationDetailsTypeHandler) Validate(t RFC9396AuthorizationDetailsType) error {
	if len(t.GetType()) == 0 {
		return errorsx.WithStack(ErrInvalidAuthorizationDetails.WithHint("Missing 'type' in the authorization details object."))
	}

	return nil
}

// GetID generates a unique identifier to identify this object
func (h *RFC9396DefaultAuthorizationDetailsTypeHandler) GetID(t RFC9396AuthorizationDetailsType) (string, error) {
	if h.RFC9396GetAuthorizationDetailsIDStrategy == nil {
		h.RFC9396GetAuthorizationDetailsIDStrategy = RFC9396GetAuthorizationDetailsTypeIDJSONHashStrategy
	}
	return h.RFC9396GetAuthorizationDetailsIDStrategy(t)
}

func (h *RFC9396DefaultAuthorizationDetailsTypeHandler) Handle(ctx context.Context, req Requester,
	t RFC9396AuthorizationDetailsType) (bool, error) {
	return false, nil
}

type RFC9396GetAuthorizationDetailsIDStrategy func(t RFC9396AuthorizationDetailsType) (string, error)

func RFC9396GetAuthorizationDetailsIDDefaultStrategy(t RFC9396AuthorizationDetailsType) (string, error) {
	identifier := t.GetPropertyAsString("identifier")
	actions := t.GetPropertyAsStringList("actions")
	datatypes := t.GetPropertyAsStringList("datatypes")
	locations := t.GetPropertyAsStringList("locations")
	privileges := t.GetPropertyAsStringList("privileges")
	// sort the string array first to get consistent result
	sort.Strings(actions)
	sort.Strings(datatypes)
	sort.Strings(locations)
	sort.Strings(privileges)
	// key is concatenation of known fields, then hash it
	key := fmt.Sprintf("%v.%v.%v.%v.%v", identifier, actions, datatypes, locations, privileges)
	hash := sha512.Sum512([]byte(key))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

func RFC9396GetAuthorizationDetailsTypeIDJSONHashStrategy(t RFC9396AuthorizationDetailsType) (string, error) {
	// for this, we just hash the whole json
	if b, err := t.MarshalJSON(); err == nil {
		hash := sha512.Sum512(b)
		return base64.RawURLEncoding.EncodeToString(hash[:]), nil
	} else {
		return "", err
	}
}

// RFC9396AuthorizationDetailsStrategy is a strategy for matching authorization detail types.
// This mirrors ScopeStrategy.
type RFC9396AuthorizationDetailsStrategy func(haystack []string, needle string) bool

func RFC9396ExactAuthorizationDetailsStrategy(haystack []string, needle string) bool {
	for _, this := range haystack {
		if needle == this {
			return true
		}
	}

	return false
}

type RFC9396Client interface {
	// GetAuthorizationDetailTypes returns the list of authorization detail types supported
	// for the client.
	GetAuthorizationDetailTypes() Arguments
}

type DefaultRFC9396Client struct {
	*DefaultClient
	AuthorizationDetails Arguments
}

// GetAuthorizationDetailTypes returns the list of authorization detail types supported
// for the client.
func (c *DefaultRFC9396Client) GetAuthorizationDetailTypes() Arguments {
	return c.AuthorizationDetails
}
