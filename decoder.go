package fosite

import (
	"encoding/json"
	"io"

	"github.com/pkg/errors"
)

var (
	DecodeErrorInvalidJSON              = errors.New("invalid JSON")                      // generic JSON error
	DecodeErrorInvalidJSONObject        = errors.New("invalid JSON object")               // expecting a JSON object
	DecodeErrorInvalidJSONArray         = errors.New("invalid JSON array")                // expecting a JSON array
	DecodeErrorMaxArrayElementsExceeded = errors.New("JSON array exceeds maximum limit")  // maximum element in JSON array exceeded
	DecodeErrorMaxSizePerObjectExceeded = errors.New("JSON object exceeds maximum size")  // maximum JSON object size exceeded
	DecodeErrorMaxDepthExceeded         = errors.New("JSON object exceeds maximum depth") // maximum JSON object depth exceeded
)

// SecurityLimits defines the thresholds for the JSON payload
type JSONLimits struct {
	MaxArrayElements int   // Maximum total number of elements inside the root array
	MaxSizePerObject int64 // Maximum bytes allowed for an individual object inside the array
	MaxDepth         int   // Maximum nesting depth allowed (e.g., 3 or 4)
}

// DecodeJSONArray reads a JSON array from a stream and validates the limits on the fly.
// If valid, it returns the unmarshaled slice of maps.
func DecodeJSONArrayWithLimits(r io.Reader, limits *JSONLimits) ([]map[string]any, error) {
	dec := json.NewDecoder(r)

	// 1. Ensure the root token is the start of an array '['
	t, err := dec.Token()
	if err != nil {
		return nil, DecodeErrorInvalidJSON
	}
	if delim, ok := t.(json.Delim); !ok || delim != '[' {
		return nil, DecodeErrorInvalidJSONArray
	}

	var result []map[string]any
	currentDepth := 0 // The depth is counted from the array content

	// 2. Stream through array contents
	for dec.More() {
		// Enforce array element count limits
		if len(result) >= limits.MaxArrayElements {
			return nil, DecodeErrorMaxArrayElementsExceeded
		}

		// Track where this specific object begins in the byte stream
		objectStartOffset := dec.InputOffset()

		// Use json.RawMessage to cleanly capture the upcoming object without allocations
		var rawItem json.RawMessage
		if err := dec.Decode(&rawItem); err != nil {
			return nil, DecodeErrorInvalidJSON
		}

		// Calculate precise byte size of the decoded object
		objectEndOffset := dec.InputOffset()
		objectSize := objectEndOffset - objectStartOffset
		if objectSize > limits.MaxSizePerObject {
			return nil, DecodeErrorMaxSizePerObjectExceeded
		}

		// Enforce deep nesting rules inside this specific object snippet
		if err := verifyDepth(rawItem, currentDepth, limits.MaxDepth); err != nil {
			return nil, err
		}

		// If all structural checks pass, safe to unmarshal into memory
		var item map[string]any
		if err := json.Unmarshal(rawItem, &item); err != nil {
			return nil, DecodeErrorInvalidJSONObject
		}

		result = append(result, item)
	}

	// 3. Read closing array token ']'
	if _, err := dec.Token(); err != nil {
		return nil, DecodeErrorInvalidJSON
	}

	return result, nil
}

// DecodeJSONObject reads a single JSON object from a stream and validates the
// MaxSizePerObject and MaxDepth limits before unmarshaling it into memory.
// At most MaxSizePerObject+1 bytes are read from the stream.
func DecodeJSONObjectWithLimits(r io.Reader, limits *JSONLimits) (map[string]any, error) {
	raw, err := io.ReadAll(io.LimitReader(r, limits.MaxSizePerObject+1))
	if err != nil {
		return nil, DecodeErrorInvalidJSON
	}

	if int64(len(raw)) > limits.MaxSizePerObject {
		return nil, DecodeErrorMaxSizePerObjectExceeded
	}

	if err := verifyDepth(raw, 0, limits.MaxDepth); err != nil {
		return nil, err
	}

	var item map[string]any
	if err := json.Unmarshal(raw, &item); err != nil {
		return nil, DecodeErrorInvalidJSONObject
	}

	return item, nil
}

// Low-overhead linear scan over the token slice to track structural balance
func verifyDepth(raw []byte, baseDepth int, maxDepth int) error {
	depth := baseDepth
	for _, b := range raw {
		switch b {
		case '{', '[':
			depth++
			if depth > maxDepth {
				return DecodeErrorMaxDepthExceeded
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return nil
}
