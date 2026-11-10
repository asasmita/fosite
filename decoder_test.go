package fosite

import (
	"errors"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeJSONArray(t *testing.T) {
	limits := func() *JSONLimits {
		return &JSONLimits{MaxDepth: 3, MaxSizePerObject: 128, MaxArrayElements: 3}
	}

	for _, tc := range []struct {
		name      string
		input     string
		limits    *JSONLimits
		expectLen int
		expectErr string
	}{
		{
			name:      "valid array",
			input:     `[{"type":"openid","locations":["https://example.com"]},{"type":"payment"}]`,
			limits:    limits(),
			expectLen: 2,
		},
		{
			name:      "empty array",
			input:     `[]`,
			limits:    limits(),
			expectLen: 0,
		},
		{
			name:      "element count at limit",
			input:     `[{"a":1},{"a":2},{"a":3}]`,
			limits:    limits(),
			expectLen: 3,
		},
		{
			name:      "element count exceeds limit",
			input:     `[{"a":1},{"a":2},{"a":3},{"a":4}]`,
			limits:    limits(),
			expectErr: "JSON array exceeds maximum limit",
		},
		{
			name:      "depth at limit",
			input:     `[{"a":{"b":{"c":1}}}]`,
			limits:    limits(),
			expectLen: 1,
		},
		{
			name:      "depth exceeds limit",
			input:     `[{"a":{"b":{"c":{"d":1}}}}]`,
			limits:    limits(),
			expectErr: "JSON object exceeds maximum depth",
		},
		{
			name:      "depth exceeded through nested array",
			input:     `[{"a":[[["x"]]]}]`,
			limits:    limits(),
			expectErr: "JSON object exceeds maximum depth",
		},
		{
			name:      "object size exceeds limit",
			input:     `[{"a":"` + strings.Repeat("x", 200) + `"}]`,
			limits:    limits(),
			expectErr: "JSON object exceeds maximum size",
		},
		{
			name:      "only the oversized object is rejected",
			input:     `[{"a":1},{"a":"` + strings.Repeat("x", 200) + `"}]`,
			limits:    limits(),
			expectErr: "JSON object exceeds maximum size",
		},
		{
			name:      "root is an object",
			input:     `{"a":1}`,
			limits:    limits(),
			expectErr: "invalid JSON",
		},
		{
			name:      "root is a scalar",
			input:     `"a"`,
			limits:    limits(),
			expectErr: "invalid JSON",
		},
		{
			name:      "empty input",
			input:     ``,
			limits:    limits(),
			expectErr: "invalid JSON",
		},
		{
			name:      "malformed element",
			input:     `[{"a":}]`,
			limits:    limits(),
			expectErr: "invalid JSON",
		},
		{
			name:      "element is not an object",
			input:     `[1]`,
			limits:    limits(),
			expectErr: "invalid JSON",
		},
		{
			name:      "unterminated array",
			input:     `[{"a":1}`,
			limits:    limits(),
			expectErr: "invalid JSON",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := DecodeJSONArrayWithLimits(strings.NewReader(tc.input), tc.limits)
			if tc.expectErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectErr)
				assert.Nil(t, res)
				return
			}
			require.NoError(t, err)
			assert.Len(t, res, tc.expectLen)
		})
	}

	t.Run("decoded content", func(t *testing.T) {
		res, err := DecodeJSONArrayWithLimits(strings.NewReader(`[{"type":"openid","n":1},{"type":"payment"}]`), limits())
		require.NoError(t, err)
		require.Len(t, res, 2)
		assert.Equal(t, "openid", res[0]["type"])
		assert.EqualValues(t, 1, res[0]["n"])
		assert.Equal(t, "payment", res[1]["type"])
	})
}

func TestDecodeJSONObject(t *testing.T) {
	limits := func() *JSONLimits {
		return &JSONLimits{MaxDepth: 3, MaxSizePerObject: 128}
	}

	for _, tc := range []struct {
		name      string
		input     string
		limits    *JSONLimits
		expectErr string
	}{
		{
			name:   "valid object",
			input:  `{"type":"openid","locations":["https://example.com"]}`,
			limits: limits(),
		},
		{
			name:   "empty object",
			input:  `{}`,
			limits: limits(),
		},
		{
			name:   "size exactly at limit",
			input:  `{"a":1}`,
			limits: &JSONLimits{MaxDepth: 3, MaxSizePerObject: 7},
		},
		{
			name:      "size one byte over limit",
			input:     `{"a":1}`,
			limits:    &JSONLimits{MaxDepth: 3, MaxSizePerObject: 6},
			expectErr: "JSON object exceeds maximum size",
		},
		{
			name:      "size far over limit",
			input:     `{"a":"` + strings.Repeat("x", 1000) + `"}`,
			limits:    limits(),
			expectErr: "JSON object exceeds maximum size",
		},
		{
			name:   "depth at limit",
			input:  `{"a":{"b":{"c":1}}}`,
			limits: limits(),
		},
		{
			name:      "depth exceeds limit",
			input:     `{"a":{"b":{"c":{"d":1}}}}`,
			limits:    limits(),
			expectErr: "JSON object exceeds maximum depth",
		},
		{
			name:      "depth exceeded through nested array",
			input:     `{"a":[[["x"]]]}`,
			limits:    limits(),
			expectErr: "JSON object exceeds maximum depth",
		},
		{
			name:      "root is an array",
			input:     `[{"a":1}]`,
			limits:    limits(),
			expectErr: "invalid JSON",
		},
		{
			name:      "root is a scalar",
			input:     `"a"`,
			limits:    limits(),
			expectErr: "invalid JSON",
		},
		{
			name:      "empty input",
			input:     ``,
			limits:    limits(),
			expectErr: "invalid JSON",
		},
		{
			name:      "malformed object",
			input:     `{"a":}`,
			limits:    limits(),
			expectErr: "invalid JSON",
		},
		{
			name:      "trailing data",
			input:     `{"a":1}{"b":2}`,
			limits:    limits(),
			expectErr: "invalid JSON",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := DecodeJSONObjectWithLimits(strings.NewReader(tc.input), tc.limits)
			if tc.expectErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectErr)
				assert.Nil(t, res)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, res)
		})
	}

	t.Run("decoded content", func(t *testing.T) {
		res, err := DecodeJSONObjectWithLimits(strings.NewReader(`{"type":"openid","n":1,"nested":{"k":"v"}}`), limits())
		require.NoError(t, err)
		assert.Equal(t, "openid", res["type"])
		assert.EqualValues(t, 1, res["n"])
		assert.Equal(t, map[string]any{"k": "v"}, res["nested"])
	})

	t.Run("reader error", func(t *testing.T) {
		readErr := errors.New("boom")
		res, err := DecodeJSONObjectWithLimits(iotest.ErrReader(readErr), limits())
		require.Error(t, err)
		assert.ErrorIs(t, err, DecodeErrorInvalidJSON)
		assert.Contains(t, err.Error(), "invalid JSON")
		assert.Nil(t, res)
	})

	t.Run("does not read beyond the size limit", func(t *testing.T) {
		r := &countingReader{r: strings.NewReader(strings.Repeat("x", 100000))}
		_, err := DecodeJSONObjectWithLimits(r, &JSONLimits{MaxDepth: 3, MaxSizePerObject: 16})
		require.Error(t, err)
		assert.LessOrEqual(t, r.n, int64(17))
	})
}

type countingReader struct {
	r *strings.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
