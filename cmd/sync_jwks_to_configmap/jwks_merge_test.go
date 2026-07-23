package main

import (
	"testing"

	"github.com/buildbarn/bb-storage/pkg/testutil"

	"github.com/stretchr/testify/require"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestParseJWKS(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		keys, err := parseJWKS([]byte(`{"keys":[{"kid":"a","kty":"RSA"},{"kid":"b","kty":"RSA"}]}`))
		require.NoError(t, err)
		require.Len(t, keys, 2)
		require.Equal(t, "a", keys[0]["kid"])
		require.Equal(t, "b", keys[1]["kid"])
	})

	t.Run("NotAJSONObject", func(t *testing.T) {
		_, err := parseJWKS([]byte(`not json`))
		testutil.RequirePrefixedStatus(t, status.Error(codes.Unknown, "Response is not a JSON object: "), err)
	})

	t.Run("MissingKeysField", func(t *testing.T) {
		_, err := parseJWKS([]byte(`{}`))
		testutil.RequireEqualStatus(t, status.Error(codes.Unknown, "Response does not contain a \"keys\" field"), err)
	})

	t.Run("KeysFieldNotAnArray", func(t *testing.T) {
		_, err := parseJWKS([]byte(`{"keys":"not an array"}`))
		testutil.RequireEqualStatus(t, status.Error(codes.Unknown, "Field \"keys\" is not an array"), err)
	})

	t.Run("KeyEntryNotAnObject", func(t *testing.T) {
		_, err := parseJWKS([]byte(`{"keys":["not an object"]}`))
		testutil.RequireEqualStatus(t, status.Error(codes.Unknown, "Key at index 0 of field \"keys\" is not a JSON object"), err)
	})
}

func TestMergeJWKS(t *testing.T) {
	t.Run("SingleURL", func(t *testing.T) {
		// Regression: a single source should behave exactly as
		// it did before multi-URL support was added.
		keysPerURL := [][]map[string]any{
			{
				{"kid": "a", "kty": "RSA"},
				{"kid": "b", "kty": "RSA"},
			},
		}
		merged, err := mergeJWKS(keysPerURL, []string{"https://example.com/jwks"})
		require.NoError(t, err)
		require.Equal(t, map[string]any{
			"keys": []map[string]any{
				{"kid": "a", "kty": "RSA"},
				{"kid": "b", "kty": "RSA"},
			},
		}, merged)
	})

	t.Run("MultipleURLsNoConflicts", func(t *testing.T) {
		keysPerURL := [][]map[string]any{
			{{"kid": "a", "kty": "RSA"}},
			{{"kid": "b", "kty": "RSA"}},
		}
		merged, err := mergeJWKS(keysPerURL, []string{"https://a.example.com/jwks", "https://b.example.com/jwks"})
		require.NoError(t, err)
		require.Equal(t, map[string]any{
			"keys": []map[string]any{
				{"kid": "a", "kty": "RSA"},
				{"kid": "b", "kty": "RSA"},
			},
		}, merged)
	})

	t.Run("MultipleURLsIdenticalDuplicateKeysMergedSilently", func(t *testing.T) {
		keysPerURL := [][]map[string]any{
			{{"kid": "a", "kty": "RSA", "n": "abc"}},
			{{"kid": "a", "kty": "RSA", "n": "abc"}},
		}
		merged, err := mergeJWKS(keysPerURL, []string{"https://a.example.com/jwks", "https://b.example.com/jwks"})
		require.NoError(t, err)
		require.Equal(t, map[string]any{
			"keys": []map[string]any{
				{"kid": "a", "kty": "RSA", "n": "abc"},
			},
		}, merged)
	})

	t.Run("MultipleURLsIdenticalDuplicateKeysWithDifferentFieldOrderingMergedSilently", func(t *testing.T) {
		// The canonicalization performed by mergeJWKS() must be
		// order-independent, since two servers may return the
		// same key with JSON fields in a different order.
		keysPerURL := [][]map[string]any{
			{{"kid": "a", "kty": "RSA", "n": "abc"}},
			{{"n": "abc", "kid": "a", "kty": "RSA"}},
		}
		merged, err := mergeJWKS(keysPerURL, []string{"https://a.example.com/jwks", "https://b.example.com/jwks"})
		require.NoError(t, err)
		require.Len(t, merged["keys"], 1)
	})

	t.Run("MultipleURLsConflictingKeysUnderSameKidFail", func(t *testing.T) {
		keysPerURL := [][]map[string]any{
			{{"kid": "a", "kty": "RSA", "n": "abc"}},
			{{"kid": "a", "kty": "RSA", "n": "def"}},
		}
		_, err := mergeJWKS(keysPerURL, []string{"https://a.example.com/jwks", "https://b.example.com/jwks"})
		testutil.RequireEqualStatus(t, status.Error(codes.InvalidArgument, "Multiple distinct keys share the same \"kid\": a"), err)
	})

	t.Run("MultipleURLsConflictingKeysNameAllConflictingKids", func(t *testing.T) {
		keysPerURL := [][]map[string]any{
			{
				{"kid": "a", "kty": "RSA", "n": "abc"},
				{"kid": "b", "kty": "RSA", "n": "abc"},
			},
			{
				{"kid": "a", "kty": "RSA", "n": "def"},
				{"kid": "b", "kty": "RSA", "n": "def"},
			},
		}
		_, err := mergeJWKS(keysPerURL, []string{"https://a.example.com/jwks", "https://b.example.com/jwks"})
		testutil.RequireEqualStatus(t, status.Error(codes.InvalidArgument, "Multiple distinct keys share the same \"kid\": a, b"), err)
	})

	t.Run("KeyWithoutKidIsPreserved", func(t *testing.T) {
		// "kid" is optional under RFC 7517, and
		// pkg/jwt.NewSignatureValidatorFromJSONWebKeySet() tries
		// unnamed keys against every JWT regardless of key ID.
		// Rejecting an unnamed key would drop a key that the
		// previous, single-URL implementation copied successfully.
		keysPerURL := [][]map[string]any{
			{{"kty": "RSA", "n": "abc"}},
		}
		merged, err := mergeJWKS(keysPerURL, []string{"https://example.com/jwks"})
		require.NoError(t, err)
		require.Equal(t, map[string]any{
			"keys": []map[string]any{
				{"kty": "RSA", "n": "abc"},
			},
		}, merged)
	})

	t.Run("MultipleDistinctKeysWithoutKidAreAllPreserved", func(t *testing.T) {
		// Without a "kid", there is no shared identifier for two
		// keys to conflict on: both must be kept.
		keysPerURL := [][]map[string]any{
			{{"kty": "RSA", "n": "abc"}},
			{{"kty": "RSA", "n": "def"}},
		}
		merged, err := mergeJWKS(keysPerURL, []string{"https://a.example.com/jwks", "https://b.example.com/jwks"})
		require.NoError(t, err)
		require.Equal(t, map[string]any{
			"keys": []map[string]any{
				{"kty": "RSA", "n": "abc"},
				{"kty": "RSA", "n": "def"},
			},
		}, merged)
	})

	t.Run("IdenticalKeysWithoutKidMergedSilently", func(t *testing.T) {
		keysPerURL := [][]map[string]any{
			{{"kty": "RSA", "n": "abc"}},
			{{"n": "abc", "kty": "RSA"}},
		}
		merged, err := mergeJWKS(keysPerURL, []string{"https://a.example.com/jwks", "https://b.example.com/jwks"})
		require.NoError(t, err)
		require.Equal(t, map[string]any{
			"keys": []map[string]any{
				{"kty": "RSA", "n": "abc"},
			},
		}, merged)
	})

	t.Run("NonStringKidFails", func(t *testing.T) {
		keysPerURL := [][]map[string]any{
			{{"kid": 123, "kty": "RSA"}},
		}
		_, err := mergeJWKS(keysPerURL, []string{"https://example.com/jwks"})
		testutil.RequireEqualStatus(t, status.Error(codes.Unknown, "Key served by \"https://example.com/jwks\" has a \"kid\" field that is not a string"), err)
	})
}
