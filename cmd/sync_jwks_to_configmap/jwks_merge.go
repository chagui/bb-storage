package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/buildbarn/bb-storage/pkg/util"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fetchJWKS downloads a JWKS from a single URL, ensuring that the
// response is a valid JSON object containing a "keys" array. This
// ensures that if the server misbehaves (e.g., serves a static HTML
// file), we don't overwrite any previously downloaded JWKS.
func fetchJWKS(ctx context.Context, httpClient *http.Client, url string) ([]map[string]any, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, util.StatusWrap(err, "Failed to create HTTP request")
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, util.StatusWrap(err, "Failed to perform HTTP request")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, status.Errorf(codes.Unavailable, "HTTP request failed with status %#v", response.Status)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, util.StatusWrap(err, "Failed to read HTTP response")
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return nil, util.StatusWrap(err, "Failed to parse HTTP response")
	}
	return keys, nil
}

// parseJWKS validates that body is a JSON object containing a "keys"
// array of JSON objects, as required by RFC 7517, and returns the
// individual key objects contained within.
//
// Keys are decoded as generic map[string]any rather than into a typed
// JWK struct. This process never inspects key material; it only
// merges and republishes it, so decoding into a fixed schema would
// risk silently dropping fields a stricter type doesn't declare
// (vendor extensions, future JWK members, etc.), corrupting the keys
// we write to the ConfigMap and breaking byte-for-byte duplicate
// detection in mergeJWKS(). A generic map preserves every field
// verbatim while still letting us pick out "kid" and canonicalize for
// comparison.
func parseJWKS(body []byte) ([]map[string]any, error) {
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, status.Errorf(codes.Unknown, "Response is not a JSON object: %s", err)
	}
	rawKeys, ok := document["keys"]
	if !ok {
		return nil, status.Error(codes.Unknown, "Response does not contain a \"keys\" field")
	}
	keysSlice, ok := rawKeys.([]any)
	if !ok {
		return nil, status.Error(codes.Unknown, "Field \"keys\" is not an array")
	}
	keys := make([]map[string]any, 0, len(keysSlice))
	for i, rawKey := range keysSlice {
		key, ok := rawKey.(map[string]any)
		if !ok {
			return nil, status.Errorf(codes.Unknown, "Key at index %d of field \"keys\" is not a JSON object", i)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// mergeJWKS merges the keys contained in one or more JWKS documents
// into a single JWKS. Keys carrying a "kid" are deduplicated by that
// ID: byte-for-byte identical keys (once canonicalized) sharing a
// "kid" are merged silently, while distinct keys that share the same
// "kid" cause an error, as silently discarding one of them would make
// tokens signed with it unverifiable.
//
// "kid" is optional under RFC 7517, and pkg/jwt's
// NewSignatureValidatorFromJSONWebKeySet() tries unnamed keys against
// every JWT regardless of any key ID it carries. Keys without a "kid"
// therefore have no identifier to merge or conflict on: they are all
// preserved, deduplicating only exact byte-for-byte duplicates.
//
// keysPerURL and urls must have the same length; urls is only used to
// produce descriptive error messages.
func mergeJWKS(keysPerURL [][]map[string]any, urls []string) (map[string]any, error) {
	seenByKid := map[string][]byte{}
	seenUnnamed := map[string]struct{}{}
	conflictingKids := map[string]struct{}{}
	mergedKeys := make([]map[string]any, 0)
	for i, keys := range keysPerURL {
		for _, key := range keys {
			// json.Marshal() of a map[string]any orders
			// object keys alphabetically, giving us a
			// canonical form to compare for equality
			// regardless of how the source served the key.
			canonical, err := json.Marshal(key)
			if err != nil {
				return nil, status.Errorf(codes.Unknown, "Failed to marshal key served by %#v: %s", urls[i], err)
			}

			kidValue, ok := key["kid"]
			if !ok {
				if _, ok := seenUnnamed[string(canonical)]; ok {
					continue
				}
				seenUnnamed[string(canonical)] = struct{}{}
				mergedKeys = append(mergedKeys, key)
				continue
			}
			kid, ok := kidValue.(string)
			if !ok {
				return nil, status.Errorf(codes.Unknown, "Key served by %#v has a \"kid\" field that is not a string", urls[i])
			}
			if existingCanonical, ok := seenByKid[kid]; ok {
				if !bytes.Equal(existingCanonical, canonical) {
					conflictingKids[kid] = struct{}{}
				}
				continue
			}
			seenByKid[kid] = canonical
			mergedKeys = append(mergedKeys, key)
		}
	}
	if len(conflictingKids) > 0 {
		kids := make([]string, 0, len(conflictingKids))
		for kid := range conflictingKids {
			kids = append(kids, kid)
		}
		sort.Strings(kids)
		return nil, status.Errorf(
			codes.InvalidArgument,
			"Multiple distinct keys share the same \"kid\": %s",
			strings.Join(kids, ", "))
	}
	return map[string]any{"keys": mergedKeys}, nil
}
