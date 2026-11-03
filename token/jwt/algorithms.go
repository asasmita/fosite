// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"github.com/go-jose/go-jose/v4"
)

// go-jose v4 require list of algorithms to be specified when parsing JWT
// for backward compatibility, fosite supports all algorithms supported by go-jose
// adopter can do additional check if required

var SupportedSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.SignatureAlgorithm("none"), jose.EdDSA,
	jose.ES256, jose.ES384, jose.ES512,
	jose.HS256, jose.HS384, jose.HS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.RS256, jose.RS384, jose.RS512,
}

var SupportedContentEncryptions = []jose.ContentEncryption{
	jose.A128GCM, jose.A192GCM, jose.A256GCM,
	jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512,
}

var SupportedKeyEncryptions = []jose.KeyAlgorithm{
	jose.A128KW, jose.A192KW, jose.A256KW, jose.DIRECT,
	jose.A128GCMKW, jose.A192GCMKW, jose.A256GCMKW,
	jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW,
	jose.ED25519, jose.RSA1_5, jose.RSA_OAEP, jose.RSA_OAEP_256,
	jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW,
}
