// Copyright 2024 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package qkd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/scionproto/scion/control/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultStoreToNoop(t *testing.T) {
	// Get the default configuration.
	cnf := config.QKDConfig{}
	cnf.InitDefaults()

	// Get the store from this configuration.
	store, err := NewStoreFromCACert(cnf.URL, cnf.SaeID, cnf.CA, cnf.Cert, cnf.Key)
	assert.NoError(t, err)

	assert.IsType(t, &noopStore{}, store)
}

func TestStoreWithConfig(t *testing.T) {
	// Create some configuration.
	cnf := config.QKDConfig{
		URL:   "https://sampleqkd.ethz.ch",
		SaeID: "1234",
		CA:    "testdata/cert.pem",
		Cert:  "testdata/cert.pem",
		Key:   "testdata/key.pem",
	}

	// Get the store from this configuration.
	store, err := NewStoreFromCACert(cnf.URL, cnf.SaeID, cnf.CA, cnf.Cert, cnf.Key)
	assert.NoError(t, err)

	assert.IsType(t, &oneTimePadStore{}, store)
}

// TODO(juagargi) more tests

func TestSimulator(t *testing.T) {

	t.Skip("Disabled. Run the QKD simulator with two KMEs and enable to pass this test.")

	// Create two http clients to talk to KME1 and KME2.
	httpClients := make([]http.Client, 2)
	for i := 1; i <= 2; i++ {
		ca := fmt.Sprintf(
			"/home/juan/devel/ETH/scion.scionlab/vm-kme%[1]d/SAE%[1]d/sae-scion-%[1]d.ca-chain.cert.pem", i)
		cert := fmt.Sprintf(
			"/home/juan/devel/ETH/scion.scionlab/vm-kme%[1]d/SAE%[1]d/sae-scion-%[1]d.cert.pem", i)
		key := fmt.Sprintf(
			"/home/juan/devel/ETH/scion.scionlab/vm-kme%[1]d/SAE%[1]d/sae-scion-%[1]d.key.pem", i)

		caCert, err := os.ReadFile(ca)
		require.NoError(t, err)

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		// load client cert
		crt, err := tls.LoadX509KeyPair(cert, key)
		require.NoError(t, err)

		// prepare TLS
		tlsConfig := &tls.Config{
			RootCAs: caCertPool,
			GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return &crt, nil
			},
		}

		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
		}
		httpClients[i-1] = http.Client{
			Transport: transport,
		}
	}
	c1 := httpClients[0]
	c2 := httpClients[1]

	// Is the simulator running?
	checkGet(t, c1, "https://qkde0001.public/docs")
	checkGet(t, c2, "https://qkde0002.public/docs")

	// Create key at KME2.
	msg := checkGet(t, c2, "https://qkde0002.public/api/v1/keys/sae-scion-1/enc_keys")
	keysAndIds := decodeKeysAndIDs(t, msg)
	require.Equal(t, 1, len(keysAndIds))

	// Retrieve key.
	msg = encodeKeyID(t, keysAndIds[0].KeyID)
	msg = checkPost(t, c1, "https://qkde0001.public/api/v1/keys/sae-scion-2/dec_keys", msg)
	t.Logf("Requested id %s and got: %s", keysAndIds[0].KeyID, msg)
	keysAndIds2 := decodeKeysAndIDs(t, msg)
	require.Equal(t, 1, len(keysAndIds2))
	require.Equal(t, keysAndIds[0].KeyID, keysAndIds2[0].KeyID)
	require.Equal(t, keysAndIds[0].Key, keysAndIds2[0].Key)

	key, err := base64.StdEncoding.DecodeString(keysAndIds[0].Key)
	require.NoError(t, err)
	require.Equal(t, 4, len(key))
	t.Logf("raw key is: %s", hex.EncodeToString(key))
}

func checkGet(t *testing.T, c http.Client, url string) string {
	resp, err := c.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)

	msg, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	t.Log(string(msg))
	return string(msg)
}

func checkPost(t *testing.T, c http.Client, url string, content string) string {
	r := bytes.NewBuffer([]byte(content))
	resp, err := c.Post(url, "application/json", r)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)

	msg, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	t.Log(string(msg))
	return string(msg)
}

func decodeKeysAndIDs(t *testing.T, msg string) []QkdKey {
	var keys struct {
		Keys []QkdKey `json:"keys"`
	}
	err := json.Unmarshal([]byte(msg), &keys)
	require.NoError(t, err)
	return keys.Keys
}

func encodeKeyID(t *testing.T, id string) string {
	type KeyID struct {
		KeyID string `json:"key_ID"`
	}
	ids := struct {
		KeyIDs []KeyID `json:"key_IDs"`
	}{
		KeyIDs: []KeyID{
			{id},
		},
	}
	content, err := json.Marshal(ids)
	require.NoError(t, err)
	return string(content)
}
