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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
)

// Store is the QKD store in charge of (de)scrambling the L1 key.
type Store interface {
	MySaeId() string
	PrepareRequest(req *cppb.DRKeyLevel1Request)
	// ScrambleKey returns the key id or error
	ScrambleKey(req *cppb.DRKeyLevel1Request, key *drkey.Key) (string, error)
	DescrambleKey(rep *cppb.DRKeyLevel1Response, L1Key *drkey.Level1Key) error
}

// NewStoreFromCACert constructs an appropriate QKD store depending on the arguments.
func NewStoreFromCACert(url, saeId, ca, cert, key string) (Store, error) {
	if ca != "" || cert != "" || key != "" {
		log.Debug("[DRKey ServiceStore QKD] Will be using a one time pad from a KME")
		return newOneTimePadStore(url, saeId, ca, cert, key)
	}
	log.Debug("[DRKey ServiceStore QKD] No QKD enabled")
	return &noopStore{}, nil
}

// noopStore implements a null scrambler (doesn't modify anything).
type noopStore struct{}

var _ Store = (*noopStore)(nil)

func (s *noopStore) MySaeId() string {
	return ""
}

// PrepareRequest noop
func (s *noopStore) PrepareRequest(req *cppb.DRKeyLevel1Request) {}

// ScrambleKey noop
func (s *noopStore) ScrambleKey(req *cppb.DRKeyLevel1Request, key *drkey.Key) (string, error) {
	return "", nil
}

// DescrambleKey noop
func (s *noopStore) DescrambleKey(rep *cppb.DRKeyLevel1Response, L1Key *drkey.Level1Key) error {
	return nil
}

// oneTimePadStore implements the client for the IDQuantique API
type oneTimePadStore struct {
	url        url.URL     // where is the QKD machine
	saeId      string      // The ID of this SAE
	httpClient http.Client // to call the API
}

// newOneTimePadStore constructs a one time pad QKD store that uses ID Quantique API.
func newOneTimePadStore(URL, saeID, ca, cert, key string) (*oneTimePadStore, error) {
	baseURL, err := url.Parse(URL)
	if err != nil {
		return nil, serrors.WrapStr("Error parsing URL", err)
	}

	caCert, err := ioutil.ReadFile(ca)
	if err != nil {
		return nil, serrors.WrapStr("Error loading CA", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	// load client cert
	crt, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, serrors.WrapStr("Error loading cert and key", err)
	}
	// prepare TLS
	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &crt, nil
		},
	}

	c := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	return &oneTimePadStore{
		url:        *baseURL,
		saeId:      saeID,
		httpClient: c,
	}, nil
}

var _ Store = (*oneTimePadStore)(nil)

func (s *oneTimePadStore) MySaeId() string {
	return s.saeId
}

func (s *oneTimePadStore) PrepareRequest(req *cppb.DRKeyLevel1Request) {
	req.SaeId = s.saeId // we would like to use QKD, if available
}

func (s *oneTimePadStore) ScrambleKey(req *cppb.DRKeyLevel1Request, key *drkey.Key) (string, error) {
	if len(req.SaeId) == 0 {
		return "", nil
	}
	keyPair, err := s.newQKDKey(req.SaeId)
	if err != nil {
		return "", serrors.WrapStr("Error obtaining QKD keys", err)
	}
	keyID := keyPair[0].KeyID
	keyBytes, err := base64.StdEncoding.DecodeString(keyPair[0].Key)
	if err != nil {
		return "", serrors.WrapStr("Error base64 decoding key", err)
	}

	// XOR the key with the one time pad
	len := min(len(keyBytes), len(*key))
	for i := 0; i < len; i++ {
		(*key)[i] ^= keyBytes[i]
	}
	return keyID, nil
}

func (s *oneTimePadStore) DescrambleKey(rep *cppb.DRKeyLevel1Response, L1Key *drkey.Level1Key) error {
	if len(rep.QkdKeyId) == 0 {
		return nil
	}
	key := &L1Key.Key

	keys, err := s.retrieveQKDKey(rep.SaeId, rep.QkdKeyId)
	if err != nil {
		return serrors.WrapStr("Error retrieving the QKD keys", err)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(keys[0].Key)
	if err != nil {
		return serrors.WrapStr("Error base64 decoding key", err)
	}
	// XOR the key with the one time pad
	len := min(len(keyBytes), len(*key))
	for i := 0; i < len; i++ {
		(*key)[i] ^= keyBytes[i]
	}
	L1Key.IsQKD = true

	return nil
}

// QkdKey represents a key returned by the KME API.
type QkdKey struct {
	KeyID string `json:"key_ID"`
	Key   string `json:"key"`
}

func deserializeKeys(b []byte) ([]QkdKey, error) {
	var keys struct {
		Keys []QkdKey `json:"keys"`
	}
	err := json.Unmarshal(b, &keys)
	return keys.Keys, err
}

func (s *oneTimePadStore) newQKDKey(saeId string) ([]QkdKey, error) {
	log.Debug("[DRKey ServiceStore QKD] Requesting new keys", "SaeID", saeId)
	url := s.joinToURL("api/v1/keys/%s/enc_keys", saeId)
	b, err := s.getBytes(url)
	if err != nil {
		return nil, err
	}
	return deserializeKeys(b)
}

// retrieveQKDKey gets a key from the KME, given the key ID. It needs the SAE ID of the master.
func (s *oneTimePadStore) retrieveQKDKey(saeId string, keyId string) ([]QkdKey, error) {
	log.Debug("[DRKey ServiceStore QKD] Retrieving quantum key as slave",
		"SaeID", saeId, "KeyID", keyId)
	url := s.joinToURL("api/v1/keys/%s/dec_keys", saeId)
	type KeyID struct {
		KeyID string `json:"key_ID"`
	}
	kIDs := struct {
		KeyIDs []KeyID `json:"key_IDs"`
	}{
		KeyIDs: []KeyID{
			{keyId},
		},
	}
	content, err := json.Marshal(kIDs)
	if err != nil {
		return nil, err
	}
	b, err := s.postBytes(url, content)
	if err != nil {
		return nil, err
	}
	return deserializeKeys(b)
}

func (s *oneTimePadStore) getBytes(url string) ([]byte, error) {
	res, err := s.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	return decodeResponse(res)
}

func (s *oneTimePadStore) postBytes(url string, posting []byte) ([]byte, error) {
	rdr := bytes.NewBuffer(posting)
	res, err := s.httpClient.Post(url, "application/json", rdr)
	if err != nil {
		return nil, err
	}
	return decodeResponse(res)
}

// joinToURL is a handy function that joins the path in p to the base URL contained in this store.
func (s *oneTimePadStore) joinToURL(format string, args ...any) string {
	return s.url.String() + "/" + fmt.Sprintf(format, args...)
}

func decodeResponse(res *http.Response) ([]byte, error) {
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return nil, errors.New(res.Status)
	}
	contentBA, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return contentBA, nil
}
