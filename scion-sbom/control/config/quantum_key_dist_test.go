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

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestQKDConfigDefaults(t *testing.T) {
	var cfg QKDConfig
	cfg.InitDefaults()
	if cfg.URL != "" {
		t.Errorf("URL should be empty but is %s", cfg.URL)
	}
	if cfg.CA != "" {
		t.Errorf("CA should be empty but is %s", cfg.CA)
	}
	if cfg.Cert != "" {
		t.Errorf("Cert should be empty but is %s", cfg.Cert)
	}
	if cfg.Key != "" {
		t.Errorf("Key should be empty but is %s", cfg.Key)
	}
}

func TestQKDValidation(t *testing.T) {
	var cfg QKDConfig

	assert.NoError(t, cfg.Validate())

	cfg.URL = "https://machine/api"
	assert.Error(t, cfg.Validate(), "Expected validation error but got none")

	cfg.SaeID = "mySAEID"
	assert.Error(t, cfg.Validate(), "Expected validation error but got none")
	filename := tempFile(t)

	cfg.CA = filename
	assert.Error(t, cfg.Validate(), "Expected validation error but got none")
	cfg.Cert = filename
	assert.Error(t, cfg.Validate(), "Expected validation error but got none")
	cfg.Key = filename
	assert.NoError(t, cfg.Validate())

	saneConfig := cfg
	// Now start with a sane configuration and start provoking errors.
	var err error

	cfg.URL = ""
	err = cfg.Validate()
	assert.Error(t, err, "expected validation error but got none")

	cfg.SaeID = ""
	err = cfg.Validate()
	assert.Error(t, err, "expected validation error but got none")

	cfg = saneConfig
	cfg.URL = "http>://machine/api"
	err = cfg.Validate()
	assert.Error(t, err, "expected validation error but got none")

	cfg = saneConfig
	cfg.CA = "invalid"
	err = cfg.Validate()
	assert.Error(t, err, "expected validation error but got none")

	cfg = saneConfig
	cfg.Cert = "invalid"
	err = cfg.Validate()
	assert.Error(t, err, "expected validation error but got none")

	cfg = saneConfig
	cfg.Key = "invalid"
	err = cfg.Validate()
	assert.Error(t, err, "expected validation error but got none")
}
