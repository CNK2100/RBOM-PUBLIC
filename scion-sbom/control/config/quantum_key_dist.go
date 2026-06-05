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
	"io"
	"net/url"
	"os"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/config"
)

// QKDConfig holds the necessary crypto material to talk to the ID-Quantique HTTP API.
type QKDConfig struct {
	URL   string `toml:"url,omitempty"`
	SaeID string `toml:"sae_id,omitempty"`
	CA    string `toml:"ca,omitempty"`
	Cert  string `toml:"cert,omitempty"`
	Key   string `toml:"key,omitempty"`
}

var _ (config.Config) = (*QKDConfig)(nil)

// InitDefaults will set all strings to empty.
func (cfg *QKDConfig) InitDefaults() {}

// Validate validates that the file paths exist, if set.
func (cfg *QKDConfig) Validate() error {
	filePaths := make([]string, 0)
	if cfg.URL != "" {
		if cfg.SaeID == "" {
			return serrors.New("SAE ID is empty")
		}
		filePaths = append(filePaths, cfg.CA, cfg.Cert, cfg.Key)
		_, err := url.Parse(cfg.URL)
		if err != nil {
			return serrors.WrapStr("Invalid URL", err)
		}
	} else if cfg.SaeID != "" || cfg.CA != "" || cfg.Cert != "" || cfg.Key != "" {
		return serrors.New("URL is empty, but SAE ID or crypto material are configured")
	}
	for _, p := range filePaths {
		if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() {
			return serrors.New("Path doesn't exist or not a regular file", "path", p)
		}
	}
	return nil
}

// Sample writes a config sample to the writer.
func (cfg *QKDConfig) Sample(dst io.Writer, path config.Path, ctx config.CtxMap) {
	config.WriteString(dst, drkeyQKDConfigSample)
}

// ConfigName is the key in the toml file.
func (cfg *QKDConfig) ConfigName() string {
	return "qkd"
}
