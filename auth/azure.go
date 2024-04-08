// Copyright 2016 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"

	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"

	"github.com/flatcar/mantle/platform"
)

const (
	AzureAuthPath = ".azure/credentials.json"
)

// A version of the Options struct from platform/api/azure that only
// contains the ASM values. Otherwise there's a cyclical depdendence
// because platform/api/azure has to import auth to have access to
// the ReadAzureProfile function.
type Options struct {
	*platform.Options

	SubscriptionName string
	SubscriptionID   string

	// Azure API endpoint. If unset, the Azure SDK default will be used.
	ManagementURL         string
	ManagementCertificate []byte

	// Azure Storage API endpoint suffix. If unset, the Azure SDK default will be used.
	StorageEndpointSuffix string
}

type AzureCredentials struct {
	ClientID                       string `json:"clientId"`
	ClientSecret                   string `json:"clientSecret"`
	SubscriptionID                 string `json:"subscriptionId"`
	TenantID                       string `json:"tenantId"`
	ActiveDirectoryEndpointURL     string `json:"activeDirectoryEndpointUrl"`
	ResourceManagerEndpointURL     string `json:"resourceManagerEndpointUrl"`
	ActiveDirectoryGraphResourceID string `json:"activeDirectoryGraphResourceId"`
	SQLManagementEndpointURL       string `json:"sqlManagementEndpointUrl"`
	GalleryEndpointURL             string `json:"galleryEndpointUrl"`
	ManagementEndpointURL          string `json:"managementEndpointUrl"`
}

// ReadAzureCredentials decodes an Azure Subscription, as created by
// the Azure Cross-platform CLI.
//
// If path is empty, value of the environment variable
// AZURE_AUTH_LOCATION is read. If it is empty too, then
// $HOME/.azure/credentials.json is read.
func ReadAzureCredentials(path string) (*AzureCredentials, error) {
	if path == "" {
		path = os.Getenv("AZURE_AUTH_LOCATION")
	}
	contents, err := readBOMFile(path, AzureAuthPath)
	if err != nil {
		return nil, err
	}

	var ac AzureCredentials
	if err := json.Unmarshal(contents, &ac); err != nil {
		return nil, err
	}

	if ac.ClientID == "" || ac.ClientSecret == "" || ac.TenantID == "" || ac.SubscriptionID == "" {
		return nil, fmt.Errorf("Azure credentials %q are incomplete", path)
	}

	return &ac, nil
}

func readBOMFile(path, defaultFilename string) ([]byte, error) {
	if path == "" {
		user, err := user.Current()
		if err != nil {
			return nil, err
		}

		path = filepath.Join(user.HomeDir, defaultFilename)
	}

	return DecodeBOMFile(path)
}

func DecodeBOMFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	decoder := unicode.UTF8.NewDecoder()
	reader := transform.NewReader(f, unicode.BOMOverride(decoder))
	return ioutil.ReadAll(reader)
}
