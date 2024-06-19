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
	"bytes"
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
	AzureAuthPath    = ".azure/credentials.json"
	AzureProfilePath = ".azure/azureProfile.json"
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

type AzureEnvironment struct {
	ActiveDirectoryEndpointURL                        string `json:"activeDirectoryEndpointUrl"`
	ActiveDirectoryGraphAPIVersion                    string `json:"activeDirectoryGraphApiVersion"`
	ActiveDirectoryGraphResourceID                    string `json:"activeDirectoryGraphResourceId"`
	ActiveDirectoryResourceID                         string `json:"activeDirectoryResourceId"`
	AzureDataLakeAnalyticsCatalogAndJobEndpointSuffix string `json:"azureDataLakeAnalyticsCatalogAndJobEndpointSuffix"`
	AzureDataLakeStoreFileSystemEndpointSuffix        string `json:"azureDataLakeStoreFileSystemEndpointSuffix"`
	GalleryEndpointURL                                string `json:"galleryEndpointUrl"`
	KeyVaultDNSSuffix                                 string `json:"keyVaultDnsSuffix"`
	ManagementEndpointURL                             string `json:"managementEndpointUrl"`
	Name                                              string `json:"name"`
	PortalURL                                         string `json:"portalUrl"`
	PublishingProfileURL                              string `json:"publishingProfileUrl"`
	ResourceManagerEndpointURL                        string `json:"resourceManagerEndpointUrl"`
	SqlManagementEndpointURL                          string `json:"sqlManagementEndpointUrl"`
	SqlServerHostnameSuffix                           string `json:"sqlServerHostnameSuffix"`
	StorageEndpointSuffix                             string `json:"storageEndpointSuffix"`
}

type AzureManagementCertificate struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

type AzureSubscription struct {
	EnvironmentName       string                     `json:"environmentName"`
	ID                    string                     `json:"id"`
	IsDefault             bool                       `json:"isDefault"`
	ManagementCertificate AzureManagementCertificate `json:"managementCertificate"`
	ManagementEndpointURL string                     `json:"managementEndpointUrl"`
	Name                  string                     `json:"name"`
	RegisteredProviders   []string                   `json:"registeredProviders"`
	State                 string                     `json:"state"`
}

// AzureProfile represents a parsed Azure Profile Configuration File.
type AzureProfile struct {
	Environments  []AzureEnvironment  `json:"environments"`
	Subscriptions []AzureSubscription `json:"subscriptions"`
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

// AsOptions converts all subscriptions into a slice of Options.
// If there is an environment with a name matching the subscription, that environment's storage endpoint will be copied to the options.
func (ap *AzureProfile) AsOptions() []Options {
	var o []Options

	for _, sub := range ap.Subscriptions {
		var cert []byte
		if len(sub.ManagementCertificate.Key) > 0 || len(sub.ManagementCertificate.Cert) > 0 {
			cert = bytes.Join([][]byte{[]byte(sub.ManagementCertificate.Key), []byte(sub.ManagementCertificate.Cert)}, []byte("\n"))
		}
		newo := Options{
			SubscriptionName:      sub.Name,
			SubscriptionID:        sub.ID,
			ManagementURL:         sub.ManagementEndpointURL,
			ManagementCertificate: cert,
		}

		// find the storage endpoint for the subscription
		for _, e := range ap.Environments {
			if e.Name == sub.EnvironmentName {
				newo.StorageEndpointSuffix = e.StorageEndpointSuffix
				break
			}
		}

		o = append(o, newo)
	}

	return o
}

type SubFilter struct {
	name string
	id   string
}

func FilterByName(name string) SubFilter {
	return SubFilter{name: name}
}
func FilterByID(id string) SubFilter {
	return SubFilter{id: id}
}
func (s *SubFilter) IsEmpty() bool {
	return s.name == "" && s.id == ""
}
func (s *SubFilter) Matches(opts *Options) bool {
	if s.name != "" && opts.SubscriptionName == s.name {
		return true
	}
	if s.id != "" && opts.SubscriptionID == s.id {
		return true
	}
	return false
}

// SubscriptionOptions returns the name subscription in the Azure profile as a Options struct.
// If the subscription name is "", the first subscription is returned.
// If there are no subscriptions or the named subscription is not found, SubscriptionOptions returns nil.
func (ap *AzureProfile) SubscriptionOptions(filter SubFilter) *Options {
	opts := ap.AsOptions()

	if len(opts) == 0 {
		return nil
	}

	if filter.IsEmpty() {
		return &opts[0]
	} else {
		for _, o := range ap.AsOptions() {
			if filter.Matches(&o) {
				return &o
			}
		}
	}

	return nil
}

// ReadAzureSubscription decodes an Azure Subscription, as created by
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

// ReadAzureProfile decodes an Azure Profile, as created by the Azure Cross-platform CLI.
//
// If path is empty, $HOME/.azure/azureProfile.json is read.
func ReadAzureProfile(path string) (*AzureProfile, error) {
	contents, err := readBOMFile(path, AzureProfilePath)
	if err != nil {
		return nil, err
	}

	var ap AzureProfile
	if err := json.Unmarshal(contents, &ap); err != nil {
		return nil, err
	}

	if len(ap.Subscriptions) == 0 {
		return nil, fmt.Errorf("Azure profile %q contains no subscriptions", path)
	}

	return &ap, nil
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
