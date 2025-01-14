// Copyright 2018 CoreOS, Inc.
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

package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2021-02-01/network"

	"github.com/flatcar/mantle/util"
)

var (
	virtualNetworkPrefix = []string{"10.0.0.0/16"}
	subnetPrefix         = "10.0.0.0/24"
	kolaSubnet           = "kola-subnet"
	kolaVnet             = "kola-vn"
)

func (a *API) PrepareNetworkResources(resourceGroup string) (Network, error) {
	if a.Opts.VnetSubnetName != "" {
		parts := strings.SplitN(a.Opts.VnetSubnetName, "/", 2)
		vnetName := parts[0]
		subnetName := "default"
		if len(parts) > 1 {
			subnetName = parts[1]
		}
		result, err := a.netClient.ListAllComplete(context.TODO())
		if err != nil {
			return Network{}, fmt.Errorf("failed to query vnets: %w", err)
		}
		var net network.VirtualNetwork
		found := false
		for result.NotDone() {
			net = result.Value()
			if net.Name != nil && *net.Name == vnetName {
				found = true
				break
			}
			err = result.Next()
			if err != nil {
				return Network{}, fmt.Errorf("failed to iterate vnets: %w", err)
			}
		}
		if !found {
			return Network{}, fmt.Errorf("failed to find vnet %s", vnetName)
		}
		subnets := net.VirtualNetworkPropertiesFormat.Subnets
		if subnets == nil {
			return Network{}, fmt.Errorf("failed to find subnet %s in vnet %s", subnetName, vnetName)
		}
		for _, subnet := range *subnets {
			if subnet.Name != nil && *subnet.Name == subnetName {
				return Network{subnet}, nil
			}
		}
		return Network{}, fmt.Errorf("failed to find subnet %s in vnet %s", subnetName, vnetName)
	}

	if err := a.createVirtualNetwork(resourceGroup); err != nil {
		return Network{}, err
	}

	subnet, err := a.createSubnet(resourceGroup)
	if err != nil {
		return Network{}, err
	}
	return Network{subnet}, nil
}

func (a *API) createVirtualNetwork(resourceGroup string) error {
	plog.Infof("Creating VirtualNetwork %s", kolaVnet)
	future, err := a.netClient.CreateOrUpdate(context.TODO(), resourceGroup, kolaVnet, network.VirtualNetwork{
		Location: &a.Opts.Location,
		VirtualNetworkPropertiesFormat: &network.VirtualNetworkPropertiesFormat{
			AddressSpace: &network.AddressSpace{
				AddressPrefixes: &virtualNetworkPrefix,
			},
		},
	})
	if err != nil {
		return err
	}
	err = future.WaitForCompletionRef(context.TODO(), a.netClient.Client)
	if err != nil {
		return err
	}
	_, err = future.Result(a.netClient)
	return err
}

func (a *API) createSubnet(resourceGroup string) (network.Subnet, error) {
	plog.Infof("Creating Subnet %s", kolaSubnet)
	future, err := a.subClient.CreateOrUpdate(context.TODO(), resourceGroup, kolaVnet, kolaSubnet, network.Subnet{
		SubnetPropertiesFormat: &network.SubnetPropertiesFormat{
			AddressPrefix: &subnetPrefix,
		},
	})
	if err != nil {
		return network.Subnet{}, err
	}
	err = future.WaitForCompletionRef(context.TODO(), a.subClient.Client)
	if err != nil {
		return network.Subnet{}, err
	}
	return future.Result(a.subClient)
}

func (a *API) getSubnet(resourceGroup, vnet, subnet string) (network.Subnet, error) {
	return a.subClient.Get(context.TODO(), resourceGroup, vnet, subnet, "")
}

func (a *API) createPublicIP(resourceGroup string) (*network.PublicIPAddress, error) {
	name := randomName("ip")
	plog.Infof("Creating PublicIP %s", name)

	future, err := a.ipClient.CreateOrUpdate(context.TODO(), resourceGroup, name, network.PublicIPAddress{
		Location: &a.Opts.Location,
		PublicIPAddressPropertiesFormat: &network.PublicIPAddressPropertiesFormat{
			DeleteOption: network.DeleteOptionsDelete,
		},
	})
	if err != nil {
		return nil, err
	}
	err = future.WaitForCompletionRef(context.TODO(), a.ipClient.Client)
	if err != nil {
		return nil, err
	}
	ip, err := future.Result(a.ipClient)
	if err != nil {
		return nil, err
	}
	ip.PublicIPAddressPropertiesFormat = &network.PublicIPAddressPropertiesFormat{
		DeleteOption: network.DeleteOptionsDelete,
	}
	return &ip, nil
}

func (a *API) getPublicIP(name, resourceGroup string) (string, error) {
	ip, err := a.ipClient.Get(context.TODO(), resourceGroup, name, "")
	if err != nil {
		return "", err
	}

	if ip.PublicIPAddressPropertiesFormat.IPAddress == nil {
		return "", fmt.Errorf("IP Address is nil")
	}

	return *ip.PublicIPAddressPropertiesFormat.IPAddress, nil
}

// returns PublicIP, PrivateIP, error
func (a *API) GetIPAddresses(name, publicIPName, resourceGroup string) (string, string, error) {
	nic, err := a.intClient.Get(context.TODO(), resourceGroup, name, "")
	if err != nil {
		return "", "", err
	}
	configs := *nic.InterfacePropertiesFormat.IPConfigurations
	var privateIP *string
	for _, conf := range configs {
		if conf.PrivateIPAddress == nil {
			return "", "", fmt.Errorf("PrivateIPAddress is nil")
		}
		privateIP = conf.PrivateIPAddress
		break
	}
	if privateIP == nil {
		return "", "", fmt.Errorf("no ip configurations found")
	}
	if publicIPName == "" {
		return *privateIP, *privateIP, nil
	}

	publicIP, err := a.getPublicIP(publicIPName, resourceGroup)
	if err != nil {
		return "", "", err
	}
	return publicIP, *privateIP, nil
}

func (a *API) GetPrivateIP(name, resourceGroup string) (string, error) {
	nic, err := a.intClient.Get(context.TODO(), resourceGroup, name, "")
	if err != nil {
		return "", err
	}

	configs := *nic.InterfacePropertiesFormat.IPConfigurations
	return *configs[0].PrivateIPAddress, nil
}

func (a *API) createNIC(ip *network.PublicIPAddress, subnet *network.Subnet, resourceGroup string) (*network.Interface, error) {
	name := randomName("nic")
	ipconf := randomName("nic-ipconf")
	plog.Infof("Creating NIC %s", name)

	future, err := a.intClient.CreateOrUpdate(context.TODO(), resourceGroup, name, network.Interface{
		Location: &a.Opts.Location,
		InterfacePropertiesFormat: &network.InterfacePropertiesFormat{
			IPConfigurations: &[]network.InterfaceIPConfiguration{
				{
					Name: &ipconf,
					InterfaceIPConfigurationPropertiesFormat: &network.InterfaceIPConfigurationPropertiesFormat{
						PublicIPAddress:           ip,
						PrivateIPAllocationMethod: network.IPAllocationMethodDynamic,
						Subnet:                    subnet,
					},
				},
			},
			EnableAcceleratedNetworking: util.BoolToPtr(true),
		},
	})
	if err != nil {
		return nil, err
	}
	err = future.WaitForCompletionRef(context.TODO(), a.intClient.Client)
	if err != nil {
		return nil, err
	}
	nic, err := future.Result(a.intClient)
	if err != nil {
		return nil, err
	}
	return &nic, nil
}
