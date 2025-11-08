/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

// +kubebuilder:validation:MinProperties=1
// +kubebuilder:validation:MaxProperties=1
type YandexAuth struct {
	// The authorized key used for authentication
	// +optional
	AuthorizedKey *esmeta.SecretKeySelector `json:"authorizedKeySecretRef,omitempty"`

	// JWT authentication
	// +optional
	Jwt *Jwt `json:"jwt,omitempty"`

	// Instance Service Account authentication
	// +optional
	InstanceSA *InstanceSA `json:"instanceSA"`
}

type YandexCAProvider struct {
	Certificate esmeta.SecretKeySelector `json:"certSecretRef,omitempty"`
}

// ByID configures the provider to interpret the `data.secretKey.remoteRef.key` field in ExternalSecret as secret ID.
type ByID struct{}

// ByName configures the provider to interpret the `data.secretKey.remoteRef.key` field in ExternalSecret as secret name.
type ByName struct {
	// The folder to fetch secrets from
	FolderID string `json:"folderID"`
}

// +kubebuilder:validation:MinProperties=1
// +kubebuilder:validation:MaxProperties=1
type FetchingPolicy struct {
	ByID   *ByID   `json:"byID,omitempty"`
	ByName *ByName `json:"byName,omitempty"`
}

type Jwt struct {
	// Yandex Cloud service account ID
	IamServiceAccountID string `json:"iamServiceAccountID"`

	// Kubernetes service account reference
	ServiceAccountRef esmeta.ServiceAccountSelector `json:"serviceAccountRef"`

	// Endpoint for exchanging k8s service account token to Yandex IAM token
	// +optional
	TokenExchangeEndpoint string `json:"tokenExchangeEndpoint,omitempty"`
}

type InstanceSA struct {
}
