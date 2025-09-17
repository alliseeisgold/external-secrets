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

package common

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/yandex-cloud/go-sdk/iamkey"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	clock2 "github.com/external-secrets/external-secrets/pkg/provider/yandex/common/clock"
	"github.com/external-secrets/external-secrets/pkg/utils/resolvers"

	"k8s.io/client-go/kubernetes"
	ctrlcfg "sigs.k8s.io/controller-runtime/pkg/client/config"
)

const maxSecretsClientLifetime = 5 * time.Minute // supposed SecretsClient lifetime is quite short

// https://github.com/external-secrets/external-secrets/issues/644
var _ esv1.Provider = &YandexCloudProvider{}

// Implementation of v1beta1.Provider.
type YandexCloudProvider struct {
	logger              logr.Logger
	clock               clock2.Clock
	adaptInputFunc      AdaptInputFunc
	newSecretGetterFunc NewSecretGetterFunc
	newIamTokenFunc     NewIamTokenFunc

	secretGetteMap       map[string]SecretGetter // apiEndpoint -> SecretGetter
	secretGetterMapMutex sync.Mutex
	iamTokenMap          map[any]*IamToken // not type-safe!
	iamTokenMapMutex     sync.Mutex
	iamTokenProvider     IamTokenProvider
}

func InitYandexCloudProvider(
	logger logr.Logger,
	clock clock2.Clock,
	adaptInputFunc AdaptInputFunc,
	newSecretGetterFunc NewSecretGetterFunc,
	newIamTokenFunc NewIamTokenFunc,
	iamTokenCleanupDelay time.Duration,
) *YandexCloudProvider {

	provider := &YandexCloudProvider{
		logger:              logger,
		clock:               clock,
		adaptInputFunc:      adaptInputFunc,
		newSecretGetterFunc: newSecretGetterFunc,
		newIamTokenFunc:     newIamTokenFunc,
		secretGetteMap:      make(map[string]SecretGetter),
		iamTokenMap:         make(map[any]*IamToken),
	}

	if iamTokenCleanupDelay > 0 {
		go func() {
			for {
				time.Sleep(iamTokenCleanupDelay)
				provider.CleanUpIamTokenMap()
			}
		}()
	}

	return provider
}

type NewSecretSetterFunc func()
type AdaptInputFunc func(store esv1.GenericStore) (*SecretsClientInput, error)
type NewSecretGetterFunc func(ctx context.Context, apiEndpoint string, authorizedKey *iamkey.Key, caCertificate []byte) (SecretGetter, error)
type NewIamTokenFunc func(ctx context.Context, apiEndpoint string, authorizedKey *iamkey.Key, caCertificate []byte) (*IamToken, error)

type IamToken struct {
	Token     string
	ExpiresAt time.Time
}

type SecretsClientInput struct {
	APIEndpoint               string
	AuthorizedKey             *esmeta.SecretKeySelector
	YandexIamServiceAccountID string
	ServiceAccountRef         *esmeta.ServiceAccountSelector
	CACertificate             *esmeta.SecretKeySelector
	ResourceKeyType           ResourceKeyType
	FolderID                  string
}

type ResourceKeyType int

const (
	ResourceKeyTypeId   ResourceKeyType = iota
	ResourceKeyTypeName ResourceKeyType = iota
)

func (p *YandexCloudProvider) Capabilities() esv1.SecretStoreCapabilities {
	return esv1.SecretStoreReadOnly
}

// NewClient constructs a Yandex.Cloud Provider.
func (p *YandexCloudProvider) NewClient(ctx context.Context, store esv1.GenericStore, kube kclient.Client, namespace string) (esv1.SecretsClient, error) {
	input, err := p.adaptInputFunc(store)
	if err != nil {
		return nil, err
	}

	var authorizedKey *iamkey.Key
	if input.AuthorizedKey != nil {
		key, err := resolvers.SecretKeyRef(
			ctx,
			kube,
			store.GetKind(),
			namespace,
			input.AuthorizedKey,
		)
		if err != nil {
			return nil, err
		}

		authorizedKey = &iamkey.Key{}
		err = json.Unmarshal([]byte(key), authorizedKey)
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal authorized key: %w", err)
		}
	}

	var caCertificateData []byte
	if input.CACertificate != nil {
		caCert, err := resolvers.SecretKeyRef(
			ctx,
			kube,
			store.GetKind(),
			namespace,
			input.CACertificate,
		)
		if err != nil {
			return nil, err
		}
		caCertificateData = []byte(caCert)
	}

	// https://github.com/external-secrets/external-secrets/blob/a116df926276d985213f6049fec953576131a91b/pkg/provider/yandex/common/provider.go#L136
	iamTokenProvider, err := p.initializeIamTokenProvider(authorizedKey, input.YandexIamServiceAccountID, input.ServiceAccountRef, namespace)

	if err != nil {
		return nil, err
	}
	p.iamTokenProvider = iamTokenProvider

	secretGetter, err := p.getOrCreateSecretGetter(ctx, input.APIEndpoint, authorizedKey, caCertificateData)

	if err != nil {
		return nil, fmt.Errorf("failed to create Yandex.Cloud client: %w", err)
	}

	iamToken, err := p.getOrCreateIamToken(ctx, input.APIEndpoint, caCertificateData)
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM token: %w", err)
	}

	return &yandexCloudSecretsClient{secretGetter, nil, iamToken.Token, input.ResourceKeyType, input.FolderID}, nil
}

func (p *YandexCloudProvider) getOrCreateSecretGetter(ctx context.Context, apiEndpoint string, authorizedKey *iamkey.Key, caCertificate []byte) (SecretGetter, error) {
	p.secretGetterMapMutex.Lock()
	defer p.secretGetterMapMutex.Unlock()

	if _, ok := p.secretGetteMap[apiEndpoint]; !ok {
		p.logger.Info("creating SecretGetter", "apiEndpoint", apiEndpoint)
		secretGetter, err := p.newSecretGetterFunc(ctx, apiEndpoint, authorizedKey, caCertificate)
		if err != nil {
			return nil, err
		}
		p.secretGetteMap[apiEndpoint] = secretGetter
	}
	return p.secretGetteMap[apiEndpoint], nil
}

func (p *YandexCloudProvider) getOrCreateIamToken(ctx context.Context, apiEndpoint string, caCertificate []byte) (*IamToken, error) {
	p.iamTokenMapMutex.Lock()
	defer p.iamTokenMapMutex.Unlock()

	iamTokenKey := buildIamTokenKey(p.iamTokenProvider)
	if iamToken, ok := p.iamTokenMap[iamTokenKey]; !ok || !p.isIamTokenUsable(iamToken) {
		// тут не знал, что добавить в логах, поэтому просто добавил тип текущего провайдер
		p.logger.Info("creating IAM token via provider", "type", fmt.Sprintf("%T", p.iamTokenProvider))

		iamToken, err := p.iamTokenProvider.GetIamToken(ctx, apiEndpoint, caCertificate)
		if err != nil {
			return nil, err
		}

		p.logger.Info("created IAM token via provider", "type", fmt.Sprintf("%T", p.iamTokenProvider), "expiresAt", iamToken.ExpiresAt)

		p.iamTokenMap[iamTokenKey] = iamToken
	}
	return p.iamTokenMap[iamTokenKey], nil
}

func (p *YandexCloudProvider) isIamTokenUsable(iamToken *IamToken) bool {
	now := p.clock.CurrentTime()
	return now.Add(maxSecretsClientLifetime).Before(iamToken.ExpiresAt)
}

// Used for testing.
func (p *YandexCloudProvider) IsIamTokenCached(authorizedKey *iamkey.Key) bool {
	p.iamTokenMapMutex.Lock()
	defer p.iamTokenMapMutex.Unlock()

	iamTokenKey := buildIamTokenKey(p.iamTokenProvider)
	_, ok := p.iamTokenMap[iamTokenKey]
	return ok
}

func (p *YandexCloudProvider) CleanUpIamTokenMap() {
	p.iamTokenMapMutex.Lock()
	defer p.iamTokenMapMutex.Unlock()

	for key, value := range p.iamTokenMap {
		if p.clock.CurrentTime().After(value.ExpiresAt) {
			p.logger.Info("deleting IAM token", "key", key)
			delete(p.iamTokenMap, key)
		}
	}
}

func (p *YandexCloudProvider) ValidateStore(store esv1.GenericStore) (admission.Warnings, error) {
	_, err := p.adaptInputFunc(store) // adaptInputFunc validates the input store
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (p *YandexCloudProvider) initializeIamTokenProvider(authorizedKey *iamkey.Key, yandexIamServiceAccountId string, serviceAccountRef *esmeta.ServiceAccountSelector, namespace string) (IamTokenProvider, error) {
	var provider IamTokenProvider
	switch {
	case authorizedKey != nil:
		provider = &AuthorizedKeyAuthProvider{
			AuthorizedKey:   authorizedKey,
			NewIamTokenFunc: p.newIamTokenFunc,
		}
	case yandexIamServiceAccountId != "" && serviceAccountRef != nil:
		// этот блок в vault провайдере инициализируется в NewClient. https://github.com/external-secrets/external-secrets/blob/main/pkg/provider/vault/provider.go#L92
		// UPD: по сути это инциализируется в NewClient
		config, err := ctrlcfg.GetConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to get any Kubernetes config: %w", err)
		}

		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			return nil, err
		}
		// https://github.com/external-secrets/external-secrets/blob/a116df926276d985213f6049fec953576131a91b/pkg/provider/yandex/common/provider.go#L136
		ns := &namespace
		if serviceAccountRef.Namespace != nil {
			ns = serviceAccountRef.Namespace
		}
		provider = &WlifAuthProvider{
			YandexIamServiceAccountID: yandexIamServiceAccountId,
			ServiceAccountName:        serviceAccountRef.Name,
			Namespace:                 ns,
			Audiences:                 serviceAccountRef.Audiences,
			clock:                     p.clock,
			logger:                    p.logger,
			corev1:                    clientset.CoreV1(),
		}
		// на уровне кубернетиса должна ошибку выдать
		// default:
		// 	return nil, errors.New("invalid Yandex Lockbox SecretStore: requires either 'authorizedKey' or 'jwt'")
	}
	return provider, nil
}
