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
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	clock2 "github.com/external-secrets/external-secrets/pkg/provider/yandex/common/clock"
	"github.com/external-secrets/external-secrets/pkg/provider/yandex/common/iamtoken"
	"github.com/external-secrets/external-secrets/pkg/utils/resolvers"
)

const maxSecretsClientLifetime = 5 * time.Minute // supposed SecretsClient lifetime is quite short

// https://github.com/external-secrets/external-secrets/issues/644
var _ esv1.Provider = &YandexCloudProvider{}

// Implementation of v1beta1.Provider.
type YandexCloudProvider struct {
	logger                 logr.Logger
	clock                  clock2.Clock
	adaptInputFunc         AdaptInputFunc
	newSecretGetterFunc    NewSecretGetterFunc
	newIamTokenCreatorFunc NewIamTokenCreatorFunc

	secretGetteMap       map[string]SecretGetter // apiEndpoint -> SecretGetter
	secretGetterMapMutex sync.Mutex
	iamTokenMap          map[any]*iamtoken.IamToken // any of two structs: authorizedKeyAuthCacheKey or jwtAuthCacheKey can be used as a key
	iamTokenMapMutex     sync.Mutex
}

func InitYandexCloudProvider(
	logger logr.Logger,
	clock clock2.Clock,
	adaptInputFunc AdaptInputFunc,
	newSecretGetterFunc NewSecretGetterFunc,
	newIamTokenCreatorFunc NewIamTokenCreatorFunc,
	iamTokenCleanupDelay time.Duration,
) *YandexCloudProvider {

	provider := &YandexCloudProvider{
		logger:                 logger,
		clock:                  clock,
		adaptInputFunc:         adaptInputFunc,
		newSecretGetterFunc:    newSecretGetterFunc,
		newIamTokenCreatorFunc: newIamTokenCreatorFunc,
		secretGetteMap:         make(map[string]SecretGetter),
		iamTokenMap:            make(map[any]*iamtoken.IamToken),
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
type NewIamTokenCreatorFunc func(ctx context.Context, kube kclient.Client, store esv1.GenericStore, namespace string, auth *esv1.YandexAuth, logger logr.Logger, clock clock2.Clock) (iamtoken.IamTokenCreator, error)
type NewSecretGetterFunc func(ctx context.Context, apiEndpoint string, caCertificate []byte) (SecretGetter, error)

type SecretsClientInput struct {
	APIEndpoint    string
	Auth           *esv1.YandexAuth
	CAProvider     *esv1.YandexCAProvider
	FetchingPolicy *esv1.FetchingPolicy
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

	var caCertificate *esmeta.SecretKeySelector
	if input.CAProvider != nil {
		caCertificate = &input.CAProvider.Certificate
	}

	var caCertificateData []byte
	if caCertificate != nil {
		caCert, err := resolvers.SecretKeyRef(
			ctx,
			kube,
			store.GetKind(),
			namespace,
			caCertificate,
		)
		if err != nil {
			return nil, err
		}
		caCertificateData = []byte(caCert)
	}

	// чтобы в логах писать какой именно провайдер используется, но можно в целом убрать
	provider := "YandexLockbox"
	if store.GetSpec().Provider.YandexCertificateManager != nil {
		provider = "YandexCertificateManager"
	}

	var resourceKeyType ResourceKeyType
	var folderID string
	policy := input.FetchingPolicy
	if policy != nil {
		switch {
		case policy.ByName != nil:
			if policy.ByName.FolderID == "" {
				return nil, fmt.Errorf("folderID is required when fetching policy is 'byName'")
			}
			resourceKeyType = ResourceKeyTypeName
			folderID = policy.ByName.FolderID

		case policy.ByID != nil:
			resourceKeyType = ResourceKeyTypeId

		default:
			return nil, fmt.Errorf("invalid %s SecretStore: requires either 'byName' or 'byID' policy", provider)
		}
	}

	iamTokenCreator, err := p.newIamTokenCreatorFunc(ctx, kube, store, namespace, input.Auth, p.logger, p.clock)
	if err != nil {
		return nil, err
	}

	secretGetter, err := p.getOrCreateSecretGetter(ctx, input.APIEndpoint, caCertificateData)

	if err != nil {
		return nil, fmt.Errorf("failed to create Yandex.Cloud client: %w", err)
	}

	iamToken, err := p.getOrCreateIamToken(ctx, input.APIEndpoint, caCertificateData, iamTokenCreator)
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM token: %w", err)
	}

	return &yandexCloudSecretsClient{secretGetter, nil, iamToken.Token, resourceKeyType, folderID}, nil
}

func (p *YandexCloudProvider) getOrCreateSecretGetter(ctx context.Context, apiEndpoint string, caCertificate []byte) (SecretGetter, error) {
	p.secretGetterMapMutex.Lock()
	defer p.secretGetterMapMutex.Unlock()

	if _, ok := p.secretGetteMap[apiEndpoint]; !ok {
		p.logger.Info("creating SecretGetter", "apiEndpoint", apiEndpoint)
		secretGetter, err := p.newSecretGetterFunc(ctx, apiEndpoint, caCertificate)
		if err != nil {
			return nil, err
		}
		p.secretGetteMap[apiEndpoint] = secretGetter
	}
	return p.secretGetteMap[apiEndpoint], nil
}

func (p *YandexCloudProvider) getOrCreateIamToken(ctx context.Context, apiEndpoint string, caCertificate []byte, iamTokenCreator iamtoken.IamTokenCreator) (*iamtoken.IamToken, error) {
	// есть потенциальная race condition: между проверкой доступа и получением токена из кеша другая горутина может положить токен в кеш??
	if jwtProvider, ok := iamTokenCreator.(*iamtoken.JwtAuthIamTokenProvider); ok {
		_, err := jwtProvider.СreateTokenForServiceAccount(ctx, jwtProvider)
		if err != nil {
			return nil, fmt.Errorf("access denied: cannot create token for service account %s in namespace %s: %w",
				jwtProvider.ServiceAccountName,
				*jwtProvider.Namespace,
				err)
		}
	}
	p.iamTokenMapMutex.Lock()
	defer p.iamTokenMapMutex.Unlock()

	iamTokenCacheKey := iamTokenCreator.BuildIamTokenCacheKey()
	if iamToken, ok := p.iamTokenMap[iamTokenCacheKey]; !ok || !p.isIamTokenUsable(iamToken) {
		p.logger.Info("creating IAM token via cache-key", "cacheKey", iamTokenCacheKey)
		iamToken, err := iamTokenCreator.Create(ctx, apiEndpoint, caCertificate)
		if err != nil {
			return nil, err
		}

		p.logger.Info("created IAM token via cache-key", "cacheKey", iamTokenCacheKey, "expiresAt", iamToken.ExpiresAt)

		p.iamTokenMap[iamTokenCacheKey] = iamToken
	}
	return p.iamTokenMap[iamTokenCacheKey], nil
}

func (p *YandexCloudProvider) isIamTokenUsable(iamToken *iamtoken.IamToken) bool {
	now := p.clock.CurrentTime()
	return now.Add(maxSecretsClientLifetime).Before(iamToken.ExpiresAt)
}

// Used for testing.
func (p *YandexCloudProvider) IsIamTokenCached(iamTokenCreator iamtoken.IamTokenCreator) bool { // в самих тестах исправляю в отдельном PR-е с новыми юнит тестами
	p.iamTokenMapMutex.Lock()
	defer p.iamTokenMapMutex.Unlock()

	iamTokenCacheKey := iamTokenCreator.BuildIamTokenCacheKey()
	_, ok := p.iamTokenMap[iamTokenCacheKey]
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
