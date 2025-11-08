package iamtokencreator

import (
	"context"

	"github.com/external-secrets/external-secrets/pkg/provider/yandex/common/sdk"
	ycsdk "github.com/yandex-cloud/go-sdk"
)

type InstanceServiceAccountIamTokenCreator struct{}

type instanceServiceAccountCacheKey struct{}

func (key instanceServiceAccountCacheKey) ToLoggableString() string {
	return "InstanceServiceAccount{}"
}

func (p *InstanceServiceAccountIamTokenCreator) Create(ctx context.Context, apiEndpoint string, caCertificate []byte) (*IamToken, error) {
	creds := ycsdk.InstanceServiceAccount()

	ycSDK, err := sdk.BuildSDK(ctx, apiEndpoint, creds, caCertificate)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = sdk.CloseSDK(ctx, ycSDK)
	}()

	iamToken, err := ycSDK.CreateIAMToken(ctx)
	if err != nil {
		return nil, err
	}
	return &IamToken{Token: iamToken.IamToken, ExpiresAt: iamToken.ExpiresAt.AsTime()}, nil
}

func (p *InstanceServiceAccountIamTokenCreator) BuildIamTokenCacheKey() CacheKey {
	return instanceServiceAccountCacheKey{}
}

func (p *InstanceServiceAccountIamTokenCreator) CheckAccess(ctx context.Context) error {
	return nil
}
