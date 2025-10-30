package iamtoken

import (
	"context"

	"github.com/external-secrets/external-secrets/pkg/provider/yandex/common/config"
	ycsdk "github.com/yandex-cloud/go-sdk"
)

type InstanceServiceAccountAuthProvider struct{}

type instanceServiceAccountAuthCacheKey struct{}

func (key instanceServiceAccountAuthCacheKey) ToString() string {
	return "instance-service-account"
}

func (p *InstanceServiceAccountAuthProvider) Create(ctx context.Context, apiEndpoint string, caCertificate []byte) (*IamToken, error) {
	creds := ycsdk.InstanceServiceAccount()

	sdk, err := config.BuildSDK(ctx, apiEndpoint, creds, caCertificate)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = config.CloseSDK(ctx, sdk)
	}()

	iamToken, err := sdk.CreateIAMToken(ctx)
	if err != nil {
		return nil, err
	}
	return &IamToken{Token: iamToken.IamToken, ExpiresAt: iamToken.ExpiresAt.AsTime()}, nil
}

func (p *InstanceServiceAccountAuthProvider) BuildIamTokenCacheKey() CacheKey {
	return instanceServiceAccountAuthCacheKey{}
}

func (p *InstanceServiceAccountAuthProvider) CheckAccess(ctx context.Context) error {
	return nil
}
