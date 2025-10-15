package iamtoken

import (
	"context"

	ycsdk "github.com/yandex-cloud/go-sdk"
)

type InstanceServiceAccountAuthProvider struct{}

func (p *InstanceServiceAccountAuthProvider) Create(ctx context.Context, apiEndpoint string, caCertificate []byte) (*IamToken, error) {
	tlsConfig, err := TlsConfig(caCertificate)
	if err != nil {
		return nil, err
	}

	creds := ycsdk.InstanceServiceAccount()

	sdk, err := buildSDK(ctx, apiEndpoint, creds, tlsConfig)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = closeSDK(ctx, sdk)
	}()

	iamToken, err := sdk.CreateIAMToken(ctx)
	if err != nil {
		return nil, err
	}
	return &IamToken{Token: iamToken.IamToken, ExpiresAt: iamToken.ExpiresAt.AsTime()}, nil
}

func (p *InstanceServiceAccountAuthProvider) BuildIamTokenCacheKey() any {
	return InstanceServiceAccountAuthProvider{}
}
