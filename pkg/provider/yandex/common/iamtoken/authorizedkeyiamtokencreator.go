package iamtoken

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/external-secrets/external-secrets/pkg/provider/yandex/common/config"
	ycsdk "github.com/yandex-cloud/go-sdk"
	"github.com/yandex-cloud/go-sdk/iamkey"
)

type AuthorizedKeyIamTokenProvider struct {
	AuthorizedKey *iamkey.Key
}

// написал с заглавными буквами, чтобы в полях
type AuthorizedKeyAuthCacheKey struct {
	AuthorizedKeyID  string
	ServiceAccountID string
	PrivateKeyHash   string
}

func (key AuthorizedKeyAuthCacheKey) ToString() string {
	return fmt.Sprintf("AuthorizedKey{ID:%s, IamSA:%s, PrivateKeyHash:%s...}",
		key.AuthorizedKeyID,
		key.ServiceAccountID,
		key.PrivateKeyHash[:16])
}

func (p *AuthorizedKeyIamTokenProvider) Create(ctx context.Context, apiEndpoint string, caCertificate []byte) (*IamToken, error) {
	creds, err := ycsdk.ServiceAccountKey(p.AuthorizedKey)
	if err != nil {
		return nil, err
	}

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

func (p *AuthorizedKeyIamTokenProvider) BuildIamTokenCacheKey() CacheKey {
	privateKeyHash := sha256.Sum256([]byte(p.AuthorizedKey.PrivateKey))
	return AuthorizedKeyAuthCacheKey{
		AuthorizedKeyID:  p.AuthorizedKey.GetId(),
		ServiceAccountID: p.AuthorizedKey.GetServiceAccountId(),
		PrivateKeyHash:   hex.EncodeToString(privateKeyHash[:]),
	}
}

func (p *AuthorizedKeyIamTokenProvider) CheckAccess(ctx context.Context) error {
	return nil // we don't need to check access because privatekeyhash is unique
}
