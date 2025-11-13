package iamtokencreator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/external-secrets/external-secrets/pkg/provider/yandex/common/sdk"
	ycsdk "github.com/yandex-cloud/go-sdk"
	"github.com/yandex-cloud/go-sdk/iamkey"
)

type AuthorizedKeyIamTokenCreator struct {
	AuthorizedKey *iamkey.Key
}

type AuthorizedKeyCacheKey struct {
	AuthorizedKeyID     string
	IamServiceAccountID string
	PrivateKeyHash      string
}

func (key AuthorizedKeyCacheKey) ToLoggableString() string {
	return fmt.Sprintf("AuthorizedKey{AuthorizedKeyID:%s, IamSA:%s, PrivateKeyHash:%s...}",
		key.AuthorizedKeyID,
		key.IamServiceAccountID,
		key.PrivateKeyHash)
}

func (p *AuthorizedKeyIamTokenCreator) Create(ctx context.Context, apiEndpoint string, caCertificate []byte) (*IamToken, error) {
	creds, err := ycsdk.ServiceAccountKey(p.AuthorizedKey)
	if err != nil {
		return nil, err
	}

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

func (p *AuthorizedKeyIamTokenCreator) BuildIamTokenCacheKey() CacheKey {
	privateKeyHash := sha256.Sum256([]byte(p.AuthorizedKey.PrivateKey))
	return AuthorizedKeyCacheKey{
		AuthorizedKeyID:     p.AuthorizedKey.GetId(),
		IamServiceAccountID: p.AuthorizedKey.GetServiceAccountId(),
		PrivateKeyHash:      hex.EncodeToString(privateKeyHash[:]),
	}
}

// Access does not need to be verified because it is indirectly verified when requesting a secret containing the SA key
func (p *AuthorizedKeyIamTokenCreator) CheckAccess(ctx context.Context) error {
	return nil
}
