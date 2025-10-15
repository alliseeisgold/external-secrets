package iamtoken

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"

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

func (p *AuthorizedKeyIamTokenProvider) Create(ctx context.Context, apiEndpoint string, caCertificate []byte) (*IamToken, error) {
	tlsConfig, err := TlsConfig(caCertificate)
	if err != nil {
		return nil, err
	}

	creds, err := ycsdk.ServiceAccountKey(p.AuthorizedKey)
	if err != nil {
		return nil, err
	}

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

func (p *AuthorizedKeyIamTokenProvider) BuildIamTokenCacheKey() any {
	privateKeyHash := sha256.Sum256([]byte(p.AuthorizedKey.PrivateKey))
	return AuthorizedKeyAuthCacheKey{
		AuthorizedKeyID:  p.AuthorizedKey.GetId(),
		ServiceAccountID: p.AuthorizedKey.GetServiceAccountId(),
		PrivateKeyHash:   hex.EncodeToString(privateKeyHash[:]),
	}
}

func buildSDK(ctx context.Context, apiEndpoint string, creds ycsdk.Credentials, tlsConfig *tls.Config) (*ycsdk.SDK, error) {
	sdk, err := ycsdk.Build(ctx, ycsdk.Config{
		Credentials: creds,
		Endpoint:    apiEndpoint,
		TLSConfig:   tlsConfig,
	})
	if err != nil {
		return nil, err
	}

	return sdk, nil
}

func closeSDK(ctx context.Context, sdk *ycsdk.SDK) error {
	return sdk.Shutdown(ctx)
}

// чтобы не было циклической зависимости перенес сюда
func TlsConfig(caCertificate []byte) (*tls.Config, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caCertificate != nil {
		caCertPool := x509.NewCertPool()
		ok := caCertPool.AppendCertsFromPEM(caCertificate)
		if !ok {
			return nil, errors.New("unable to read trusted CA certificates")
		}
		tlsConfig.RootCAs = caCertPool
	}
	return tlsConfig, nil
}
