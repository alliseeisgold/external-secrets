package iamtokencreator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/external-secrets/external-secrets/pkg/provider/yandex/common/clock"
	"github.com/go-logr/logr"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

type JwtIamTokenCreator struct {
	IamServiceAccountID   string
	K8sServiceAccountName string
	Namespace             *string
	Audiences             []string
	TokenExchangeEndpoint string

	Logger logr.Logger
	Clock  clock.Clock
	Corev1 typedcorev1.CoreV1Interface
}

type JwtCacheKey struct {
	IamServiceAccountID       string
	K8sServiceAccountName     string
	Namespace                 string
	NewlineSeparatedAudiences string
}

func (key JwtCacheKey) ToLoggableString() string {
	return fmt.Sprintf("Jwt{IamSA:%s, K8sSA:%s, Namespace:%s, Audiences:%s}",
		key.IamServiceAccountID,
		key.K8sServiceAccountName,
		key.Namespace,
		strings.ReplaceAll(key.NewlineSeparatedAudiences, "\n", "; "))
}

func (p *JwtIamTokenCreator) Create(ctx context.Context, apiEndpoint string, caCertificate []byte) (*IamToken, error) {
	jwt, err := p.CreateTokenForServiceAccount(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWT for k8s service account: %w", err)
	}

	response, err := p.exchangeJwtForYandexIamToken(ctx, jwt)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange JWT to IAM token: %w", err)
	}

	expiresAt := p.Clock.CurrentTime().Add(time.Duration(response.ExpiresIn) * time.Second)

	return &IamToken{
		Token:     response.AccessToken,
		ExpiresAt: expiresAt,
	}, nil
}

func (p *JwtIamTokenCreator) BuildIamTokenCacheKey() CacheKey {
	return JwtCacheKey{
		IamServiceAccountID:       p.IamServiceAccountID,
		K8sServiceAccountName:     p.K8sServiceAccountName,
		Namespace:                 *p.Namespace,
		NewlineSeparatedAudiences: strings.Join(p.Audiences, "\n"),
	}
}

func (p *JwtIamTokenCreator) CheckAccess(ctx context.Context) error {
	_, err := p.CreateTokenForServiceAccount(ctx, p)
	if err != nil {
		return fmt.Errorf("cannot create token for service account %s in namespace %s: %w", p.K8sServiceAccountName, *p.Namespace, err)
	}
	return nil
}

func (p *JwtIamTokenCreator) CreateTokenForServiceAccount(ctx context.Context, jwtAuthConfig *JwtIamTokenCreator) (string, error) {
	tokenRequest := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences: jwtAuthConfig.Audiences,
		},
	}

	tokenResponse, err := p.Corev1.ServiceAccounts(*jwtAuthConfig.Namespace).
		CreateToken(ctx, jwtAuthConfig.K8sServiceAccountName, tokenRequest, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create token: %w", err)
	}

	return tokenResponse.Status.Token, nil
}

type tokenExchangeResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func (p *JwtIamTokenCreator) exchangeJwtForYandexIamToken(ctx context.Context, jwt string) (*tokenExchangeResponse, error) {
	requestBody := fmt.Sprintf(
		"grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=%s&subject_token_type=urn:ietf:params:oauth:token-type:id_token&requested_token_type=urn:ietf:params:oauth:token-type:access_token&audience=%s",
		url.QueryEscape(jwt),
		url.QueryEscape(p.IamServiceAccountID),
	)

	tokenExchangeURL := fmt.Sprintf("https://%s/oauth/token", p.TokenExchangeEndpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenExchangeURL, strings.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create token exchange request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var response tokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	p.Logger.Info("Successfully exchanged JWT for IAM token",
		"IamSA", p.IamServiceAccountID,
		"expiresIn", response.ExpiresIn)

	return &response, nil
}
