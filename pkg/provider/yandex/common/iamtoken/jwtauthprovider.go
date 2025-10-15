package iamtoken

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

type JwtAuthIamTokenProvider struct {
	YandexIamServiceAccountID string
	ServiceAccountName        string
	Namespace                 *string
	Audiences                 []string
	TokenUrl                  string

	Logger logr.Logger
	Clock  clock.Clock
	Corev1 typedcorev1.CoreV1Interface
}

type JwtAuthCacheKey struct {
	IamServiceAccountID       string
	K8sServiceAccountName     string
	Namespace                 string
	NewlineSeparatedAudiences string
}

func (p *JwtAuthIamTokenProvider) Create(ctx context.Context, apiEndpoint string, caCertificate []byte) (*IamToken, error) {
	k8sToken, err := p.СreateTokenForServiceAccount(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("failed to get K8S token: %w", err)
	}

	response, err := p.exchangeK8sTokenForYandexIamToken(ctx, k8sToken)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}

	expiresAt := p.Clock.CurrentTime().Add(time.Duration(response["expires_in"].(float64)) * time.Second)

	return &IamToken{
		Token:     response["access_token"].(string),
		ExpiresAt: expiresAt,
	}, nil
}

func (p *JwtAuthIamTokenProvider) BuildIamTokenCacheKey() any {
	audiences := ""
	if len(p.Audiences) > 0 {
		normalizedAudiences := make([]string, 0, len(p.Audiences))
		for _, aud := range p.Audiences {
			normalized := strings.Replace(aud, "\n", "\\n", -1) // qwe\nrty -> qwe\\nrty
			normalizedAudiences = append(normalizedAudiences, normalized)
		}
		audiences = strings.Join(normalizedAudiences, "\n")
	}

	return JwtAuthCacheKey{
		IamServiceAccountID:       p.YandexIamServiceAccountID,
		K8sServiceAccountName:     p.ServiceAccountName,
		Namespace:                 *p.Namespace,
		NewlineSeparatedAudiences: audiences,
	}
}

// creates token for k8s service account
func (p *JwtAuthIamTokenProvider) СreateTokenForServiceAccount(ctx context.Context, jwtAuthConfig *JwtAuthIamTokenProvider) (string, error) {
	tokenRequest := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences: jwtAuthConfig.Audiences,
		},
	}

	tokenResponse, err := p.Corev1.ServiceAccounts(*jwtAuthConfig.Namespace).
		CreateToken(ctx, jwtAuthConfig.ServiceAccountName, tokenRequest, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}

	return tokenResponse.Status.Token, nil
}

func (p *JwtAuthIamTokenProvider) exchangeK8sTokenForYandexIamToken(ctx context.Context, k8sToken string) (map[string]interface{}, error) {
	requestBody := fmt.Sprintf(
		"grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=%s&subject_token_type=urn:ietf:params:oauth:token-type:id_token&requested_token_type=urn:ietf:params:oauth:token-type:access_token&audience=%s",
		url.QueryEscape(k8sToken),
		url.QueryEscape(p.YandexIamServiceAccountID),
	)

	tokenUrl := "https://auth.yandex.cloud/oauth/token"
	if p.TokenUrl != "" {
		tokenUrl = p.TokenUrl
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenUrl, strings.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// наверное лучше инициализировать HTTP-клиент при создании провайдера и использовать его повторно
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	p.Logger.Info("Successfully exchanged K8S token for Yandex IAM token",
		"cloudSA", p.YandexIamServiceAccountID,
		"expiresIn", tokenResp["expires_in"])

	return tokenResp, nil
}
