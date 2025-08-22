package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Iilun/survey/v2"
	"github.com/cyberark/ark-sdk-golang/pkg/common"
	"github.com/cyberark/ark-sdk-golang/pkg/common/args"
	"github.com/cyberark/ark-sdk-golang/pkg/models"
	"github.com/cyberark/ark-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/ark-sdk-golang/pkg/models/common"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

var (
	identityOauthApp = "__idaptive_cybr_user_oidc"
)

// ArkIdentityPKCE is a struct that represents identity authentication with PKCE flow.
type ArkIdentityPKCE struct {
	username            string
	oauthToken          *oauth2.Token
	tenantSubdomain     string
	logger              *common.ArkLogger
	keyring             *common.ArkKeyring
	cacheAuthentication bool
	session             *common.ArkClient
	sessionExp          commonmodels.ArkRFC3339Time
}

// NewArkIdentityPKCE creates a new instance of ArkIdentityPKCE.
func NewArkIdentityPKCE(username string, tenantSubdomain string, logger *common.ArkLogger, cacheAuthentication bool, loadCache bool, cacheProfile *models.ArkProfile) (*ArkIdentityPKCE, error) {
	identityPKCEAuth := &ArkIdentityPKCE{
		username:            username,
		tenantSubdomain:     tenantSubdomain,
		logger:              logger,
		cacheAuthentication: cacheAuthentication,
	}
	if tenantSubdomain == "" {
		return nil, fmt.Errorf("missing tenant subdomain")
	}
	identityURL, err := ResolveTenantFqdnFromTenantSubdomain(tenantSubdomain, commonmodels.GetDeployEnv())
	if err != nil {
		return nil, fmt.Errorf("missing identity url: %v", err)
	}
	identityPKCEAuth.session = common.NewArkClient(identityURL, "", "", "Authorization", nil, nil)
	if cacheAuthentication {
		identityPKCEAuth.keyring = common.NewArkKeyring(strings.ToLower("ArkIdentity"))
	}
	if loadCache && cacheAuthentication && cacheProfile != nil {
		identityPKCEAuth.loadCache(cacheProfile)
	}
	return identityPKCEAuth, nil
}

// loadCache Load cache data in the object
func (ai *ArkIdentityPKCE) loadCache(profile *models.ArkProfile) bool {
	if ai.keyring == nil || profile == nil {
		return false
	}
	token, err := ai.keyring.LoadToken(profile, ai.username+"_identity_pkce_oauth2", false)
	if err != nil {
		ai.logger.Error(fmt.Sprintf("Error loading token from cache: %v", err))
		return false
	}
	if token == nil {
		ai.logger.Error(fmt.Sprintf("Token not found in cache"))
		return false
	}
	session, err := ai.keyring.LoadToken(profile, ai.username+"_identity_pkce_session", false)
	if err != nil {
		ai.logger.Error(fmt.Sprintf("Error loading session from cache: %v", err))
		return false
	}
	if session == nil {
		ai.logger.Error(fmt.Sprintf("Session not found in cache"))
		return false
	}
	if token.Username != ai.username {
		ai.logger.Error(fmt.Sprintf("Username mismatch for token"))
		return false
	}

	// Load oauth2 token
	var oauthToken *oauth2.Token
	oauthToken, err = decodeToken(token.Token)
	if err != nil {
		ai.logger.Error("Fail to decode token: %v", err)
		return false
	}
	err = ai.UpdateToken(oauthToken)
	if err != nil {
		return false
	}

	// Load session headers and cookies
	headers, cookies, err := decodeSession(session.Token)
	if err != nil {
		ai.logger.Error("Fail to decode token: %v", err)
		return false
	}
	ai.session = common.NewArkClient(session.Endpoint, "", "", "Authorization", nil, nil)
	ai.session.SetHeaders(headers)
	ai.session.SetCookies(cookies)
	return true
}

// saveCache Save object data to the cache.
func (ai *ArkIdentityPKCE) saveCache(profile *models.ArkProfile) error {
	if ai.keyring != nil && profile != nil {
		// Save oauth2 token
		if ai.oauthToken != nil {
			encodedToken, err := encodeToken(ai.oauthToken)
			if err != nil {
				return fmt.Errorf("error encoding token: %v", err)
			}
			err = ai.keyring.SaveToken(profile, &auth.ArkToken{
				Token:      encodedToken,
				Username:   ai.username,
				Endpoint:   ai.session.BaseURL,
				TokenType:  auth.Internal,
				AuthMethod: auth.Other,
				ExpiresIn:  ai.sessionExp,
			}, ai.username+"_identity_pkce_oauth2", false)
			if err != nil {
				return err
			}
		}
		// Save session headers and cookies
		sessionInfo := map[string]interface{}{
			"headers": ai.session.GetHeaders(),
			"cookies": ai.session.GetCookies(),
		}
		sessionInfoBytes, err := json.Marshal(sessionInfo)
		if err != nil {
			return err
		}
		err = ai.keyring.SaveToken(profile, &auth.ArkToken{
			Token:      string(sessionInfoBytes),
			Username:   ai.username,
			Endpoint:   ai.session.BaseURL,
			TokenType:  auth.Internal,
			AuthMethod: auth.Other,
			ExpiresIn:  ai.sessionExp,
		}, ai.username+"_identity_pkce_session", false)
		if err != nil {
			return err
		}
	}
	return nil
}

func (ai *ArkIdentityPKCE) UpdateToken(oauth2Token *oauth2.Token) error {
	expirationTime, err := tokenExpiresAt(oauth2Token.AccessToken)
	if err != nil {
		ai.logger.Error(fmt.Sprintf("Error getting token expiration time: %v", err))
		return err
	}
	ai.oauthToken = oauth2Token
	ai.session.UpdateToken(ai.oauthToken.AccessToken, "Bearer")
	ai.sessionExp = commonmodels.ArkRFC3339Time(expirationTime)

	return nil
}

// AuthIdentity Authenticates to Identity with PKCE flow (https://oauth.net/2/pkce/)
func (ai *ArkIdentityPKCE) AuthIdentity(profile *models.ArkProfile, force bool) error {
	ai.logger.Info(fmt.Sprintf("Authenticating to identity on tenant [%s]", ai.tenantSubdomain))
	if ai.cacheAuthentication && !force && ai.loadCache(profile) {
		if time.Time(ai.sessionExp).After(time.Now()) {
			ai.logger.Info("Loaded identity identity user (PKCE) details from cache")
			return nil
		}
	}
	// Fetch OpenID configuration
	wellKnownUrl := fmt.Sprintf("/%s/.well-known/openid-configuration", identityOauthApp)
	// Create a new OAuth2 config
	oauth2Config, err := ai.NewOIDCConfig(wellKnownUrl)
	if err != nil {
		return err
	}
	// Generate new PKCE challenge
	verifier := oauth2.GenerateVerifier()
	authCodeUrl := oauth2Config.AuthCodeURL("",
		oauth2.AccessTypeOffline,
		oauth2.S256ChallengeOption(verifier),
	)

	// Generate PKCE challenge URL
	args.PrintNormal(fmt.Sprintf("Please open the following url in your browser: %s", authCodeUrl))
	loginResponse := &survey.Input{
		Message: "Paste the URL you're redirected to:",
	}
	// Wait for response URL
	var inputtedUrl string
	err = survey.AskOne(loginResponse, &inputtedUrl)
	if err != nil {
		return err
	}
	// Extract code from response URL
	var code string
	code, err = extractCodeFromURI(inputtedUrl)
	if err != nil {
		return err
	}
	// Exchange code for token
	oauth2Token, err := oauth2Config.Exchange(
		context.Background(),
		code,
		oauth2.VerifierOption(verifier),
	)
	if err != nil {
		return err
	}

	// Verify token's username matches the profile's username to prevent login with the wrong session
	tokenClaims, _, err := new(jwt.Parser).ParseUnverified(oauth2Token.AccessToken, jwt.MapClaims{})
	if err != nil {
		return err
	}
	username := tokenClaims.Claims.(jwt.MapClaims)["unique_name"].(string)
	if username != ai.username {
		return fmt.Errorf("usernames don't match: %s != %s", ai.username, username)
	}
	// Update ArkIdentity with new token data
	err = ai.UpdateToken(oauth2Token)
	if err != nil {
		return fmt.Errorf("error updating oauth2 token: %v", err)
	}
	ai.logger.Info(fmt.Sprintf("Created a user session (PKCE) on tenant [%s] with user [%s] to platform", ai.tenantSubdomain, ai.username))
	// Refresh the access token to get a proper platform token
	// The token obtained above is not authorized to perform API calls to the platform
	err = ai.RefreshAuthIdentity(profile, force)
	if err != nil {
		return fmt.Errorf("error refreshing the oauth token for a platform token: %v", err)
	}
	return nil
}

// RefreshAuthIdentity Performs a token refresh with the object's existing details.
func (ai *ArkIdentityPKCE) RefreshAuthIdentity(profile *models.ArkProfile, force bool) error {
	if ai.oauthToken == nil {
		return ai.AuthIdentity(profile, force)
	}

	ai.logger.Debug("Attempting to refresh authenticate to Identity (PKCE)")
	var savedCookies map[string]string
	if ai.session != nil {
		savedCookies = ai.session.GetCookies()
	}
	ai.session = common.NewArkClient(ai.session.BaseURL, "", "", "Authorization", nil, nil)
	ai.session.SetHeaders(DefaultHeaders())

	token, _, err := new(jwt.Parser).ParseUnverified(ai.SessionToken(), jwt.MapClaims{})
	if err != nil {
		return err
	}
	claims := token.Claims.(jwt.MapClaims)
	platformTenantID := claims["tenant_id"].(string)

	authCookies := map[string]string{
		fmt.Sprintf("refreshToken-%s", platformTenantID): ai.RefreshToken(),
		fmt.Sprintf("idToken-%s", platformTenantID):      ai.SessionToken(),
	}
	ai.session.SetCookies(authCookies)
	response, err := ai.session.Post(context.Background(), "OAuth2/RefreshPlatformToken", nil)
	if err != nil {
		ai.logger.Error("fail to refresh token: %v", err)
		return ai.AuthIdentity(profile, force)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			ai.logger.Warning("Error closing response body")
		}
	}(response.Body)

	if response.StatusCode != http.StatusOK {
		ai.logger.Error("failed to refresh token")
		return ai.AuthIdentity(profile, force)
	}

	var newSessionToken, newRefreshToken string
	for _, cookie := range response.Cookies() {
		if cookie.Name == fmt.Sprintf("idToken-%s", platformTenantID) {
			newSessionToken = cookie.Value
		}
		if cookie.Name == fmt.Sprintf("refreshToken-%s", platformTenantID) {
			newRefreshToken = cookie.Value
		}
	}
	if newSessionToken == "" || newRefreshToken == "" {
		ai.logger.Error("failed to retrieve refresh tokens cookies")
		return ai.AuthIdentity(profile, force)
	}
	if savedCookies != nil {
		ai.session.SetCookies(savedCookies)
	}
	lifetime, err := tokenLifetime(newSessionToken)
	if err != nil {
		return fmt.Errorf("failed to retrieve token's lifetime: %v", err)
	}
	refreshedToken := &oauth2.Token{
		AccessToken:  newSessionToken,
		RefreshToken: newRefreshToken,
		TokenType:    ai.oauthToken.TokenType,
		Expiry:       time.Unix(0, 0), // disables oauth2 builtin token refresh
		ExpiresIn:    lifetime,
	}
	err = ai.UpdateToken(refreshedToken)
	if err != nil {
		return fmt.Errorf("failed to update oauth2 token: %v", err)
	}

	if ai.cacheAuthentication {
		if err = ai.saveCache(profile); err != nil {
			return fmt.Errorf("error saving token to cache: %v", err)
		}
	}
	return nil
}

// Session returns the current identity session
func (ai *ArkIdentityPKCE) Session() *common.ArkClient {
	return ai.session
}

// SessionExpiration returns the token expiration time
func (ai *ArkIdentityPKCE) SessionExpiration() commonmodels.ArkRFC3339Time {
	return ai.sessionExp
}

// Token returns the oauth2 token if logged in
func (ai *ArkIdentityPKCE) Token() *oauth2.Token {
	return ai.oauthToken
}

// SessionToken returns the access token if logged in
func (ai *ArkIdentityPKCE) SessionToken() string {
	return ai.oauthToken.AccessToken
}

// RefreshToken returns the refresh token if logged in
func (ai *ArkIdentityPKCE) RefreshToken() string {
	return ai.oauthToken.RefreshToken
}

// IdentityURL returns the current identity URL
func (ai *ArkIdentityPKCE) IdentityURL() string {
	return ai.session.BaseURL
}

// OIDCMetadata represents a subset of the OpenID Connect discovery document.
type OIDCMetadata struct {
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	ResponseTypesSupported        []string `json:"response_types_supported,omitempty"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
}

// fetchOIDCMetadata downloads and parses the OpenId Connect discovery document.
func (ai *ArkIdentityPKCE) fetchOIDCMetadata(wellKnown string) (*OIDCMetadata, error) {
	resp, err := ai.session.Get(context.Background(), wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch well-known config: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP %d from %s", resp.StatusCode, wellKnown)
	}
	var metadata OIDCMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}
	return &metadata, nil
}

// NewOIDCConfig returns an oauth2 config
func (ai *ArkIdentityPKCE) NewOIDCConfig(wellKnownUrl string) (*oauth2.Config, error) {
	metadata, err := ai.fetchOIDCMetadata(wellKnownUrl)
	if err != nil {
		return nil, fmt.Errorf("error fetching OpenID configuration from %s: %v", wellKnownUrl, err)
	}
	if !slices.Contains(metadata.ResponseTypesSupported, "code") {
		return nil, fmt.Errorf("OpenID configuration does not support code as a response type %s", wellKnownUrl)
	}
	if !slices.Contains(metadata.CodeChallengeMethodsSupported, "S256") {
		return nil, fmt.Errorf("OpenID configuration does not support S256 as a code challenge method")
	}

	oidcConfig := &oauth2.Config{
		ClientID:     identityOauthApp,
		ClientSecret: "",
		Scopes:       []string{"openid"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  metadata.AuthorizationEndpoint,
			TokenURL: metadata.TokenEndpoint,
		},
		RedirectURL: fmt.Sprintf("https://%s.cyberark.cloud/shell/api/login", ai.tenantSubdomain),
	}
	return oidcConfig, nil
}

// extractCodeParam parses the given URL string and returns the "code" query parameter value.
func extractCodeFromURI(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		return "", fmt.Errorf("no 'code' parameter found")
	}
	return code, nil
}

// encodeToken serializes an oauth2.Token into a string.
func encodeToken(tok *oauth2.Token) (string, error) {
	b, err := json.Marshal(tok)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// decodeToken parses a string back into an oauth2.Token.
func decodeToken(s string) (*oauth2.Token, error) {
	var tok oauth2.Token
	if err := json.Unmarshal([]byte(s), &tok); err != nil {
		return nil, err
	}
	return &tok, nil
}

// decodeSession parses a string back into headers and cookies.
func decodeSession(s string) (map[string]string, map[string]string, error) {
	sessionInfo := map[string]interface{}{}
	err := json.Unmarshal([]byte(s), &sessionInfo)
	if err != nil {
		return nil, nil, err
	}
	headers := make(map[string]string)
	cookies := make(map[string]string)
	for k, v := range sessionInfo["headers"].(map[string]interface{}) {
		headers[k] = v.(string)
	}
	for k, v := range sessionInfo["cookies"].(map[string]interface{}) {
		cookies[k] = v.(string)
	}
	return headers, cookies, nil
}

// tokenExpiresAt returns the expiration time
func tokenExpiresAt(token string) (time.Time, error) {
	newTokenClaims, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return time.Unix(0, 0), err
	}
	newClaims := newTokenClaims.Claims.(jwt.MapClaims)
	exp := int64(newClaims["exp"].(float64))
	return time.Unix(exp, 0), nil
}

func tokenExpiresIn(token string) (int64, error) {
	at, err := tokenExpiresAt(token)
	if err != nil {
		return 0, err
	}
	seconds := time.Now().Sub(at).Seconds()
	return int64(seconds), nil
}

// tokenLifetime return the token's lifetime
func tokenLifetime(token string) (int64, error) {
	newTokenClaims, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return 0, err
	}
	newClaims := newTokenClaims.Claims.(jwt.MapClaims)
	exp := int64(newClaims["exp"].(float64))
	iat := int64(newClaims["iat"].(float64))
	delta := int(exp - iat)
	if delta == 0 {
		delta = DefaultTokenLifetimeSeconds
	}
	return int64(delta), nil
}
