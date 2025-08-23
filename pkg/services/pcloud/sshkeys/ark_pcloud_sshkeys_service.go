package sshkeys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Kalybus/ark-sdk-golang/pkg/auth"
	"github.com/Kalybus/ark-sdk-golang/pkg/common"
	"github.com/Kalybus/ark-sdk-golang/pkg/common/isp"
	pcloudsshkeymodels "github.com/Kalybus/ark-sdk-golang/pkg/models/services/pcloud/sshkeys"
	"github.com/Kalybus/ark-sdk-golang/pkg/services"
	"github.com/golang-jwt/jwt/v5"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	// SSH key endpoint under PasswordVault API
	SSHKeyURL = "/api/users/secret/sshkeys/cache/"
)

// DefaultSSHFolderPath is the default folder path for SSH keys.
const (
	DefaultSSHFolderPath = "~/.ssh"
)

// PCloudSSHKeysServiceConfig is the configuration for the Privilege Cloud SSH Keys service.
var PCloudSSHKeysServiceConfig = services.ArkServiceConfig{
	ServiceName:                "pcloud-sshkeys",
	RequiredAuthenticatorNames: []string{"isp"},
	OptionalAuthenticatorNames: []string{},
}

// ArkPCloudSSHKeysService provides operations related to Privilege Cloud SSH Keys.
type ArkPCloudSSHKeysService struct {
	services.ArkService
	*services.ArkBaseService
	ispAuth *auth.ArkISPAuth
	client  *isp.ArkISPServiceClient
}

// NewArkPCloudSSHKeysService creates a new instance of ArkPCloudSSHKeysService.
func NewArkPCloudSSHKeysService(authenticators ...auth.ArkAuth) (*ArkPCloudSSHKeysService, error) {
	sshKeyService := &ArkPCloudSSHKeysService{}
	var sshServiceInterface services.ArkService = sshKeyService
	baseService, err := services.NewArkBaseService(sshServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.ArkISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "privilegecloud", ".", "passwordvault", sshKeyService.refreshPCloudSSHKeyAuth)
	if err != nil {
		return nil, err
	}
	sshKeyService.client = client
	sshKeyService.ispAuth = ispAuth
	sshKeyService.ArkBaseService = baseService
	return sshKeyService, nil
}

func (s *ArkPCloudSSHKeysService) refreshPCloudSSHKeyAuth(client *common.ArkClient) error {
	return isp.RefreshClient(client, s.ispAuth)
}

// fetchSSHKey fetches and returns the SSH key.
func (s *ArkPCloudSSHKeysService) fetchSSHKey(getSSHKey *pcloudsshkeymodels.ArkPCloudGetSSHKey) (*pcloudsshkeymodels.ArkPCloudSSHKeyResponse, error) {
	s.Logger.Info("Fetching SSH key from Privilege Cloud")
	ctx := context.Background()
	payload := map[string]interface{}{
		"formats": []string{getSSHKey.Format},
	}
	resp, err := s.client.Post(ctx, SSHKeyURL, payload)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch ssh key - [%d] - [%s]", resp.StatusCode, common.SerializeResponseToJSON(resp.Body))
	}
	var result pcloudsshkeymodels.ArkPCloudSSHKeyResponse
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if jsonErr := json.Unmarshal(data, &result); jsonErr != nil {
		return nil, jsonErr
	}
	return &result, nil
}

// extractFirstPrivateKey traverses the response to find the first available private key string.
func extractFirstPrivateKey(items []pcloudsshkeymodels.ArkPCloudSSHKeyItem) string {
	for _, it := range items {
		if it.PrivateKey != "" {
			return it.PrivateKey
		}
	}
	return ""
}

// SSHKey fetches the SSH private key and returns the first available private key string.
func (s *ArkPCloudSSHKeysService) SSHKey(getSSHKey *pcloudsshkeymodels.ArkPCloudGetSSHKey) (string, error) {
	parsed, err := s.fetchSSHKey(getSSHKey)
	if err != nil {
		return "", err
	}
	key := extractFirstPrivateKey(parsed.Value)
	if key == "" {
		return "", fmt.Errorf("no private key found in response")
	}
	return key, nil
}

// SSHKeyFile fetches the SSH key and writes it to a file. Returns the full path to the written file.
func (s *ArkPCloudSSHKeysService) SSHKeyFile(getSSHKeyFile *pcloudsshkeymodels.ArkPCloudGetSSHKeyFile) (string, error) {
	key, err := s.SSHKey(&getSSHKeyFile.ArkPCloudGetSSHKey)
	if err != nil {
		return "", err
	}
	folderPath := getSSHKeyFile.Folder
	if folderPath == "" {
		folderPath = DefaultSSHFolderPath
	}
	folderPath = common.ExpandFolder(folderPath)
	if folderPath == "" {
		return "", errors.New("folder parameter is required")
	}
	if _, err = os.Stat(folderPath); os.IsNotExist(err) {
		err = os.MkdirAll(folderPath, os.ModePerm)
		if err != nil {
			return "", err
		}
	}
	parsedToken, _, err := new(jwt.Parser).ParseUnverified(s.client.GetToken(), jwt.MapClaims{})
	if err != nil {
		return "", err
	}
	claims := parsedToken.Claims.(jwt.MapClaims)
	baseName := fmt.Sprintf("pcloud_ssh_key_%s.pem", strings.Split(claims["unique_name"].(string), "@")[0])
	fullPath := filepath.Join(folderPath, baseName)
	err = os.WriteFile(fullPath, []byte(key), 0600)
	if err != nil {
		return "", err
	}
	return fullPath, nil
}

// ServiceConfig returns the service configuration for the ArkPCloudSSHKeysService.
func (s *ArkPCloudSSHKeysService) ServiceConfig() services.ArkServiceConfig {
	return PCloudSSHKeysServiceConfig
}
