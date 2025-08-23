package pcloud

import (
	"github.com/Kalybus/ark-sdk-golang/pkg/auth"
	"github.com/Kalybus/ark-sdk-golang/pkg/services/pcloud/accounts"
	"github.com/Kalybus/ark-sdk-golang/pkg/services/pcloud/safes"
	"github.com/Kalybus/ark-sdk-golang/pkg/services/pcloud/sshkeys"
)

// ArkPCloudAPI is a struct that provides access to the Ark PCloud API as a wrapped set of services.
type ArkPCloudAPI struct {
	safesService    *safes.ArkPCloudSafesService
	accountsService *accounts.ArkPCloudAccountsService
	sshKeysService  *sshkeys.ArkPCloudSSHKeysService
}

// NewArkPCloudAPI creates a new instance of ArkPCloudAPI with the provided ArkISPAuth.
func NewArkPCloudAPI(ispAuth *auth.ArkISPAuth) (*ArkPCloudAPI, error) {
	var baseIspAuth auth.ArkAuth = ispAuth
	safesService, err := safes.NewArkPCloudSafesService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	accountsService, err := accounts.NewArkPCloudAccountsService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	sshKeysService, err := sshkeys.NewArkPCloudSSHKeysService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	return &ArkPCloudAPI{
		safesService:    safesService,
		accountsService: accountsService,
		sshKeysService:  sshKeysService,
	}, nil
}

// Safes returns the Safes service of the ArkPCloudAPI instance.
func (api *ArkPCloudAPI) Safes() *safes.ArkPCloudSafesService {
	return api.safesService
}

// Accounts returns the Accounts service of the ArkPCloudAPI instance.
func (api *ArkPCloudAPI) Accounts() *accounts.ArkPCloudAccountsService {
	return api.accountsService
}

// SSHKeys returns the SSH Keys service of the ArkPCloudAPI instance.
func (api *ArkPCloudAPI) SSHKeys() *sshkeys.ArkPCloudSSHKeysService {
	return api.sshKeysService
}
