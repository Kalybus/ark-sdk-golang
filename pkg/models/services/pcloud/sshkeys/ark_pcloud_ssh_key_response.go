package sshkeys

// ArkPCloudSSHKeyResponse models the JSON response for the SSH key endpoint.
type ArkPCloudSSHKeyResponse struct {
	Count          int                   `json:"count" mapstructure:"count"`
	CreationTime   int                   `json:"creationTime" mapstructure:"creation_time"`
	ExpirationTime int                   `json:"expirationTime" mapstructure:"expiration_time"`
	PublicKey      string                `json:"publicKey" mapstructure:"public_key"`
	Value          []ArkPCloudSSHKeyItem `json:"value" mapstructure:"value"`
}

// ArkPCloudSSHKeyItem represents a private key entry. The nested Value allows representing multiple key variants.
type ArkPCloudSSHKeyItem struct {
	Format     string                `json:"format" mapstructure:"format"`
	KeyAlg     string                `json:"keyAlg" mapstructure:"key_alg"`
	PrivateKey string                `json:"privateKey" mapstructure:"private_key"`
	Value      []ArkPCloudSSHKeyItem `json:"value,omitempty" mapstructure:"value"`
}
