package sshkeys

// ArkPCloudGetSSHKey is a struct that represents the request for getting the SSH key from the Ark Privilege Cloud SSH Key service.
type ArkPCloudGetSSHKey struct {
	Format string `json:"format" mapstructure:"format" flag:"format" validate:"oneof=PPK PEM OPENSSH" desc:"Formats of the key (allowed: PEM, PPK, OPENSSH)" default:"PEM"`
}
