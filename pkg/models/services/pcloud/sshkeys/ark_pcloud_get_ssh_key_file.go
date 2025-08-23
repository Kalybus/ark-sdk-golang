package sshkeys

// ArkPCloudGetSSHKeyFile represents the request for getting the SSH key from the Ark Privilege Cloud SSH Key service.
type ArkPCloudGetSSHKeyFile struct {
	ArkPCloudGetSSHKey
	Folder string `json:"folder" mapstructure:"folder" flag:"folder" desc:"Output folder to write the ssh key to" default:"~/.ssh"`
}
