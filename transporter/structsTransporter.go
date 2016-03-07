package nessusTransporter

import (
	"golang.org/x/crypto/ssh"
)

// Transporter holds all information necessary to transport result files.
type Transporter struct {
	SSHKey       SSHKey
	SSHAuth      SSHAuth
	TargetHost   TargetHost
	WithSSHAgent bool
	Client       *ssh.Client
}

// SSHKey includes details necessary to locate SSH Keys used for a session.
type SSHKey struct {
	PathToFile  string
	KeyFilename string
}

// SSHAuth includes the details necessary to authenticate with a remote host
type SSHAuth struct {
	Username string
	password string
}

// TargetHost includes information about the remote host that result files
// should be retrieved by.
type TargetHost struct {
	Host string
	Port string
}
