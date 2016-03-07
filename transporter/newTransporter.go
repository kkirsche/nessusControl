package nessusTransporter

// NewTransporter returns an instance of the Transporter structure
func NewTransporter(sshKey SSHKey, auth SSHAuth, targetHost TargetHost,
	withSSHAgent bool) *Transporter {
	return &Transporter{
		SSHKey:       sshKey,
		SSHAuth:      auth,
		TargetHost:   targetHost,
		WithSSHAgent: withSSHAgent,
	}
}

// NewSSHKey returns a SSHKey instance for use by the transporter
func NewSSHKey(pathToKeyFile, keyFilename string) SSHKey {
	return SSHKey{
		PathToFile:  pathToKeyFile,
		KeyFilename: keyFilename,
	}
}

// NewSSHAuth returns an SSHAuth instance for use by the transporter
func NewSSHAuth(username, password string) SSHAuth {
	return SSHAuth{
		Username: username,
		password: password, // Private for safety
	}
}

// NewTargetHost returns a target host instance for use by the transporter
func NewTargetHost(hostname, port string) TargetHost {
	return TargetHost{
		Host: hostname,
		Port: port,
	}
}
