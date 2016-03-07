package nessusTransporter

import (
	"fmt"
	"github.com/kkirsche/go-scp"
)

// Connect creates an SSH Client which is used to transport Nessus result files
func (t *Transporter) Connect() error {
	if t.WithSSHAgent && (t.SSHAuth.Username == "" || t.SSHAuth.password == "") {
		return fmt.Errorf("Cannot connect with empty SSH username or password")
	}

	if t.SSHKey.PathToFile == "" || t.SSHKey.KeyFilename == "" {
		return fmt.Errorf("Cannot connect with empty SSH Key path or Filename")
	}

	sshCredentials := goScp.SSHCredentials{
		Username: t.SSHAuth.Username,
		Password: t.SSHAuth.password,
	}

	sshKey := goScp.SSHKeyfile{
		Path:     t.SSHKey.PathToFile,
		Filename: t.SSHKey.KeyFilename,
	}

	if t.TargetHost.Host == "" || t.TargetHost.Port == "" {
		return fmt.Errorf("Cannot connect with empty target hostname or port")
	}
	targetHost := goScp.RemoteHost{
		Host: t.TargetHost.Host,
		Port: t.TargetHost.Port,
	}

	sshClient, err := goScp.Connect(sshKey, sshCredentials, targetHost, t.WithSSHAgent)
	if err != nil {
		return err
	}

	t.Client = sshClient

	return nil
}
