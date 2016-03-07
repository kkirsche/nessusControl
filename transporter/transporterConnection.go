package nessusTransporter

import (
	"fmt"
	"github.com/kkirsche/go-scp"
)

// Connect creates an SSH Client which is used to transport Nessus result files
func (t *Transporter) Connect() error {
	if t.SSHKey.PathToFile == "" ||
		t.SSHKey.KeyFilename == "" {
		return fmt.Errorf("Cannot connect with empty SSH Key path or Filename")
	}
	sshKey := goScp.SshKeyfile{
		Path:     t.SSHKey.PathToFile,
		Filename: t.SSHKey.KeyFilename,
	}

	if t.SSHAuth.Username == "" ||
		t.SSHAuth.password == "" {
		return fmt.Errorf("Cannot connect with empty SSH username or password")
	}
	sshCredentials := goScp.SshCredentials{
		Username: t.SSHAuth.Username,
		Password: t.SSHAuth.password,
	}

	if t.TargetHost.Host == "" ||
		t.TargetHost.Port == "" {
		return fmt.Errorf("Cannot connect with empty target hostname or port")
	}
	targetHost := goScp.RemoteMachine{
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
