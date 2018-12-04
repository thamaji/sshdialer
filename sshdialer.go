package sshdialer

import (
	"crypto/x509"
	"encoding/pem"
	"os/user"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

type Config struct {
	Host       string `json:"host" yaml:"host"`
	Port       int    `json:"port" yaml:"port"`
	Username   string `json:"username" yaml:"username"`
	Password   string `json:"password,omitempty" yaml:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty" yaml:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty" yaml:"passphrase,omitempty"`
}

func Dial(config *Config) (*ssh.Client, error) {
	username := config.Username
	if username == "" {
		u, err := user.Current()
		if err != nil {
			return nil, err
		}
		username = u.Username
	}

	conf := &ssh.ClientConfig{
		User:            username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	if config.Password != "" {
		conf.Auth = append(conf.Auth, ssh.Password(config.Password))
	}

	if config.PrivateKey != "" {
		block, _ := pem.Decode([]byte(config.PrivateKey))
		procType := strings.Split(block.Headers["Proc-Type"], ",")
		for i := range procType {
			if procType[i] != "ENCRYPTED" {
				continue
			}

			bytes, err := x509.DecryptPEMBlock(block, []byte(config.Passphrase))
			if err != nil {
				return nil, err
			}

			block.Bytes = bytes
			block.Headers["Proc-Type"] = strings.Join(append(procType[:i], procType[i+1:]...), ",")
			break
		}

		signer, err := ssh.ParsePrivateKey(pem.EncodeToMemory(block))
		if err != nil {
			return nil, err
		}

		conf.Auth = append(conf.Auth, ssh.PublicKeys(signer))
	}

	port := config.Port
	if port <= 0 {
		port = 22
	}

	address := config.Host + ":" + strconv.Itoa(port)

	return ssh.Dial("tcp", address, conf)
}
