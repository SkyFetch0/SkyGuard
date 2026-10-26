package honeypot

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/skyguard/skyguard/internal/config"
)

// SSHHoneypot is a real SSH-2 server (golang.org/x/crypto/ssh) that completes
// key exchange, captures every password / keyboard-interactive attempt and
// rejects all of them. A hand-rolled plaintext imitation cannot work: real
// clients only send credentials after the encrypted key exchange.
type SSHHoneypot struct {
	cfg         config.HoneypotService
	eventLogger *EventLogger
	logger      *slog.Logger
	hostKeys    []ssh.Signer
}

const sshSessionTimeout = 60 * time.Second

var errAuthDenied = errors.New("permission denied")

// NewSSHHoneypot creates an SSHHoneypot. Host keys are loaded from (or
// generated into) dataDir so the server fingerprint stays stable across
// restarts — a changing key is an easy honeypot tell.
func NewSSHHoneypot(cfg config.HoneypotService, eventLogger *EventLogger, logger *slog.Logger, dataDir string) (*SSHHoneypot, error) {
	if cfg.Banner == "" {
		cfg.Banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
	}
	if cfg.MaxAuthAttempts <= 0 {
		cfg.MaxAuthAttempts = 3
	}
	if cfg.FakeShell {
		logger.Warn("fake_shell is not implemented and is ignored; the SSH honeypot never grants a session")
	}
	keys, err := loadOrCreateHostKeys(dataDir, logger)
	if err != nil {
		return nil, fmt.Errorf("ssh honeypot host keys: %w", err)
	}
	return &SSHHoneypot{cfg: cfg, eventLogger: eventLogger, logger: logger, hostKeys: keys}, nil
}

// Type implements Handler.
func (s *SSHHoneypot) Type() string { return "ssh" }

// Handle implements Handler.
func (s *SSHHoneypot) Handle(conn net.Conn, sess Session) error {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(sshSessionTimeout))

	var (
		mu       sync.Mutex
		attempts int
		client   string
		users    = map[string]bool{}
		methods  = map[string]bool{}
	)
	note := func(meta ssh.ConnMetadata, method string) {
		mu.Lock()
		defer mu.Unlock()
		client = string(meta.ClientVersion())
		users[meta.User()] = true
		methods[method] = true
	}
	capture := func(meta ssh.ConnMetadata, password string) {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		s.logger.Info("ssh credential attempt", "source_ip", sess.IP, "user", meta.User(), "attempt", n)
		s.eventLogger.LogCredential(sess, meta.User(), password, "ssh")
		// A short delay mimics real sshd and slows brute-forcers down.
		time.Sleep(300 * time.Millisecond)
	}

	cfg := &ssh.ServerConfig{
		ServerVersion: s.cfg.Banner,
		MaxAuthTries:  s.cfg.MaxAuthAttempts,
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			note(meta, "password")
			capture(meta, string(password))
			return nil, errAuthDenied
		},
		KeyboardInteractiveCallback: func(meta ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			note(meta, "keyboard-interactive")
			answers, err := challenge("", "", []string{"Password: "}, []bool{false})
			if err == nil && len(answers) == 1 {
				capture(meta, answers[0])
			}
			return nil, errAuthDenied
		},
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			note(meta, "publickey:"+key.Type())
			return nil, errAuthDenied
		},
	}
	for _, k := range s.hostKeys {
		cfg.AddHostKey(k)
	}

	_, _, _, err := ssh.NewServerConn(conn, cfg)
	if err == nil {
		// Unreachable: every callback rejects. Never let a session through.
		return errors.New("ssh honeypot: unexpected successful authentication")
	}

	mu.Lock()
	data := fmt.Sprintf("client=%q attempts=%d users=%v methods=%v", client, attempts, keys(users), keys(methods))
	mu.Unlock()
	s.eventLogger.LogConnection(sess, "ssh", data)
	return nil
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// loadOrCreateHostKeys returns an ed25519 and an RSA host key, persisted as
// OpenSSH private keys under dataDir. If dataDir is not writable the keys
// are kept in memory only.
func loadOrCreateHostKeys(dataDir string, logger *slog.Logger) ([]ssh.Signer, error) {
	specs := []struct {
		file string
		gen  func() (any, error)
	}{
		{"ssh_honeypot_ed25519_key", func() (any, error) {
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			return priv, err
		}},
		{"ssh_honeypot_rsa_key", func() (any, error) {
			return rsa.GenerateKey(rand.Reader, 3072)
		}},
	}

	var signers []ssh.Signer
	for _, spec := range specs {
		path := filepath.Join(dataDir, spec.file)
		if b, err := os.ReadFile(path); err == nil {
			signer, err := ssh.ParsePrivateKey(b)
			if err != nil {
				return nil, fmt.Errorf("parsing %s: %w", path, err)
			}
			signers = append(signers, signer)
			continue
		}

		key, err := spec.gen()
		if err != nil {
			return nil, err
		}
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			return nil, err
		}
		signers = append(signers, signer)

		block, err := ssh.MarshalPrivateKey(key, "skyguard honeypot")
		if err != nil {
			return nil, err
		}
		if dataDir == "" {
			continue
		}
		if err := os.MkdirAll(dataDir, 0o750); err == nil {
			err = os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
		}
		if err != nil {
			logger.Warn("could not persist ssh honeypot host key; fingerprint will change on restart",
				"path", path, "error", err)
		}
	}
	return signers, nil
}
