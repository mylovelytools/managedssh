package sshclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

const defaultDialTimeout = 10 * time.Second

var knownHostsMu sync.Mutex

// VerifyConfig holds SSH verification connection inputs.
type VerifyConfig struct {
	Host          string
	Port          int
	DialTimeout   time.Duration
	User          string
	Password      []byte
	KeyPath       string
	KeyData       []byte
	KeyPassphrase []byte
}

// UnknownHostError indicates a host key was not yet trusted.
type UnknownHostError struct {
	Host           string
	Address        string
	KeyType        string
	Fingerprint    string
	KnownHostsLine string
}

// KeyPassphraseRequiredError indicates a key is encrypted but no passphrase was provided.
type KeyPassphraseRequiredError struct{}

func (e *KeyPassphraseRequiredError) Error() string {
	return "SSH key requires a passphrase"
}

func (e *UnknownHostError) Error() string {
	return fmt.Sprintf("unknown host key for %s (%s)", e.Host, e.Fingerprint)
}

// Session implements bubbletea.ExecCommand so it can be handed
// the terminal via tea.Exec while the SSH session is active.
type Session struct {
	Host          string
	Port          int
	DialTimeout   time.Duration
	User          string
	Password      []byte
	KeyPath       string
	KeyData       []byte
	KeyPassphrase []byte

	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

func (s *Session) SetStdin(r io.Reader)  { s.stdin = r }
func (s *Session) SetStdout(w io.Writer) { s.stdout = w }
func (s *Session) SetStderr(w io.Writer) { s.stderr = w }

// Run executes the SSH session with a background context.
func (s *Session) Run() error {
	return s.RunWithContext(context.Background())
}

// RunWithContext executes the SSH session and honors context cancellation.
func (s *Session) RunWithContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	dialCtx, cancel := withDefaultTimeout(ctx, s.DialTimeout)
	defer cancel()

	defer s.zeroPassword()
	defer s.zeroKeyData()
	defer s.zeroKeyPassphrase()

	authMethods, err := buildAuthMethods(s.Password, s.KeyPath, s.KeyData, s.KeyPassphrase)
	if err != nil {
		return fmt.Errorf("build auth methods: %w", err)
	}
	defer closeAuthResources(authMethods)

	hostKeyCallback, err := buildVerifyHostKeyCallback()
	if err != nil {
		return fmt.Errorf("known_hosts setup failed: %w", err)
	}

	config := &ssh.ClientConfig{
		User:            s.User,
		Auth:            flattenAuthMethods(authMethods),
		HostKeyCallback: hostKeyCallback,
	}

	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	if _, err := fmt.Fprintf(s.stdout, "Connecting to %s@%s ...\r\n", s.User, addr); err != nil {
		return fmt.Errorf("write connect banner: %w", err)
	}

	client, err := dialSSHClientWithContext(dialCtx, addr, config)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("session failed: %w", err)
	}
	defer session.Close()

	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("terminal setup failed: %w", err)
	}
	defer term.Restore(fd, oldState)

	w, h, _ := term.GetSize(fd)
	if w == 0 {
		w = 80
	}
	if h == 0 {
		h = 24
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", h, w, modes); err != nil {
		return fmt.Errorf("PTY request failed: %w", err)
	}

	session.Stdin = s.stdin
	session.Stdout = s.stdout
	session.Stderr = s.stderr

	if err := session.Shell(); err != nil {
		return fmt.Errorf("shell failed: %w", err)
	}

	sigCh := make(chan os.Signal, 1)
	sigDone := make(chan struct{})
	signal.Notify(sigCh, syscall.SIGWINCH)
	go func() {
		for {
			select {
			case <-sigDone:
				return
			case <-sigCh:
				if nw, nh, err := term.GetSize(fd); err == nil {
					_ = session.WindowChange(nh, nw)
				}
			}
		}
	}()
	defer func() {
		signal.Stop(sigCh)
		close(sigDone)
	}()

	waitErrCh := make(chan error, 1)
	go func() {
		waitErrCh <- session.Wait()
	}()

	select {
	case <-ctx.Done():
		if err := client.Close(); err != nil {
			return fmt.Errorf("close SSH client after cancellation: %w", err)
		}
		return fmt.Errorf("session canceled: %w", ctx.Err())
	case err := <-waitErrCh:
		if err != nil {
			return fmt.Errorf("wait for SSH session: %w", err)
		}
		return nil
	}
}

func (s *Session) zeroPassword() {
	for i := range s.Password {
		s.Password[i] = 0
	}
	s.Password = nil
}

func (s *Session) zeroKeyData() {
	for i := range s.KeyData {
		s.KeyData[i] = 0
	}
	s.KeyData = nil
}

func (s *Session) zeroKeyPassphrase() {
	for i := range s.KeyPassphrase {
		s.KeyPassphrase[i] = 0
	}
	s.KeyPassphrase = nil
}

// buildHostKeyCallback loads ~/.ssh/known_hosts for host key verification.
// If the file doesn't exist yet it is created so future connections are
// verified (trust-on-first-use will be handled by the ssh library's error
// reporting — the user sees a clear error and can add the key manually).
func buildHostKeyCallback() (ssh.HostKeyCallback, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve user home directory: %w", err)
	}
	khPath := filepath.Join(home, ".ssh", "known_hosts")
	if _, err := os.Stat(khPath); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(khPath), 0700); err != nil {
			return nil, fmt.Errorf("create known_hosts directory: %w", err)
		}
		if err := os.WriteFile(khPath, nil, 0600); err != nil {
			return nil, fmt.Errorf("create known_hosts file: %w", err)
		}
	}
	cb, err := knownhosts.New(khPath)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts callback: %w", err)
	}
	return cb, nil
}

func buildVerifyHostKeyCallback() (ssh.HostKeyCallback, error) {
	base, err := buildHostKeyCallback()
	if err != nil {
		return nil, err
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if err := base(hostname, remote, key); err != nil {
			var keyErr *knownhosts.KeyError
			if errors.As(err, &keyErr) && len(keyErr.Want) == 0 {
				return &UnknownHostError{
					Host:           stripKnownHostPort(hostname),
					Address:        hostname,
					KeyType:        key.Type(),
					Fingerprint:    ssh.FingerprintSHA256(key),
					KnownHostsLine: knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key),
				}
			}
			return err
		}
		return nil
	}, nil
}

func dialAgent() (ssh.AuthMethod, net.Conn) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, nil
	}
	return ssh.PublicKeysCallback(agent.NewClient(conn).Signers), conn
}

type authWithCleanup struct {
	method ssh.AuthMethod
	conn   net.Conn
}

func buildAuthMethods(password []byte, keyPath string, keyData []byte, keyPassphrase []byte) ([]authWithCleanup, error) {
	var authMethods []authWithCleanup

	if len(password) > 0 {
		pw := string(password)
		authMethods = append(authMethods, authWithCleanup{
			method: ssh.Password(pw),
		})
		authMethods = append(authMethods, authWithCleanup{
			method: ssh.KeyboardInteractive(
				func(_, _ string, questions []string, echos []bool) ([]string, error) {
					answers := make([]string, len(questions))
					if len(questions) == 1 && !echos[0] {
						answers[0] = pw
					}
					return answers, nil
				},
			),
		})
	}

	if signer, err := loadConfiguredKey(keyPath, keyData, keyPassphrase); err != nil {
		return nil, err
	} else if signer != nil {
		authMethods = append(authMethods, authWithCleanup{method: ssh.PublicKeys(signer)})
	}

	if agentAuth, conn := dialAgent(); agentAuth != nil {
		authMethods = append(authMethods, authWithCleanup{
			method: agentAuth,
			conn:   conn,
		})
	}

	if signers := loadKeyFiles(); len(signers) > 0 {
		authMethods = append(authMethods, authWithCleanup{method: ssh.PublicKeys(signers...)})
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no authentication method available (no password, agent, or key files found)")
	}
	return authMethods, nil
}

func closeAuthResources(methods []authWithCleanup) {
	for _, method := range methods {
		if method.conn != nil {
			_ = method.conn.Close()
		}
	}
}

func flattenAuthMethods(methods []authWithCleanup) []ssh.AuthMethod {
	out := make([]ssh.AuthMethod, 0, len(methods))
	for _, method := range methods {
		out = append(out, method.method)
	}
	return out
}

var defaultKeyNames = []string{"id_ed25519", "id_ed25519_sk", "id_ecdsa", "id_ecdsa_sk", "id_rsa"}

func loadKeyFiles() []ssh.Signer {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var signers []ssh.Signer
	for _, name := range defaultKeyNames {
		p := filepath.Join(home, ".ssh", name)

		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if perm := info.Mode().Perm(); perm&0077 != 0 {
			continue
		}

		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		signer, err := ssh.ParsePrivateKey(data)
		for i := range data {
			data[i] = 0
		}
		if err != nil {
			continue
		}
		signers = append(signers, signer)
	}
	return signers
}

func loadConfiguredKey(path string, keyData []byte, keyPassphrase []byte) (ssh.Signer, error) {
	switch {
	case len(keyData) > 0:
		return parseConfiguredKey(keyData, keyPassphrase)
	case path != "":
		path = expandUserPath(path)
		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("configured SSH key path failed: %w", err)
		}
		if perm := info.Mode().Perm(); perm&0077 != 0 {
			return nil, fmt.Errorf("configured SSH key permissions are too open")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("configured SSH key read failed: %w", err)
		}
		signer, parseErr := parseConfiguredKey(data, keyPassphrase)
		for i := range data {
			data[i] = 0
		}
		return signer, parseErr
	default:
		return nil, nil
	}
}

func parseConfiguredKey(keyData []byte, keyPassphrase []byte) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(keyData)
	if err == nil {
		return signer, nil
	}
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if len(keyPassphrase) == 0 {
			return nil, &KeyPassphraseRequiredError{}
		}
		signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, keyPassphrase)
		if err != nil {
			return nil, fmt.Errorf("configured SSH key passphrase is invalid: %w", err)
		}
		return signer, nil
	}
	return nil, fmt.Errorf("configured SSH key is invalid: %w", err)
}

// NeedsPassphrase checks locally (no network) whether the given key
// requires a passphrase to decrypt. Returns true when a passphrase is
// needed but none was supplied.
func NeedsPassphrase(keyPath string, keyData []byte) bool {
	switch {
	case len(keyData) > 0:
		_, err := ssh.ParsePrivateKey(keyData)
		var missing *ssh.PassphraseMissingError
		return errors.As(err, &missing)
	case keyPath != "":
		keyPath = expandUserPath(keyPath)
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return false
		}
		_, err = ssh.ParsePrivateKey(data)
		var missing *ssh.PassphraseMissingError
		return errors.As(err, &missing)
	default:
		return false
	}
}

// Verify validates SSH connectivity with a background context.
func Verify(cfg VerifyConfig) error {
	return VerifyWithContext(context.Background(), cfg)
}

// VerifyWithContext validates SSH connectivity and honors context cancellation.
func VerifyWithContext(ctx context.Context, cfg VerifyConfig) error {
	if ctx == nil {
		ctx = context.Background()
	}
	dialCtx, cancel := withDefaultTimeout(ctx, cfg.DialTimeout)
	defer cancel()

	authMethods, err := buildAuthMethods(cfg.Password, cfg.KeyPath, cfg.KeyData, cfg.KeyPassphrase)
	if err != nil {
		return fmt.Errorf("build auth methods: %w", err)
	}
	defer closeAuthResources(authMethods)

	hostKeyCallback, err := buildVerifyHostKeyCallback()
	if err != nil {
		return fmt.Errorf("known_hosts setup failed: %w", err)
	}

	config := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            flattenAuthMethods(authMethods),
		HostKeyCallback: hostKeyCallback,
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	client, err := dialSSHClientWithContext(dialCtx, addr, config)
	if err != nil {
		return fmt.Errorf("dial SSH endpoint: %w", err)
	}
	if err := client.Close(); err != nil {
		return fmt.Errorf("close SSH client: %w", err)
	}
	return nil
}

func TrustHostKey(err *UnknownHostError) error {
	if err == nil || err.KnownHostsLine == "" {
		return fmt.Errorf("missing host key to trust")
	}
	knownHostsMu.Lock()
	defer knownHostsMu.Unlock()
	khPath, readErr := ensureKnownHostsFile()
	if readErr != nil {
		return fmt.Errorf("ensure known_hosts file: %w", readErr)
	}

	data, readErr := os.ReadFile(khPath)
	if readErr == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) == strings.TrimSpace(err.KnownHostsLine) {
				return nil
			}
		}
	}

	f, openErr := os.OpenFile(khPath, os.O_APPEND|os.O_WRONLY, 0600)
	if openErr != nil {
		return fmt.Errorf("open known_hosts file: %w", openErr)
	}
	defer f.Close()

	if _, writeErr := fmt.Fprintln(f, err.KnownHostsLine); writeErr != nil {
		return fmt.Errorf("write trusted host key: %w", writeErr)
	}
	return nil
}

func expandUserPath(path string) string {
	if path == "~" || len(path) >= 2 && path[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func ensureKnownHostsFile() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home directory: %w", err)
	}
	khPath := filepath.Join(home, ".ssh", "known_hosts")
	if _, err := os.Stat(khPath); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(khPath), 0700); err != nil {
			return "", fmt.Errorf("create known_hosts directory: %w", err)
		}
		if err := os.WriteFile(khPath, nil, 0600); err != nil {
			return "", fmt.Errorf("create known_hosts file: %w", err)
		}
	}
	return khPath, nil
}

func withDefaultTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	if timeout <= 0 {
		timeout = defaultDialTimeout
	}
	return context.WithTimeout(ctx, timeout)
}

func dialSSHClientWithContext(ctx context.Context, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	dialer := &net.Dialer{}
	netConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial TCP endpoint: %w", err)
	}

	conn, chans, reqs, err := ssh.NewClientConn(netConn, addr, config)
	if err != nil {
		if closeErr := netConn.Close(); closeErr != nil {
			return nil, fmt.Errorf("create SSH client connection: %w (cleanup: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("create SSH client connection: %w", err)
	}

	return ssh.NewClient(conn, chans, reqs), nil
}

func stripKnownHostPort(host string) string {
	if strings.HasPrefix(host, "[") && strings.Contains(host, "]:") {
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			return parsedHost
		}
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		return parsedHost
	}
	return host
}
