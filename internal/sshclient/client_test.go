package sshclient

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestUnknownHostErrorString(t *testing.T) {
	err := &UnknownHostError{Host: "example.com", Fingerprint: "SHA256:abc"}
	got := err.Error()
	want := "unknown host key for example.com (SHA256:abc)"
	if got != want {
		t.Fatalf("unexpected error string: got %q want %q", got, want)
	}
}

func TestStripKnownHostPortTable(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "host with port", in: "example.com:22", want: "example.com"},
		{name: "ipv6 with port", in: "[2001:db8::1]:2200", want: "2001:db8::1"},
		{name: "plain host", in: "example.com", want: "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripKnownHostPort(tt.in)
			if got != tt.want {
				t.Fatalf("stripKnownHostPort(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func FuzzStripKnownHostPort(f *testing.F) {
	f.Add("example.com")
	f.Add("example.com:22")
	f.Add("[2001:db8::1]:22")
	f.Add(":")

	f.Fuzz(func(t *testing.T, in string) {
		_ = stripKnownHostPort(in)
	})
}

func TestVerifyWithContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := VerifyWithContext(ctx, VerifyConfig{
		Host:     "127.0.0.1",
		Port:     22,
		User:     "nobody",
		Password: []byte("pw"),
	})
	if err == nil {
		t.Fatal("expected canceled context to fail verification")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}

func TestTrustHostKeyNilInput(t *testing.T) {
	if err := TrustHostKey(nil); err == nil {
		t.Fatal("expected error for nil unknown host")
	}
}

func TestExpandUserPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("resolve home directory: %v", err)
	}

	tests := []struct {
		in   string
		want string
	}{
		{"~", home},
		{"~/", home},
		{"~/.ssh/id_ed25519", filepath.Join(home, ".ssh", "id_ed25519")},
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
	}
	for _, tt := range tests {
		if got := expandUserPath(tt.in); got != tt.want {
			t.Fatalf("expandUserPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestTrustHostKeyIdempotent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	khErr := &UnknownHostError{
		Host:           "example.com",
		KnownHostsLine: "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAFAKE",
	}

	if err := TrustHostKey(khErr); err != nil {
		t.Fatalf("first TrustHostKey failed: %v", err)
	}
	if err := TrustHostKey(khErr); err != nil {
		t.Fatalf("second TrustHostKey failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".ssh", "known_hosts"))
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	count := strings.Count(string(data), khErr.KnownHostsLine)
	if count != 1 {
		t.Fatalf("expected key to appear once, got %d occurrences", count)
	}
}

func TestTrustHostKeyConcurrent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	khErr := &UnknownHostError{
		Host:           "concurrent.example.com",
		KnownHostsLine: "concurrent.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAFAKE",
	}

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = TrustHostKey(khErr)
		}()
	}
	wg.Wait()

	data, err := os.ReadFile(filepath.Join(dir, ".ssh", "known_hosts"))
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	count := strings.Count(string(data), khErr.KnownHostsLine)
	if count != 1 {
		t.Fatalf("expected key to appear once after concurrent writes, got %d occurrences", count)
	}
}

func TestDefaultKeyNamesContainsFIDO2(t *testing.T) {
	expected := []string{"id_ed25519", "id_ed25519_sk", "id_ecdsa", "id_ecdsa_sk", "id_rsa"}
	if len(defaultKeyNames) != len(expected) {
		t.Fatalf("defaultKeyNames length = %d, want %d", len(defaultKeyNames), len(expected))
	}
	nameSet := make(map[string]struct{}, len(defaultKeyNames))
	for _, n := range defaultKeyNames {
		nameSet[n] = struct{}{}
	}
	for _, name := range expected {
		if _, ok := nameSet[name]; !ok {
			t.Fatalf("defaultKeyNames missing %q", name)
		}
	}
}

func TestNeedsPassphraseWithMissingPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if NeedsPassphrase(missing, nil) {
		t.Fatal("expected false when key path does not exist")
	}
}

func TestSessionZeroMethods(t *testing.T) {
	s := &Session{
		Password:      []byte("pw"),
		KeyData:       []byte("key"),
		KeyPassphrase: []byte("pass"),
	}

	s.zeroPassword()
	if s.Password != nil {
		t.Fatal("expected Password to be nil after zeroPassword")
	}

	s.zeroKeyData()
	if s.KeyData != nil {
		t.Fatal("expected KeyData to be nil after zeroKeyData")
	}

	s.zeroKeyPassphrase()
	if s.KeyPassphrase != nil {
		t.Fatal("expected KeyPassphrase to be nil after zeroKeyPassphrase")
	}
}

func TestFlattenAuthMethodsEmpty(t *testing.T) {
	if got := flattenAuthMethods(nil); len(got) != 0 {
		t.Fatal("expected empty auth method list")
	}
}
