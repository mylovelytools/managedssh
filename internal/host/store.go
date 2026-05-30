package host

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mylovelytools/managedssh/internal/fsutil"
)

var (
	ErrDuplicateAlias    = errors.New("host with same alias already exists")
	ErrDuplicateHostname = errors.New("host with same hostname or ip already exists")
)

type Host struct {
	ID          string     `json:"id"`
	Alias       string     `json:"alias"`
	Hostname    string     `json:"hostname"`
	Port        int        `json:"port"`
	TimeoutSec  int        `json:"timeout_sec,omitempty"`
	Group       string     `json:"group,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
	DefaultUser string     `json:"default_user,omitempty"`
	Accounts    []HostUser `json:"accounts,omitempty"`

	// Legacy fields kept for backward compatibility with existing hosts.json.
	DefaultAuthType    string `json:"default_auth_type,omitempty"`
	DefaultEncPassword []byte `json:"default_enc_password,omitempty"`
	DefaultKeyPath     string `json:"default_key_path,omitempty"`
	DefaultEncKey      []byte `json:"default_enc_key,omitempty"`
	DefaultEncKeyPass  []byte `json:"default_enc_key_pass,omitempty"`

	// Legacy fields kept for backward compatibility with existing hosts.json.
	User        string   `json:"user,omitempty"`
	Users       []string `json:"users,omitempty"`
	AuthType    string   `json:"auth_type,omitempty"`
	EncPassword []byte   `json:"enc_password,omitempty"`
}

type HostUser struct {
	Username    string `json:"username"`
	UseDefault  bool   `json:"use_default,omitempty"`
	AuthType    string `json:"auth_type,omitempty"`
	EncPassword []byte `json:"enc_password,omitempty"`
	KeyPath     string `json:"key_path,omitempty"`
	EncKey      []byte `json:"enc_key,omitempty"`
	EncKeyPass  []byte `json:"enc_key_pass,omitempty"`
}

type Store struct {
	path  string
	Hosts []Host `json:"hosts"`
}

func genID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating host ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func NewStore(dir string) (*Store, error) {
	p := filepath.Join(dir, "hosts.json")
	s := &Store{path: p}

	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, err
	}
	for i := range s.Hosts {
		s.Hosts[i].Normalize()
	}
	return s, nil
}

func (s *Store) Save() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.AtomicWrite(s.path, data, 0600)
}

func (s *Store) Add(h Host) error {
	aliasConflict, hostnameConflict := s.identityConflicts("", h.Alias, h.Hostname)
	if aliasConflict {
		return ErrDuplicateAlias
	}
	if hostnameConflict {
		return ErrDuplicateHostname
	}
	if h.ID == "" {
		id, err := genID()
		if err != nil {
			return err
		}
		h.ID = id
	}
	if h.Port == 0 {
		h.Port = 22
	}
	if h.TimeoutSec == 0 {
		h.TimeoutSec = 10
	}
	h.Normalize()
	s.Hosts = append(s.Hosts, h)
	return s.Save()
}

func (s *Store) Update(id string, h Host) error {
	aliasConflict, hostnameConflict := s.identityConflicts(id, h.Alias, h.Hostname)
	if aliasConflict {
		return ErrDuplicateAlias
	}
	if hostnameConflict {
		return ErrDuplicateHostname
	}
	for i, existing := range s.Hosts {
		if existing.ID == id {
			h.ID = id
			h.Normalize()
			s.Hosts[i] = h
			return s.Save()
		}
	}
	return nil
}

func (s *Store) Delete(id string) error {
	for i, h := range s.Hosts {
		if h.ID == id {
			s.Hosts = append(s.Hosts[:i], s.Hosts[i+1:]...)
			return s.Save()
		}
	}
	return nil
}

func (s *Store) identityConflicts(excludeID, alias, hostname string) (bool, bool) {
	alias = strings.TrimSpace(alias)
	hostname = strings.TrimSpace(hostname)
	aliasConflict := false
	hostnameConflict := false
	for _, existing := range s.Hosts {
		if existing.ID == excludeID {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(existing.Alias), alias) {
			aliasConflict = true
		}
		if strings.EqualFold(strings.TrimSpace(existing.Hostname), hostname) {
			hostnameConflict = true
		}
		if aliasConflict && hostnameConflict {
			break
		}
	}
	return aliasConflict, hostnameConflict
}

func (s *Store) Filter(query string) []Host {
	if query == "" {
		out := make([]Host, len(s.Hosts))
		copy(out, s.Hosts)
		return out
	}
	q := strings.ToLower(query)
	var out []Host
	for _, h := range s.Hosts {
		users := strings.ToLower(strings.Join(h.AccountNames(), " "))
		tags := strings.ToLower(strings.Join(h.Tags, " "))
		if strings.Contains(strings.ToLower(h.Alias), q) ||
			strings.Contains(strings.ToLower(h.Hostname), q) ||
			strings.Contains(strings.ToLower(h.Group), q) ||
			strings.Contains(tags, q) ||
			strings.Contains(users, q) {
			out = append(out, h)
		}
	}
	return out
}

func (h *Host) Normalize() {
	if h.Port == 0 {
		h.Port = 22
	}
	if h.TimeoutSec <= 0 {
		h.TimeoutSec = 10
	}

	defaultAuth := normalizeAuthType(h.DefaultAuthType)
	if defaultAuth == "" {
		defaultAuth = normalizeAuthType(h.AuthType)
	}
	if defaultAuth == "" {
		defaultAuth = "key"
	}
	h.DefaultAuthType = defaultAuth

	if len(h.DefaultEncPassword) == 0 && len(h.EncPassword) > 0 {
		h.DefaultEncPassword = cloneBytes(h.EncPassword)
	}
	if h.DefaultAuthType == "password" {
		h.DefaultKeyPath = ""
		h.DefaultEncKey = nil
		h.DefaultEncKeyPass = nil
	} else {
		h.DefaultEncPassword = nil
	}

	accounts := normalizeAccounts(h.Accounts)
	if len(accounts) == 0 {
		for _, name := range legacyAccountNames(h.User, h.Users) {
			accounts = append(accounts, HostUser{
				Username:   name,
				UseDefault: true,
			})
		}
	}
	for i := range accounts {
		if accounts[i].UseDefault {
			accounts[i].AuthType = ""
			accounts[i].EncPassword = nil
			accounts[i].KeyPath = ""
			accounts[i].EncKey = nil
			accounts[i].EncKeyPass = nil
			continue
		}
		if accounts[i].AuthType == "" {
			accounts[i].AuthType = h.DefaultAuthType
			if accounts[i].AuthType == "" {
				accounts[i].AuthType = "key"
			}
			accounts[i].EncPassword = cloneBytes(h.DefaultEncPassword)
			accounts[i].KeyPath = h.DefaultKeyPath
			accounts[i].EncKey = cloneBytes(h.DefaultEncKey)
			accounts[i].EncKeyPass = cloneBytes(h.DefaultEncKeyPass)
		}
	}
	h.Accounts = accounts

	names := h.AccountNames()
	if h.DefaultUser == "" && len(names) > 0 {
		h.DefaultUser = names[0]
	} else if h.DefaultUser != "" {
		found := false
		for _, n := range names {
			if n == h.DefaultUser {
				found = true
				break
			}
		}
		if !found && len(names) > 0 {
			h.DefaultUser = names[0]
		} else if !found {
			h.DefaultUser = ""
		}
	}

	h.User = ""
	if len(names) > 0 {
		h.User = names[0]
	}
	h.Users = names
	h.AuthType = h.DefaultAuthType
	h.EncPassword = cloneBytes(h.DefaultEncPassword)
}

func (h Host) AccountNames() []string {
	names := make([]string, 0, len(h.Accounts))
	for _, account := range h.Accounts {
		if account.Username != "" {
			names = append(names, account.Username)
		}
	}
	return names
}

type ResolvedAuth struct {
	AuthType   string
	Password   []byte
	KeyPath    string
	EncKey     []byte
	EncKeyPass []byte
}

func (h Host) ResolveAccount(username string) (HostUser, ResolvedAuth, bool) {
	for _, account := range h.Accounts {
		if account.Username != username {
			continue
		}
		if account.UseDefault {
			return account, ResolvedAuth{
				AuthType:   h.DefaultAuthType,
				Password:   cloneBytes(h.DefaultEncPassword),
				KeyPath:    h.DefaultKeyPath,
				EncKey:     cloneBytes(h.DefaultEncKey),
				EncKeyPass: cloneBytes(h.DefaultEncKeyPass),
			}, true
		}
		return account, ResolvedAuth{
			AuthType:   account.AuthType,
			Password:   cloneBytes(account.EncPassword),
			KeyPath:    account.KeyPath,
			EncKey:     cloneBytes(account.EncKey),
			EncKeyPass: cloneBytes(account.EncKeyPass),
		}, true
	}
	return HostUser{}, ResolvedAuth{}, false
}

func normalizeAccounts(accounts []HostUser) []HostUser {
	seen := make(map[string]struct{}, len(accounts))
	out := make([]HostUser, 0, len(accounts))
	for _, account := range accounts {
		username := strings.TrimSpace(account.Username)
		if username == "" {
			continue
		}
		if _, ok := seen[username]; ok {
			continue
		}
		seen[username] = struct{}{}

		account.Username = username
		account.AuthType = normalizeAuthType(account.AuthType)
		if account.UseDefault || account.AuthType == "" {
			account.UseDefault = true
			account.AuthType = ""
			account.EncPassword = nil
			account.KeyPath = ""
			account.EncKey = nil
			account.EncKeyPass = nil
		} else {
			account.UseDefault = false
			if account.AuthType == "password" {
				account.KeyPath = ""
				account.EncKey = nil
				account.EncKeyPass = nil
			} else {
				account.EncPassword = nil
			}
		}
		out = append(out, account)
	}
	return out
}

func legacyAccountNames(user string, users []string) []string {
	names := make([]string, 0, len(users)+1)
	if strings.TrimSpace(user) != "" {
		names = append(names, user)
	}
	names = append(names, users...)
	return normalizeNames(names)
}

func normalizeNames(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	var out []string
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func normalizeAuthType(authType string) string {
	switch strings.TrimSpace(strings.ToLower(authType)) {
	case "password":
		return "password"
	case "key":
		return "key"
	default:
		return ""
	}
}

func cloneBytes(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	out := make([]byte, len(src))
	copy(out, src)
	return out
}

