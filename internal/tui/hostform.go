package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/mylovelytools/managedssh/internal/host"
	"github.com/mylovelytools/managedssh/internal/vault"
)

const (
	fAlias = iota
	fHostname
	fGroup
	fTags
	fPort
	fTimeout
	fUsers
	fSelectedUser
	fSelectedUserAuth
	fSelectedUserCredential
)

func formInputIdx(focus int) int {
	switch focus {
	case fAlias:
		return 0
	case fHostname:
		return 1
	case fGroup:
		return 2
	case fTags:
		return 3
	case fPort:
		return 4
	case fTimeout:
		return 5
	case fUsers:
		return 6
	case fSelectedUserCredential:
		return 7
	default:
		return -1
	}
}

func newHostFormInputs(alias, hostname, users string, port, timeoutSec int, group string, tags []string) []textinput.Model {
	inputs := make([]textinput.Model, 8)

	inputs[0] = textinput.New()
	inputs[0].Placeholder = "e.g. ManagedSSH Website"
	inputs[0].CharLimit = 64
	inputs[0].Width = 36
	inputs[0].Focus()

	inputs[1] = textinput.New()
	inputs[1].Placeholder = "e.g. 192.168.1.10 or example.com"
	inputs[1].CharLimit = 256
	inputs[1].Width = 36

	inputs[2] = textinput.New()
	inputs[2].Placeholder = "e.g. production, staging"
	inputs[2].CharLimit = 64
	inputs[2].Width = 36

	inputs[3] = textinput.New()
	inputs[3].Placeholder = "e.g. web, database"
	inputs[3].CharLimit = 256
	inputs[3].Width = 36

	inputs[4] = textinput.New()
	inputs[4].Placeholder = "22"
	inputs[4].CharLimit = 5
	inputs[4].Width = 10

	inputs[5] = textinput.New()
	inputs[5].Placeholder = "10"
	inputs[5].CharLimit = 3
	inputs[5].Width = 10

	inputs[6] = textinput.New()
	inputs[6].Placeholder = "e.g. root, ubuntu, deploy"
	inputs[6].CharLimit = 256
	inputs[6].Width = 80

	inputs[7] = textinput.New()
	inputs[7].Placeholder = "Password or SSH Key Path"
	inputs[7].CharLimit = 4096
	inputs[7].Width = 36

	inputs[0].SetValue(alias)
	inputs[1].SetValue(hostname)
	inputs[2].SetValue(group)
	inputs[3].SetValue(strings.Join(tags, ", "))
	if port > 0 {
		inputs[4].SetValue(fmt.Sprintf("%d", port))
	}
	if timeoutSec > 0 {
		inputs[5].SetValue(fmt.Sprintf("%d", timeoutSec))
	}
	inputs[6].SetValue(users)

	return inputs
}

func (m model) startHostForm(editID string, duplicate bool) (model, tea.Cmd) {
	m.phase = phaseHostForm
	m.formEditing = editID
	m.formDuplicating = duplicate
	m.formSourceAlias = ""
	m.formSourceHostname = ""
	m.formFocus = fAlias
	m.formErr = ""
	m.formDefaultUser = ""
	m.formUserConfigs = nil
	m.formUserCursor = 0
	m.formScroll = 0
	m.formPathSuggestions = nil
	m.formPathSuggestIndex = 0

	var alias, hostname, users, group string
	var tags []string
	var port, timeoutSec int
	if editID != "" {
		for _, h := range m.store.Hosts {
			if h.ID != editID {
				continue
			}
			alias = h.Alias
			hostname = h.Hostname
			users = strings.Join(h.AccountNames(), ", ")
			port = h.Port
			timeoutSec = h.TimeoutSec
			group = h.Group
			tags = h.Tags
			m.formDefaultUser = h.DefaultUser
			m.formUserConfigs = make([]formUserConfig, 0, len(h.Accounts))
			for _, account := range h.Accounts {
				keyValue := account.KeyPath
				m.formUserConfigs = append(m.formUserConfigs, formUserConfig{
					Username:            account.Username,
					AuthType:            account.AuthType,
					ExistingEncPassword: cloneFormBytes(account.EncPassword),
					KeyValue:            keyValue,
					ExistingKeyPath:     account.KeyPath,
					ExistingEncKey:      cloneFormBytes(account.EncKey),
					ExistingEncKeyPass:  cloneFormBytes(account.EncKeyPass),
				})
			}
			break
		}
	}

	if duplicate {
		m.formSourceAlias = alias
		m.formSourceHostname = hostname
		m.formEditing = ""
	}

	m.formInputs = newHostFormInputs(alias, hostname, users, port, timeoutSec, group, tags)
	m.syncFormUsers()
	m.loadSelectedUserCredentialInput()
	return m, textinput.Blink
}

func (m model) startHostFormFromSSH(p parsedSSH) (model, tea.Cmd) {
	m, cmd := m.startHostForm("", false)
	m.formInputs[1].SetValue(p.Hostname)
	if p.Port > 0 {
		m.formInputs[4].SetValue(strconv.Itoa(p.Port))
	}
	if p.User != "" {
		m.formInputs[6].SetValue(p.User)
		m.syncFormUsers()
		if p.KeyPath != "" && len(m.formUserConfigs) > 0 {
			m.formUserConfigs[0].AuthType = "key"
			m.formUserConfigs[0].KeyValue = p.KeyPath
			m.loadSelectedUserCredentialInput()
		}
	}
	// Alias is empty — keep focus there so the user fills it in first.
	m.formFocus = fAlias
	for i := range m.formInputs {
		m.formInputs[i].Blur()
	}
	m.formInputs[0].Focus()
	return m, cmd
}

func (m model) updateHostForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			m.phase = phaseDashboard
			m = m.refreshFiltered()
			return m, nil
		case "tab", "down":
			if key.String() == "tab" && m.acceptPathSuggestion() {
				return m, nil
			}
			return m.cycleFormFocus(1)
		case "shift+tab", "up":
			return m.cycleFormFocus(-1)
		case "ctrl+down":
			if m.cyclePathSuggestion(1) {
				return m, nil
			}
		case "ctrl+up":
			if m.cyclePathSuggestion(-1) {
				return m, nil
			}
		case "pgdown":
			m.formScroll += 4
			return m, nil
		case "pgup":
			m.formScroll = max(0, m.formScroll-4)
			return m, nil
		case "left", "h":
			switch m.formFocus {
			case fSelectedUser:
				m.selectFormUser(-1)
				return m, nil
			case fSelectedUserAuth:
				m.selectSelectedUserAuth(-1)
				return m, nil
			}
		case "right", "l":
			switch m.formFocus {
			case fSelectedUser:
				m.selectFormUser(1)
				return m, nil
			case fSelectedUserAuth:
				m.selectSelectedUserAuth(1)
				return m, nil
			case fSelectedUserCredential:
				// Right arrow (not the 'l' character) accepts the ghost suggestion.
				if key.String() == "right" && len(m.formPathSuggestions) > 0 {
					m.acceptPathSuggestion()
					return m, nil
				}
			}
		case "end":
			if m.formFocus == fSelectedUserCredential && len(m.formPathSuggestions) > 0 {
				m.acceptPathSuggestion()
				return m, nil
			}
		case " ":
			if m.formFocus == fSelectedUser {
				if user := m.currentFormUser(); user != nil {
					m.formDefaultUser = user.Username
				}
				return m, nil
			}
		case "enter":
			return m.submitHostForm()
		}
	}

	if idx := formInputIdx(m.formFocus); idx >= 0 {
		var cmd tea.Cmd
		m.formInputs[idx], cmd = m.formInputs[idx].Update(msg)
		switch m.formFocus {
		case fUsers:
			m.syncFormUsers()
		case fSelectedUserCredential:
			m.storeSelectedUserCredentialInput()
			m.refreshPathSuggestions()
		}
		return m, cmd
	}
	return m, nil
}

func (m model) activeFormFocuses() []int {
	focuses := []int{fAlias, fHostname, fGroup, fTags, fPort, fTimeout, fUsers}
	if len(m.formUserConfigs) > 0 {
		focuses = append(focuses, fSelectedUser, fSelectedUserAuth, fSelectedUserCredential)
	}
	return focuses
}

func (m model) cycleFormFocus(dir int) (tea.Model, tea.Cmd) {
	if idx := formInputIdx(m.formFocus); idx >= 0 {
		m.formInputs[idx].Blur()
	}
	focuses := m.activeFormFocuses()
	if len(focuses) == 0 {
		return m, nil
	}
	cur := 0
	for i, focus := range focuses {
		if focus == m.formFocus {
			cur = i
			break
		}
	}
	cur = (cur + dir + len(focuses)) % len(focuses)
	m.formFocus = focuses[cur]
	if m.formFocus >= fSelectedUser {
		// Auto-jump to lower section when entering per-user auth controls.
		m.formScroll = 9999
	} else {
		m.formScroll = 0
	}

	if idx := formInputIdx(m.formFocus); idx >= 0 {
		m.refreshPathSuggestions()
		m.formInputs[idx].Focus()
		return m, textinput.Blink
	}
	m.formPathSuggestions = nil
	m.formPathSuggestIndex = 0
	return m, nil
}

func (m model) submitHostForm() (tea.Model, tea.Cmd) {
	alias := strings.TrimSpace(m.formInputs[0].Value())
	hostname := strings.TrimSpace(m.formInputs[1].Value())
	group := strings.TrimSpace(m.formInputs[2].Value())
	tagsStr := m.formInputs[3].Value()
	portStr := strings.TrimSpace(m.formInputs[4].Value())
	timeoutStr := strings.TrimSpace(m.formInputs[5].Value())
	users := parseUsers(m.formInputs[6].Value())

	var tags []string
	for _, t := range strings.Split(tagsStr, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			tags = append(tags, t)
		}
	}

	if alias == "" {
		m.formErr = "Alias is required"
		return m, nil
	}
	if hostname == "" {
		m.formErr = "Hostname is required"
		return m, nil
	}
	if len(users) == 0 {
		m.formErr = "At least one user is required"
		return m, nil
	}
	if m.formDuplicating {
		sameAlias := strings.EqualFold(strings.TrimSpace(m.formSourceAlias), alias)
		sameHostname := strings.EqualFold(strings.TrimSpace(m.formSourceHostname), hostname)
		if sameAlias || sameHostname {
			m.formErr = "To save a duplicate, change both alias and hostname/IP"
			return m, nil
		}
	}
	aliasConflict, hostnameConflict := m.identityConflicts(alias, hostname)
	if aliasConflict || hostnameConflict {
		m.formErr = identityConflictMessage(aliasConflict, hostnameConflict)
		return m, nil
	}

	port := 22
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			m.formErr = "Port must be 1-65535"
			return m, nil
		}
		port = p
	}

	timeoutSec := 10
	if timeoutStr != "" {
		t, err := strconv.Atoi(timeoutStr)
		if err != nil || t < 1 || t >= 999 {
			m.formErr = "Timeout must be between 1 and 998 seconds"
			return m, nil
		}
		timeoutSec = t
	}

	h := host.Host{
		Alias:       alias,
		Hostname:    hostname,
		Port:        port,
		TimeoutSec:  timeoutSec,
		Group:       group,
		Tags:        tags,
		DefaultUser: m.formDefaultUser,
		Accounts:    make([]host.HostUser, 0, len(m.formUserConfigs)),
	}

	for _, cfg := range m.formUserConfigs {
		account := host.HostUser{
			Username: cfg.Username,
			AuthType: cfg.AuthType,
		}
		if cfg.AuthType == "password" {
			switch {
			case cfg.Password != "":
				enc, err := vault.Encrypt(m.encKey, []byte(cfg.Password))
				if err != nil {
					m.formErr = "Failed to encrypt password for " + cfg.Username + ": " + err.Error()
					return m, nil
				}
				account.EncPassword = enc
			case len(cfg.ExistingEncPassword) > 0:
				account.EncPassword = cloneFormBytes(cfg.ExistingEncPassword)
			default:
				m.formErr = "Password is required for " + cfg.Username
				return m, nil
			}
		} else if cfg.AuthType == "key" {
			keyPath, keyPlain := splitKeyValue(cfg.KeyValue)
			switch {
			case keyPath != "":
				account.KeyPath = keyPath
				if keyPath == cfg.ExistingKeyPath {
					account.EncKeyPass = cloneFormBytes(cfg.ExistingEncKeyPass)
				}
			case keyPlain != "":
				enc, err := vault.Encrypt(m.encKey, []byte(keyPlain))
				if err != nil {
					m.formErr = "Failed to encrypt SSH key for " + cfg.Username + ": " + err.Error()
					return m, nil
				}
				account.EncKey = enc
			case cfg.ExistingKeyPath != "":
				account.KeyPath = cfg.ExistingKeyPath
				account.EncKeyPass = cloneFormBytes(cfg.ExistingEncKeyPass)
			case len(cfg.ExistingEncKey) > 0:
				account.EncKey = cloneFormBytes(cfg.ExistingEncKey)
				account.EncKeyPass = cloneFormBytes(cfg.ExistingEncKeyPass)
			}
		}
		h.Accounts = append(h.Accounts, account)
	}

	m.pendingHost = h
	m.pendingEditID = m.formEditing
	m.pendingTrust = nil
	m.phase = phaseHostVerifying
	m.formErr = ""
	return m, verifyHostCmd(h, m.encKey)
}

func (m model) viewHostForm() string {
	title := "Add Host"
	if m.formEditing != "" {
		title = "Edit Host"
	} else if m.formDuplicating {
		title = "Duplicate Host"
	}

	formW := 90
	formH := 38
	contentW := formW - 6
	colGap := 2
	colW := (contentW - colGap) / 2

	// Keep input widths in sync with the rendered layout so fields use available space.
	m.formInputs[0].Width = colW
	m.formInputs[1].Width = colW
	m.formInputs[2].Width = colW
	m.formInputs[3].Width = colW
	m.formInputs[4].Width = min(10, colW)
	m.formInputs[5].Width = min(10, colW)
	m.formInputs[6].Width = contentW

	var b strings.Builder
	b.WriteString(titleStyle.Render("📝 "+title) + "\n\n")

	renderFieldCol := func(focus int, label string, idx int, w int) string {
		lbl := inputLabelStyle.Render(label)
		if m.formFocus == focus {
			lbl = focusedLabel("▸ " + label)
		}
		field := m.formInputs[idx].View()
		col := lipgloss.NewStyle().Width(w)
		return col.Render(lbl + "\n" + field)
	}

	left := renderFieldCol(fAlias, "Alias", 0, colW)
	right := renderFieldCol(fHostname, "Hostname", 1, colW)
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right) + "\n\n")

	groupCol := renderFieldCol(fGroup, "Group", 2, colW)
	tagsCol := renderFieldCol(fTags, "Tags", 3, colW)
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, groupCol, "  ", tagsCol) + "\n\n")

	portCol := renderFieldCol(fPort, "Port", 4, colW)
	timeoutCol := renderFieldCol(fTimeout, "Timeout (sec)", 5, colW)
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, portCol, "  ", timeoutCol) + "\n\n")

	b.WriteString(lipgloss.NewStyle().Foreground(subtle).Render(strings.Repeat("─", formW-4)) + "\n\n")

	lbl := inputLabelStyle.Render("SSH Users")
	if m.formFocus == fUsers {
		lbl = focusedLabel("▸ SSH Users")
	}
	b.WriteString(lbl + "\n")
	b.WriteString(m.formInputs[6].View() + "\n")
	b.WriteString(hintStyle.Render("  Comma-separated usernames. Example: main, ubuntu, deploy") + "\n\n")

	if len(m.formUserConfigs) > 0 {
		b.WriteString(m.renderSelectedUserSection(contentW))
	} else {
		b.WriteString(hintStyle.Render("  Type usernames above to configure per-user auth settings.") + "\n")
	}

	if m.formErr != "" {
		b.WriteString("\n" + errorStyle.Render("✗ "+m.formErr) + "\n")
	}

	b.WriteString("\n" + statusBarStyle.Render("tab/↑↓ navigate • space default user • ←→ adjust • pgup/pgdn scroll • enter save • esc cancel"))

	content := b.String()
	content = m.renderFormViewport(content, formH)
	return boxStyle.Width(formW).Render(content)
}

func (m model) renderFormViewport(content string, height int) string {
	lines := strings.Split(content, "\n")
	if len(lines) <= height {
		for len(lines) < height {
			lines = append(lines, "")
		}
		return strings.Join(lines, "\n")
	}

	maxOffset := len(lines) - height
	offset := m.formScroll
	if offset < 0 {
		offset = 0
	}
	if offset > maxOffset {
		offset = maxOffset
	}

	return strings.Join(lines[offset:offset+height], "\n")
}

func (m model) renderSelectedUserSection(contentW int) string {
	user := m.currentFormUser()
	if user == nil {
		return ""
	}

	var b strings.Builder

	lbl := inputLabelStyle.Render("Select User to Configure")
	if m.formFocus == fSelectedUser {
		lbl = focusedLabel("▸ Select User to Configure")
	}
	b.WriteString(lbl + "\n\n")
	b.WriteString("  " + m.renderUserTabs() + "\n")
	if m.formFocus == fSelectedUser {
		b.WriteString(hintStyle.Render("  ←/→ to switch users • Space to set as Default User") + "\n")
	}
	b.WriteString("\n")

	cardBorder := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(highlight).Padding(1, 2).Width(contentW)
	cardContentW := max(20, contentW-6)
	m.formInputs[7].Width = cardContentW

	var card strings.Builder
	headerLabel := "👤 " + user.Username
	if m.formDefaultUser == user.Username {
		headerLabel += " [★ Default User]"
	}
	card.WriteString(lipgloss.NewStyle().Foreground(highlight).Bold(true).Render(headerLabel) + "\n\n")

	authLabel := inputLabelStyle.Render("Auth Mode")
	if m.formFocus == fSelectedUserAuth {
		authLabel = focusedLabel("▸ Auth Mode")
	}
	card.WriteString(authLabel + "\n\n")
	card.WriteString("  " + authChoice("SSH Key", user.AuthType == "key") + "\n")
	card.WriteString("  " + authChoice("Password", user.AuthType == "password") + "\n")
	if m.formFocus == fSelectedUserAuth {
		card.WriteString(hintStyle.Render("  ←/→ to change") + "\n")
	}

	card.WriteString("\n")
	if user.AuthType == "password" {
		credLabel := inputLabelStyle.Render("Password")
		if m.formFocus == fSelectedUserCredential {
			credLabel = focusedLabel("▸ Password")
		}
		card.WriteString(credLabel + "\n")
		card.WriteString(m.formInputs[7].View() + "\n")
		if m.formEditing != "" && len(user.ExistingEncPassword) > 0 {
			card.WriteString(hintStyle.Render("  Leave empty to keep current password") + "\n")
		}
	} else if user.AuthType == "key" {
		credLabel := inputLabelStyle.Render("SSH Key")
		if m.formFocus == fSelectedUserCredential {
			credLabel = focusedLabel("▸ SSH Key")
		}
		card.WriteString(credLabel + "\n")
		card.WriteString(m.renderCredentialInputWithGhost() + "\n")
		card.WriteString(hintStyle.Render("  Key path or paste private key") + "\n")
		card.WriteString(m.renderPathSuggestions(cardContentW))
		if m.formEditing != "" && (user.ExistingKeyPath != "" || len(user.ExistingEncKey) > 0) {
			card.WriteString(hintStyle.Render("  Leave empty to keep current SSH key") + "\n")
		}
	}
	b.WriteString(cardBorder.Render(card.String()) + "\n")
	return b.String()
}

func authChoice(label string, selected bool) string {
	if selected {
		return selectedChip("● " + label)
	}
	return lipgloss.NewStyle().Foreground(subtle).Render("○ " + label)
}

func (m model) renderUserTabs() string {
	var parts []string
	for i, cfg := range m.formUserConfigs {
		label := cfg.Username
		if m.formDefaultUser == cfg.Username {
			label += " ★"
		}
		if i == m.formUserCursor {
			parts = append(parts, selectedChip(label))
			continue
		}
		parts = append(parts, lipgloss.NewStyle().Foreground(subtle).Render(label))
	}
	return strings.Join(parts, "  ")
}

func selectedChip(label string) string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("#111827")).Background(highlight).Bold(true).Padding(0, 1).Render(label)
}

func focusedLabel(label string) string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("#111827")).Background(accent).Bold(true).Padding(0, 1).Render(label)
}

func (m *model) selectSelectedUserAuth(dir int) {
	user := m.currentFormUser()
	if user == nil {
		return
	}
	options := []string{"key", "password"}
	index := 0
	if user.AuthType == "password" {
		index = 1
	}
	index = (index + dir + len(options)) % len(options)
	user.AuthType = options[index]
	m.storeSelectedUserCredentialInput()
	m.loadSelectedUserCredentialInput()
	m.refreshPathSuggestions()
}

func (m *model) selectFormUser(delta int) {
	if len(m.formUserConfigs) == 0 {
		return
	}
	m.storeSelectedUserCredentialInput()
	m.formUserCursor = (m.formUserCursor + delta + len(m.formUserConfigs)) % len(m.formUserConfigs)
	m.loadSelectedUserCredentialInput()
	m.refreshPathSuggestions()
}

func (m *model) currentFormUser() *formUserConfig {
	if len(m.formUserConfigs) == 0 || m.formUserCursor >= len(m.formUserConfigs) {
		return nil
	}
	return &m.formUserConfigs[m.formUserCursor]
}

func (m *model) storeSelectedUserCredentialInput() {
	user := m.currentFormUser()
	if user == nil {
		return
	}
	if user.AuthType == "password" {
		user.Password = m.formInputs[7].Value()
	} else {
		user.KeyValue = strings.TrimSpace(m.formInputs[7].Value())
	}
}

func (m *model) loadSelectedUserCredentialInput() {
	m.formInputs[7].SetValue("")
	user := m.currentFormUser()
	if user == nil {
		return
	}
	configureCredentialInput(&m.formInputs[7], user.AuthType, "Override")
	if user.AuthType == "password" {
		m.formInputs[7].SetValue(user.Password)
	} else {
		m.formInputs[7].SetValue(user.KeyValue)
	}
}

func configureCredentialInput(input *textinput.Model, authType string, mode string) {
	if authType == "password" {
		input.Placeholder = "Password"
		input.EchoMode = textinput.EchoPassword
		input.EchoCharacter = '•'
	} else {
		input.Placeholder = "SSH Key Path"
		input.EchoMode = textinput.EchoNormal
	}
}

func (m *model) syncFormUsers() {
	parsed := parseUsers(m.formInputs[6].Value())
	keep := make([]formUserConfig, 0, len(parsed))
	for _, uname := range parsed {
		var existing *formUserConfig
		for j := range m.formUserConfigs {
			if m.formUserConfigs[j].Username == uname {
				existing = &m.formUserConfigs[j]
				break
			}
		}
		if existing != nil {
			keep = append(keep, *existing)
		} else {
			keep = append(keep, formUserConfig{
				Username: uname,
				AuthType: "key",
			})
		}
	}
	m.formUserConfigs = keep
	if m.formUserCursor >= len(m.formUserConfigs) {
		m.formUserCursor = max(0, len(m.formUserConfigs)-1)
	}

	if m.formDefaultUser == "" && len(parsed) > 0 {
		m.formDefaultUser = parsed[0]
	} else if len(parsed) > 0 {
		found := false
		for _, p := range parsed {
			if p == m.formDefaultUser {
				found = true
				break
			}
		}
		if !found {
			m.formDefaultUser = parsed[0]
		}
	} else {
		m.formDefaultUser = ""
	}
}

func parseUsers(raw string) []string {
	parts := strings.Split(raw, ",")
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	return out
}

func splitKeyValue(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if strings.Contains(raw, "BEGIN ") || strings.Contains(raw, "\n") {
		return "", strings.ReplaceAll(raw, "\n", "\n")
	}
	return raw, ""
}

// renderCredentialInputWithGhost renders the credential text input and, when a
// path suggestion is active, appends the untyped completion suffix as greyed-out
// ghost text — the same inline-preview style used by fish shell.
func (m model) renderCredentialInputWithGhost() string {
	base := m.formInputs[7].View()
	user := m.currentFormUser()
	if user == nil || user.AuthType != "key" || len(m.formPathSuggestions) == 0 {
		return base
	}
	suggestion := m.formPathSuggestions[m.formPathSuggestIndex]
	current := strings.TrimSpace(m.formInputs[7].Value())
	if len(suggestion) <= len(current) || !strings.EqualFold(suggestion[:len(current)], current) {
		return base
	}
	return base + lipgloss.NewStyle().Foreground(subtle).Render(suggestion[len(current):])
}

func (m *model) activePathInput() (*textinput.Model, bool) {
	if m.formFocus == fSelectedUserCredential {
		if user := m.currentFormUser(); user != nil && user.AuthType == "key" {
			return &m.formInputs[7], true
		}
	}
	return nil, false
}

func (m *model) refreshPathSuggestions() {
	input, ok := m.activePathInput()
	if !ok {
		m.formPathSuggestions = nil
		m.formPathSuggestIndex = 0
		return
	}
	suggestions := completePathSuggestions(strings.TrimSpace(input.Value()))
	m.formPathSuggestions = suggestions
	if len(suggestions) == 0 {
		m.formPathSuggestIndex = 0
		return
	}
	if m.formPathSuggestIndex >= len(suggestions) {
		m.formPathSuggestIndex = 0
	}
}

func (m *model) cyclePathSuggestion(delta int) bool {
	if len(m.formPathSuggestions) == 0 {
		return false
	}
	m.formPathSuggestIndex = (m.formPathSuggestIndex + delta + len(m.formPathSuggestions)) % len(m.formPathSuggestions)
	return true
}

func (m *model) acceptPathSuggestion() bool {
	input, ok := m.activePathInput()
	if !ok || len(m.formPathSuggestions) == 0 {
		return false
	}
	suggestion := m.formPathSuggestions[m.formPathSuggestIndex]
	input.SetValue(suggestion)
	input.CursorEnd()
	if m.formFocus == fSelectedUserCredential {
		m.storeSelectedUserCredentialInput()
	}
	m.refreshPathSuggestions()
	return true
}

func completePathSuggestions(raw string) []string {
	if raw == "" {
		raw = "~/.ssh/"
	}
	if strings.Contains(raw, "BEGIN ") || strings.Contains(raw, "\n") {
		return nil
	}

	expanded := expandUserPath(raw)
	dirPart := expanded
	prefix := ""
	if !strings.HasSuffix(expanded, string(os.PathSeparator)) {
		dirPart = filepath.Dir(expanded)
		prefix = filepath.Base(expanded)
	}
	if dirPart == "" {
		dirPart = "."
	}

	entries, err := os.ReadDir(dirPart)
	if err != nil {
		return nil
	}

	var matches []string
	for _, entry := range entries {
		name := entry.Name()
		if prefix != "" && !strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
			continue
		}
		full := filepath.Join(dirPart, name)
		display := collapseUserPath(full)
		if entry.IsDir() {
			display += string(os.PathSeparator)
		}
		matches = append(matches, display)
	}
	sort.Strings(matches)
	if len(matches) > 8 {
		matches = matches[:8]
	}
	return matches
}

func expandUserPath(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}

func collapseUserPath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return path
	}
	if path == home {
		return "~"
	}
	prefix := home + string(os.PathSeparator)
	if strings.HasPrefix(path, prefix) {
		return "~/" + strings.TrimPrefix(path, prefix)
	}
	return path
}

func cloneFormBytes(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	out := make([]byte, len(src))
	copy(out, src)
	return out
}

func (m model) identityConflicts(alias, hostname string) (bool, bool) {
	alias = strings.TrimSpace(alias)
	hostname = strings.TrimSpace(hostname)
	aliasConflict := false
	hostnameConflict := false
	for _, existing := range m.store.Hosts {
		if m.formEditing != "" && existing.ID == m.formEditing {
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

func identityConflictMessage(aliasConflict, hostnameConflict bool) string {
	switch {
	case aliasConflict && hostnameConflict:
		return "Alias and hostname/IP already exist. Change both before saving"
	case aliasConflict:
		return "A host with this alias already exists"
	case hostnameConflict:
		return "A host record for this hostname/IP already exists"
	default:
		return ""
	}
}

func (m model) renderPathSuggestions(contentW int) string {
	if len(m.formPathSuggestions) == 0 {
		return ""
	}
	itemW := max(20, contentW-2)
	var b strings.Builder
	b.WriteString(hintStyle.Render("  Suggestions (→/end/tab accept • ctrl+↑↓ cycle):") + "\n")

	for i, s := range m.formPathSuggestions {
		label := truncateForWidth(s, itemW-4)
		prefix := "  "
		style := lipgloss.NewStyle().Foreground(subtle)
		if i == m.formPathSuggestIndex {
			prefix = "▸ "
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("#111827")).Background(highlight).Bold(true).Padding(0, 1)
		}
		line := prefix + label
		b.WriteString("  " + style.Render(line) + "\n")
	}

	return b.String()
}

func truncateForWidth(s string, width int) string {
	if width <= 3 {
		return s
	}
	r := []rune(s)
	if len(r) <= width {
		return s
	}
	return string(r[:width-3]) + "..."
}
