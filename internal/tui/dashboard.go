package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/mylovelytools/managedssh/internal/host"
	"github.com/mylovelytools/managedssh/internal/sshclient"
	"github.com/mylovelytools/managedssh/internal/vault"
)

// ------------------------------------------------------------------
// Update
// ------------------------------------------------------------------

func (m model) updateDashboard(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.searchFocused {
		return m.updateDashboardSearch(msg)
	}
	return m.updateDashboardNormal(msg)
}

func (m model) updateDashboardSearch(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			m.searchFocused = false
			m.search.Blur()
			m.search.Reset()
			m = m.refreshFiltered()
			return m, nil
		case "enter", "down":
			m.searchFocused = false
			m.search.Blur()
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.search, cmd = m.search.Update(msg)
	m = m.refreshFiltered()
	return m, cmd
}

func (m model) updateDashboardNormal(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	m.connErr = ""

	if m.confirmDelete && key.String() != "d" {
		m.confirmDelete = false
	}

	switch key.String() {
	case "q":
		m.quitting = true
		return m, tea.Quit
	case "l":
		m = m.toLockedSession()
		return m, textinput.Blink
	case "c":
		m.phase = phaseChangeKeyInit
		m.input = newPasswordInput("Current master key...")
		m.err = ""
		return m, textinput.Blink
	case "x":
		m.phase = phaseExportAuth
		m.exportErr = ""
		m.exportDir = ""
		m.input = newPasswordInput("Enter master key to export backup...")
		return m, textinput.Blink
	case "i":
		return m.startImportFlow()
	case "h":
		if m.healthChecking {
			return m, nil
		}
		m.healthChecking = true
		return m, healthCheckAllCmd(m.store.Hosts, m.encKey)
	case "j", "down":
		if len(m.filtered) > 0 {
			m.hostCursor = (m.hostCursor + 1) % len(m.filtered)
		}
	case "k", "up":
		if len(m.filtered) > 0 {
			m.hostCursor = (m.hostCursor - 1 + len(m.filtered)) % len(m.filtered)
		}
	case "/":
		m.searchFocused = true
		m.search.Focus()
		return m, textinput.Blink
	case "esc":
		if m.search.Value() != "" {
			m.search.Reset()
			m = m.refreshFiltered()
		}
	case "a":
		m, cmd := m.startHostForm("", false)
		return m, cmd
	case "s":
		m.phase = phaseSSHImport
		m.input = newSSHCommandInput()
		m.err = ""
		return m, textinput.Blink
	case "e":
		if len(m.filtered) > 0 {
			h := m.filtered[m.hostCursor]
			m, cmd := m.startHostForm(h.ID, false)
			return m, cmd
		}
	case "y":
		if len(m.filtered) > 0 {
			h := m.filtered[m.hostCursor]
			m, cmd := m.startHostForm(h.ID, true)
			return m, cmd
		}
	case "d":
		if len(m.filtered) > 0 {
			if m.confirmDelete {
				h := m.filtered[m.hostCursor]
				if err := m.store.Delete(h.ID); err != nil {
					m.connErr = "Delete failed: " + err.Error()
				}
				m.confirmDelete = false
				m = m.refreshFiltered()
			} else {
				m.confirmDelete = true
			}
		}
	case "enter":
		if len(m.filtered) > 0 {
			h := m.filtered[m.hostCursor]
			users := h.AccountNames()
			if len(users) == 0 {
				m.connErr = "No users configured for this host"
				return m, nil
			}
			if len(users) == 1 {
				return m.connectSSH(h, users[0])
			}
			return m.startUserSelect(h), nil
		}
	}
	return m, nil
}

func (m model) connectSSH(h host.Host, user string) (tea.Model, tea.Cmd) {
	_, resolved, ok := h.ResolveAccount(user)
	if !ok {
		m.connErr = "Selected user is no longer available"
		return m, nil
	}

	// If key auth with no saved passphrase, check locally if one is needed.
	if resolved.AuthType == "key" && len(resolved.EncKeyPass) == 0 {
		var keyData []byte
		if len(resolved.EncKey) > 0 {
			dec, err := vault.Decrypt(m.encKey, resolved.EncKey)
			if err == nil {
				keyData = dec
			}
		}
		needsPass := sshclient.NeedsPassphrase(resolved.KeyPath, keyData)
		zeroBytes(keyData)
		if needsPass {
			return m.startKeyPassphrasePrompt(h, user, resolved), nil
		}
	}

	return m.connectSSHWithResolved(h, user, resolved, nil, false)
}

func (m model) connectSSHWithResolved(h host.Host, user string, resolved host.ResolvedAuth, promptPassphrase []byte, savePrompt bool) (tea.Model, tea.Cmd) {
	m.phase = phaseDashboard
	m.selectedHost = host.Host{}
	m.connErr = ""

	var password []byte
	var keyData []byte
	var keyPath string
	var keyPassphrase []byte

	if resolved.AuthType == "password" && len(resolved.Password) > 0 {
		dec, err := vault.Decrypt(m.encKey, resolved.Password)
		if err == nil {
			password = dec
		}
	}
	if resolved.AuthType == "key" {
		keyPath = resolved.KeyPath
		if len(resolved.EncKey) > 0 {
			dec, err := vault.Decrypt(m.encKey, resolved.EncKey)
			if err == nil {
				keyData = dec
			}
		}
		if len(promptPassphrase) > 0 {
			keyPassphrase = append([]byte(nil), promptPassphrase...)
		} else if len(resolved.EncKeyPass) > 0 {
			dec, err := vault.Decrypt(m.encKey, resolved.EncKeyPass)
			if err == nil {
				keyPassphrase = dec
			}
		}
	}

	sess := &sshclient.Session{
		Host:          h.Hostname,
		Port:          h.Port,
		DialTimeout:   hostDialTimeout(h),
		User:          user,
		Password:      password,
		KeyPath:       keyPath,
		KeyData:       keyData,
		KeyPassphrase: keyPassphrase,
	}

	m.connectHost = h
	m.connectUser = user
	m.connectResolved = resolved
	m.pendingKeyPassSave = savePrompt
	if !savePrompt {
		zeroBytes(m.pendingKeyPassphrase)
		m.pendingKeyPassphrase = nil
	}
	m.connectPassphraseInput.Reset()

	return m, tea.Exec(sess, func(err error) tea.Msg {
		return sshDoneMsg{err: err}
	})
}

func (m model) startKeyPassphrasePrompt(h host.Host, user string, resolved host.ResolvedAuth) model {
	m.phase = phaseKeyPassphrasePrompt
	m.connectHost = h
	m.connectUser = user
	m.connectResolved = resolved
	m.connectPassphraseInput = newKeyPassphraseInput()
	m.connErr = ""
	return m
}

func (m model) startUserSelect(h host.Host) model {
	m.phase = phaseUserSelect
	m.selectedHost = h
	m.userCursor = 0
	if h.DefaultUser != "" {
		for i, u := range h.AccountNames() {
			if u == h.DefaultUser {
				m.userCursor = i
				break
			}
		}
	}
	m.connErr = ""
	return m
}

// ------------------------------------------------------------------
// View
// ------------------------------------------------------------------

func (m model) viewDashboard() string {
	w := m.width
	if w < 40 {
		w = 40
	}
	h := m.height
	if h < 15 {
		h = 15
	}

	contentW := w - 4
	panelH := h - 7
	if panelH < 10 {
		panelH = 10
	}

	// Title
	title := titleStyle.Render("⚡ ManagedSSH")

	// Search bar
	searchIcon := lipgloss.NewStyle().Foreground(subtle).Render("🔍 ")
	if m.searchFocused {
		searchIcon = lipgloss.NewStyle().Foreground(highlight).Render("🔍 ")
	}
	searchLine := " " + searchIcon + m.search.View()
	if m.search.Value() != "" && !m.searchFocused {
		count := fmt.Sprintf("  %d/%d", len(m.filtered), len(m.store.Hosts))
		searchLine += lipgloss.NewStyle().Foreground(subtle).Render(count)
	}

	var leftW, rightW, leftH, detailH, cmdH int
	var panels string

	if w < 75 {
		// Stack panels vertically on narrow screens
		leftW = contentW
		rightW = contentW

		leftH = panelH * 45 / 100
		detailH = panelH * 35 / 100
		cmdH = panelH - leftH - detailH

		if leftH < 5 {
			leftH = 5
		}
		if detailH < 5 {
			detailH = 5
		}
		if cmdH < 5 {
			cmdH = 5
		}

		hostContent := m.renderHostList(leftW-4, leftH-4)
		leftPanel := panelBorder.Width(leftW).Height(leftH).Render(panelTitleStyle.Render(" Hosts") + "\n\n" + hostContent)

		detailContent := m.renderDetails()
		detailPanel := panelBorder.Width(rightW).Height(detailH).Render(panelTitleStyle.Render(" Server Details") + "\n\n" + detailContent)

		cmdContent := m.renderCommands(rightW - 4)
		cmdPanel := panelBorder.Width(rightW).Height(cmdH).Render(panelTitleStyle.Render(" Commands") + "\n\n" + cmdContent)

		panels = lipgloss.JoinVertical(lipgloss.Left, leftPanel, detailPanel, cmdPanel)
	} else {
		// Side-by-side split
		leftW = contentW * 55 / 100
		rightW = contentW - leftW - 1

		cmdContent := m.renderCommands(rightW - 4)
		// Commands panel must be tall enough for all lines, otherwise lipgloss will
		// grow it and break side-by-side alignment.
		cmdH = lipgloss.Height(cmdContent) + 2
		if cmdH < 6 {
			cmdH = 6
		}

		detailH = panelH - cmdH - 2
		if detailH < 5 {
			detailH = 5
			panelH = detailH + cmdH + 2
		}
		leftH = panelH

		hostContent := m.renderHostList(leftW-4, leftH-4)
		leftPanel := panelBorder.Width(leftW).Height(leftH).Render(panelTitleStyle.Render(" Hosts") + "\n\n" + hostContent)

		detailContent := m.renderDetails()
		detailPanel := panelBorder.Width(rightW).Height(detailH).Render(panelTitleStyle.Render(" Server Details") + "\n\n" + detailContent)

		cmdPanel := panelBorder.Width(rightW).Height(cmdH).Render(panelTitleStyle.Render(" Commands") + "\n\n" + cmdContent)

		rightPanel := lipgloss.JoinVertical(lipgloss.Left, detailPanel, cmdPanel)
		leftPanelHeight := lipgloss.Height(leftPanel)
		rightPanelHeight := lipgloss.Height(rightPanel)
		if rightPanelHeight < leftPanelHeight {
			rightPanel = lipgloss.NewStyle().Height(leftPanelHeight).Render(rightPanel)
		} else if rightPanelHeight > leftPanelHeight {
			leftPanel = lipgloss.NewStyle().Height(rightPanelHeight).Render(leftPanel)
		}
		panels = lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, " ", rightPanel)
	}

	view := title + "\n" + searchLine + "\n\n" + panels
	if m.healthChecking {
		view += "\n" + hintStyle.Render(" Running health check across all saved hosts...")
	}

	if m.connErr != "" {
		errBanner := errorStyle.Render(" ✗ " + m.connErr)
		view += "\n" + errBanner
	}

	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, view)
}

// ------------------------------------------------------------------
// Render helpers
// ------------------------------------------------------------------

func (m model) renderHostList(maxW, maxH int) string {
	if len(m.filtered) == 0 {
		empty := "No hosts yet.\n\nPress " +
			cmdKeyStyle.Render("a") + " to add your first host."
		return lipgloss.NewStyle().Foreground(subtle).Render(empty)
	}

	// Column widths — adapt to available space.
	available := maxW - 6
	if available < 10 {
		available = 10
	}
	colAlias := available * 40 / 100
	colHost := available - colAlias

	var b strings.Builder

	// Rows
	visible := maxH - 1 // account for scroll hint
	if visible < 1 {
		visible = 1
	}
	offset := 0
	if m.hostCursor >= visible {
		offset = m.hostCursor - visible + 1
	}
	end := offset + visible
	if end > len(m.filtered) {
		end = len(m.filtered)
	}

	for i := offset; i < end; i++ {
		h := m.filtered[i]
		indicator := m.healthIndicator(m.hostHealth(h.ID))

		cursor := "  "
		style := lipgloss.NewStyle().Foreground(text)
		if i == m.hostCursor {
			cursor = "▸ "
			style = lipgloss.NewStyle().Foreground(highlight).Bold(true)
		}

		alias := truncate(h.Alias, colAlias)
		aliasStr := fmt.Sprintf("%-*s", colAlias, alias)

		hostStr := h.Hostname
		if h.Group != "" {
			groupTag := lipgloss.NewStyle().Foreground(subtle).Bold(false).Render("[" + h.Group + "]")
			hostStr += " " + groupTag
		}
		hostColStr := lipgloss.NewStyle().Width(colHost).MaxWidth(colHost).Render(hostStr)

		line := fmt.Sprintf("%s%s %s %s", cursor, indicator, aliasStr, hostColStr)
		b.WriteString(style.Render(line))
		if i < end-1 {
			b.WriteByte('\n')
		}
	}

	if len(m.filtered) > visible {
		b.WriteString("\n" + hintStyle.Render(fmt.Sprintf("  ↕ %d hosts total", len(m.filtered))))
	}

	return b.String()
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 1 {
		return "…"
	}
	return s[:maxLen-1] + "…"
}

func (m model) renderDetails() string {
	if len(m.filtered) == 0 {
		return hintStyle.Render("  No host selected")
	}
	h := m.filtered[m.hostCursor]

	var users []string
	for _, account := range h.Accounts {
		label := account.Username
		if len(h.Accounts) > 1 && h.DefaultUser == account.Username {
			label += "*"
		}
		if account.AuthType == "password" {
			label += " (Pass)"
		} else {
			label += " (Key)"
		}
		users = append(users, label)
	}

	render := func(label, value string) string {
		return detailLabelStyle.Render("  "+label) + detailValueStyle.Render(value)
	}

	lines := []string{
		render("Health", healthLabel(m.hostHealth(h.ID))),
		render("Alias", h.Alias),
		render("Host", h.Hostname),
		render("Users", strings.Join(users, ", ")),
		render("Port", fmt.Sprintf("%d", h.Port)),
		render("Timeout", fmt.Sprintf("%ds", h.TimeoutSec)),
		render("Group", h.Group),
		render("Tags", strings.Join(h.Tags, ", ")),
	}
	return strings.Join(lines, "\n")
}

func (m model) renderCommands(maxW int) string {
	if m.confirmDelete {
		return errorStyle.Render("  Press d to confirm delete") + "\n" +
			hintStyle.Render("  Any other key to cancel")
	}

	cmd := func(key, desc string) string {
		return cmdKeyStyle.Render(key) + cmdDescStyle.Render(" "+desc)
	}
	pad := func(s string, w int) string {
		return lipgloss.NewStyle().Width(w).Render(s)
	}

	col := maxW / 2
	if col < 12 {
		col = 12
	}
	if col > 25 {
		col = 25
	}
	return "  " + pad(cmd("/", "Search"), col) + cmd("l", "Lock Session") + "\n" +
		"  " + pad(cmd("a", "Add"), col) + cmd("s", "Quick Add") + "\n" +
		"  " + pad(cmd("e", "Edit"), col) + cmd("y", "Duplicate") + "\n" +
		"  " + pad(cmd("d", "Delete"), col) + cmd("h", "Health Check") + "\n" +
		"  " + pad(cmd("c", "Change Master Key"), col) + cmd("x", "Export Backup") + "\n" +
		"  " + pad(cmd("i", "Import Backup"), col) + cmd("⏎", "Connect") + "\n" +
		"  " + cmd("q", "Quit")
}

func (m model) updateUserSelect(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	users := m.selectedHost.AccountNames()
	if len(users) == 0 {
		m.phase = phaseDashboard
		return m, nil
	}

	switch key.String() {
	case "esc":
		m.phase = phaseDashboard
		return m, nil
	case "j", "down":
		if m.userCursor < len(users)-1 {
			m.userCursor++
		}
	case "k", "up":
		if m.userCursor > 0 {
			m.userCursor--
		}
	case "enter":
		return m.connectSSH(m.selectedHost, users[m.userCursor])
	}

	return m, nil
}

func (m model) viewUserSelect() string {
	users := m.selectedHost.AccountNames()

	var b strings.Builder
	b.WriteString(titleStyle.Render("Choose SSH User") + "\n")
	b.WriteString(subtitleStyle.Render(m.selectedHost.Alias+" • "+m.selectedHost.Hostname) + "\n\n")

	for i, user := range users {
		prefix := "  "
		style := lipgloss.NewStyle().Foreground(text)
		if i == m.userCursor {
			prefix = "▸ "
			style = lipgloss.NewStyle().Foreground(highlight).Bold(true)
		}
		b.WriteString(style.Render(prefix + user + userSummarySuffix(m.selectedHost, user)))
		if i < len(users)-1 {
			b.WriteByte('\n')
		}
	}

	b.WriteString("\n\n")
	b.WriteString(statusBarStyle.Render("↑↓ navigate • enter connect • esc back"))
	return boxStyle.Render(b.String())
}

func userSummarySuffix(h host.Host, username string) string {
	_, resolved, ok := h.ResolveAccount(username)
	if !ok {
		return ""
	}
	badge := ""
	if h.DefaultUser == username {
		badge = " [★ default]"
	}
	if resolved.AuthType == "password" {
		return "  [password]" + badge
	}
	return "  [key]" + badge
}
