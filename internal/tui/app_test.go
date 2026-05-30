package tui

import "testing"

func TestZeroBytes(t *testing.T) {
	data := []byte{1, 2, 3}
	zeroBytes(data)
	for i, v := range data {
		if v != 0 {
			t.Fatalf("expected data[%d] to be zero, got %d", i, v)
		}
	}
}

func TestNewPasswordInputDefaults(t *testing.T) {
	in := newPasswordInput("Enter password")
	if in.Placeholder != "Enter password" {
		t.Fatalf("unexpected placeholder: %q", in.Placeholder)
	}
	if in.CharLimit != 128 {
		t.Fatalf("unexpected char limit: got %d want %d", in.CharLimit, 128)
	}
}

func TestNewSearchInputDefaults(t *testing.T) {
	in := newSearchInput()
	if in.CharLimit != 64 {
		t.Fatalf("unexpected char limit: got %d want %d", in.CharLimit, 64)
	}
	if in.Placeholder == "" {
		t.Fatal("expected search placeholder to be set")
	}
}

func TestModelViewWhenQuitting(t *testing.T) {
	m := model{quitting: true}
	if got := m.View(); got != "" {
		t.Fatalf("expected empty view while quitting, got %q", got)
	}
}

func TestSshDoneMsgZeroesPassphraseOnSuccessWithoutSave(t *testing.T) {
	m := model{
		phase:                phaseDashboard,
		pendingKeyPassSave:   false,
		pendingKeyPassphrase: []byte("secret"),
	}

	result, _ := m.Update(sshDoneMsg{err: nil})
	rm := result.(model)

	if rm.pendingKeyPassphrase != nil {
		t.Fatal("expected pendingKeyPassphrase to be nil after success without save")
	}
	if rm.pendingKeyPassSave {
		t.Fatal("expected pendingKeyPassSave to be false after success without save")
	}
}
