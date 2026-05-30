package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "output.json")
	data := []byte(`{"ok":true}`)

	if err := AtomicWrite(path, data, 0600); err != nil {
		t.Fatalf("AtomicWrite failed: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("content mismatch: got %q want %q", got, data)
	}
}

func TestAtomicWritePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.json")

	if err := AtomicWrite(path, []byte("x"), 0600); err != nil {
		t.Fatalf("AtomicWrite failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected perm 0600, got %04o", perm)
	}
}

func TestAtomicWriteOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.json")

	if err := AtomicWrite(path, []byte("first"), 0600); err != nil {
		t.Fatalf("first AtomicWrite failed: %v", err)
	}
	if err := AtomicWrite(path, []byte("second"), 0600); err != nil {
		t.Fatalf("second AtomicWrite failed: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("expected %q, got %q", "second", got)
	}
}

func TestAtomicWriteLeavesNoTempOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.json")

	if err := AtomicWrite(path, []byte("ok"), 0600); err != nil {
		t.Fatalf("AtomicWrite failed: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "data.json" {
			t.Fatalf("unexpected leftover file: %q", e.Name())
		}
	}
}
