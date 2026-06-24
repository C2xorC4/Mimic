package control

import (
	"testing"

	"github.com/c2xorc4/mimic/internal/config"
)

func TestApplyPatchProfile(t *testing.T) {
	cfg := &config.AppConfig{Profile: "Windows 10", Services: []string{"smb"}}
	p := "Windows 11"
	if err := ApplyPatch(cfg, ConfigPatch{Profile: &p}); err != nil {
		t.Fatal(err)
	}
	if cfg.Profile != "Windows 11" {
		t.Fatalf("profile = %q", cfg.Profile)
	}
}

func TestApplyPatchEmpty(t *testing.T) {
	cfg := &config.AppConfig{}
	if err := ApplyPatch(cfg, ConfigPatch{}); err != errEmptyPatch {
		t.Fatalf("err = %v, want empty patch", err)
	}
}

func TestApplyPatchLoggingPartial(t *testing.T) {
	cfg := &config.AppConfig{
		Logging: config.LogConfig{Level: "info", JSONMode: true, ToStdout: false},
	}
	dbg := "debug"
	if err := ApplyPatch(cfg, ConfigPatch{Logging: &LoggingPatch{Level: &dbg}}); err != nil {
		t.Fatal(err)
	}
	if cfg.Logging.Level != "debug" || !cfg.Logging.JSONMode || cfg.Logging.ToStdout {
		t.Fatalf("logging = %+v", cfg.Logging)
	}
}

func TestNormalizeLogName(t *testing.T) {
	for _, c := range []struct {
		in, want string
	}{
		{"events", "events.log"},
		{"mimic.log", "mimic.log"},
		{"probes", "probes.log"},
	} {
		got, err := NormalizeLogName(c.in)
		if err != nil || got != c.want {
			t.Fatalf("NormalizeLogName(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	if _, err := NormalizeLogName("secret"); err == nil {
		t.Fatal("expected error for unknown log")
	}
}

