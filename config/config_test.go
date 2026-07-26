package config

import (
	"testing"
)

func TestValidateVersion(t *testing.T) {
	t.Run("valid version", func(t *testing.T) {
		err := ValidateVersion(&Config{Version: CurrentSchemaVersion})
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("unset version", func(t *testing.T) {
		err := ValidateVersion(&Config{Version: 0})
		if err != nil {
			t.Errorf("expected nil (warning only) for unset version, got %v", err)
		}
	})

	t.Run("wrong version", func(t *testing.T) {
		err := ValidateVersion(&Config{Version: 999})
		if err == nil {
			t.Error("expected error for wrong version")
		}
	})
}

func TestCurrentSchemaVersion(t *testing.T) {
	if CurrentSchemaVersion != 1 {
		t.Errorf("expected 1, got %d", CurrentSchemaVersion)
	}
}

func TestDefaultFileName(t *testing.T) {
	if DefaultFileName != "config.yaml" {
		t.Errorf("expected 'config.yaml', got %q", DefaultFileName)
	}
}
