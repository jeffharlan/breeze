package heartbeat

import (
	"slices"
	"testing"

	"github.com/breeze-rmm/agent/internal/opsign"
)

func TestEveryRegisteredTypeHasATier(t *testing.T) {
	known := opsign.KnownTypes()
	for k := range handlerRegistry {
		if !slices.Contains(known, k) {
			t.Errorf("handlerRegistry key %q has no entry in the opsign tier table", k)
		}
	}
}

func TestNoStaleTierEntries(t *testing.T) {
	for _, k := range opsign.KnownTypes() {
		if _, ok := handlerRegistry[k]; !ok {
			t.Errorf("tier table entry %q is not a handlerRegistry key", k)
		}
	}
}

func TestUnknownTypeIsTierA(t *testing.T) {
	if got := opsign.TierOf("brand_new_command"); got != opsign.TierA {
		t.Errorf("TierOf(unknown) = %v, want TierA", got)
	}
}

// The Tier A names listed in spec section 1. Names the registry does not have are
// skipped, so this stays valid if one is renamed or retired.
func TestDesignTierAListIsTierA(t *testing.T) {
	designTierA := []string{
		"script", "run_script", "task_run", "computer_action", "http_request",
		"network_http_check", "terminal_start", "start_desktop", "desktop_stream_start", "tunnel_open",
		"software_install", "software_update", "software_uninstall", "install_patches",
		"rollback_patches", "oem_update_run", "homebrew_bootstrap",
		"dev_update", "agent_rollback_v1", "set_auto_update", "self_uninstall",
		"actuate_elevation", "pam_apply_v2", "pam_cleanup_v2", "pam_reconcile_v2",
		"apply_cis_remediation", "apply_audit_policy_baseline", "manage_startup_item",
		"peripheral_policy_sync", "peripheral_policy_sync_v2", "vault_configure",
		"file_write", "file_copy", "file_rename", "file_mkdir", "file_delete",
		"secure_delete_file", "encrypt_file", "file_trash_purge", "file_trash_restore",
		"registry_set", "registry_delete", "registry_key_create", "registry_key_delete",
		"bare_metal_rebuild", "bmr_recover", "vm_restore_from_backup", "vm_instant_boot",
		"backup_restore", "mssql_restore", "hyperv_restore", "hyperv_checkpoint",
		"backup_cleanup", "execute_containment", "release_containment",
		"security_threat_restore", "encryption_rotate_key", "system_cleanup_run",
		"backup_run", "mssql_backup", "hyperv_backup", "security_threat_remove",
		"security_threat_quarantine", "quarantine_file",
		"time_apply_policy", "time_set_timezone",
	}
	checked := 0
	for _, k := range designTierA {
		if _, ok := handlerRegistry[k]; !ok {
			continue
		}
		checked++
		if got := opsign.TierOf(k); got != opsign.TierA {
			t.Errorf("TierOf(%q) = %v, spec section 1 lists it as Tier A", k, got)
		}
	}
	if checked < 60 {
		t.Errorf("only %d spec Tier A names found in the registry; the list or registry has drifted", checked)
	}
}

func TestSessionTypes(t *testing.T) {
	for _, k := range []string{"terminal_start", "start_desktop", "desktop_stream_start", "tunnel_open"} {
		if !opsign.IsSessionType(k) {
			t.Errorf("IsSessionType(%q) = false, want true", k)
		}
	}
	for _, k := range []string{"terminal_data", "terminal_resize", "tunnel_data", "desktop_input", "desktop_config", "terminal_stop", "file_write", "script"} {
		if opsign.IsSessionType(k) {
			t.Errorf("IsSessionType(%q) = true, want false", k)
		}
	}
}
