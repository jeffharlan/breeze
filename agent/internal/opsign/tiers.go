package opsign

import (
	"maps"
	"slices"
)

// Tier says how much operator approval a command needs. TierA needs a signed
// approval under enforce; TierB (outage-only) and TierC (reads, telemetry,
// session frames) do not.
type Tier int

const (
	TierA Tier = iota
	TierB
	TierC
)

// tiers has one entry per handlerRegistry key; the completeness tests in
// internal/heartbeat fail on a missing or stale entry. Types not listed are
// TierA, so a new command is gated until someone classifies it.
var tiers = map[string]Tier{
	"actuate_elevation":           TierA,
	"agent_rollback_v1":           TierA,
	"apply_audit_policy_baseline": TierA,
	"apply_cis_remediation":       TierA,
	"backup_cleanup":              TierA,
	"backup_restore":              TierA,
	"backup_run":                  TierA,
	"backup_test_restore":         TierA,
	"bare_metal_rebuild":          TierA,
	"bmr_recover":                 TierA,
	"computer_action":             TierA,
	"desktop_stream_start":        TierA,
	"dev_update":                  TierA,
	"encrypt_file":                TierA,
	"encryption_rotate_key":       TierA,
	"execute_containment":         TierA,
	"file_copy":                   TierA,
	"file_delete":                 TierA,
	"file_mkdir":                  TierA,
	"file_rename":                 TierA,
	"file_trash_purge":            TierA,
	"file_trash_restore":          TierA,
	"file_write":                  TierA,
	"homebrew_bootstrap":          TierA,
	"http_request":                TierA,
	"hyperv_backup":               TierA,
	"hyperv_checkpoint":           TierA,
	"hyperv_restore":              TierA,
	"install_patches":             TierA,
	"manage_startup_item":         TierA,
	"mssql_backup":                TierA,
	"mssql_restore":               TierA,
	"network_http_check":          TierA,
	"oem_update_release":          TierA,
	"oem_update_run":              TierA,
	"pam_apply_v2":                TierA,
	"pam_cleanup_v2":              TierA,
	"pam_reconcile_v2":            TierA,
	"peripheral_policy_sync":      TierA,
	"peripheral_policy_sync_v2":   TierA,
	"quarantine_file":             TierA,
	"registry_delete":             TierA,
	"registry_key_create":         TierA,
	"registry_key_delete":         TierA,
	"registry_set":                TierA,
	"release_containment":         TierA,
	"rollback_patches":            TierA,
	"run_script":                  TierA,
	"script":                      TierA,
	"secure_delete_file":          TierA,
	"security_threat_quarantine":  TierA,
	"security_threat_remove":      TierA,
	"security_threat_restore":     TierA,
	"self_uninstall":              TierA,
	"set_auto_update":             TierA,
	"software_install":            TierA,
	"software_uninstall":          TierA,
	"software_update":             TierA,
	"start_desktop":               TierA,
	"system_cleanup_run":          TierA,
	"task_run":                    TierA,
	"terminal_start":              TierA,
	"time_apply_policy":           TierA,
	"time_set_timezone":           TierA,
	"tunnel_open":                 TierA,
	"vault_configure":             TierA,
	"vm_instant_boot":             TierA,
	"vm_restore_from_backup":      TierA,

	"backup_stop":               TierB,
	"cancel_reboot":             TierB,
	"chat_close":                TierB,
	"chat_message":              TierB,
	"chat_open":                 TierB,
	"desktop_stream_stop":       TierB,
	"download_patches":          TierB,
	"force_reboot":              TierB,
	"hyperv_vm_state":           TierB,
	"kill_process":              TierB,
	"lock":                      TierB,
	"network_diagnostic_cancel": TierB,
	"notify_user":               TierB,
	"pam_request_notify":        TierB,
	"reboot":                    TierB,
	"reboot_safe_mode":          TierB,
	"restart_service":           TierB,
	"retract_message":           TierB,
	"schedule_reboot":           TierB,
	"script_cancel":             TierB,
	"security_scan":             TierB,
	"set_log_level":             TierB,
	"shutdown":                  TierB,
	"start_service":             TierB,
	"stop_desktop":              TierB,
	"stop_service":              TierB,
	"support_end":               TierB,
	"task_disable":              TierB,
	"task_enable":               TierB,
	"terminal_stop":             TierB,
	"time_resync":               TierB,
	"tray_update":               TierB,
	"tunnel_close":              TierB,
	"vault_sync":                TierB,
	"wake_on_lan":               TierB,

	// terminal_data, terminal_resize, tunnel_data, desktop_input and desktop_config are
	// frames inside an already-approved session; the live-session check covers them.
	"backup_list":                 TierC,
	"backup_verify":               TierC,
	"caller_verify":               TierC,
	"capture_pprof":               TierC,
	"cis_benchmark":               TierC,
	"collect_audit_policy":        TierC,
	"collect_boot_performance":    TierC,
	"collect_evidence":            TierC,
	"collect_reliability_metrics": TierC,
	"collect_software":            TierC,
	"desktop_config":              TierC,
	"desktop_input":               TierC,
	"diag_file_list":              TierC,
	"diag_file_read":              TierC,
	"encryption_collect_keys":     TierC,
	"event_log_get":               TierC,
	"event_logs_list":             TierC,
	"event_logs_query":            TierC,
	"file_list":                   TierC,
	"file_list_drives":            TierC,
	"file_read":                   TierC,
	"file_trash_list":             TierC,
	"filesystem_analysis":         TierC,
	"get_process":                 TierC,
	"get_reboot_status":           TierC,
	"get_service":                 TierC,
	"hardware_profile":            TierC,
	"hyperv_discover":             TierC,
	"list_processes":              TierC,
	"list_services":               TierC,
	"list_sessions":               TierC,
	"mssql_discover":              TierC,
	"mssql_verify":                TierC,
	"network_diagnostic":          TierC,
	"network_discovery":           TierC,
	"network_dns_check":           TierC,
	"network_ping":                TierC,
	"network_tcp_check":           TierC,
	"oem_observe":                 TierC,
	"patch_scan":                  TierC,
	"refresh_inventory":           TierC,
	"registry_get":                TierC,
	"registry_keys":               TierC,
	"registry_values":             TierC,
	"script_list_running":         TierC,
	"security_collect_status":     TierC,
	"sensitive_data_scan":         TierC,
	"snmp_poll":                   TierC,
	"system_cleanup_list":         TierC,
	"system_state_collect":        TierC,
	"take_screenshot":             TierC,
	"task_get":                    TierC,
	"task_history":                TierC,
	"tasks_list":                  TierC,
	"terminal_data":               TierC,
	"terminal_resize":             TierC,
	"topology_interface_poll":     TierC,
	"tunnel_data":                 TierC,
	"vault_status":                TierC,
	"vm_restore_estimate":         TierC,
	"vss_status":                  TierC,
	"vss_writer_list":             TierC,
}

// TierOf returns the tier of a command type; unknown types are TierA.
func TierOf(commandType string) Tier {
	if t, ok := tiers[commandType]; ok {
		return t
	}
	return TierA
}

// KnownTypes lists every classified command type, sorted.
func KnownTypes() []string {
	return slices.Sorted(maps.Keys(tiers))
}

// IsSessionType reports whether a command opens an interactive session.
func IsSessionType(commandType string) bool {
	return sessionTypes[commandType]
}
