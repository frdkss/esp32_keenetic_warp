"""Real C++ Monitor + Network + KeeneticClient with synthetic I/O and NVS.
No board, router, owner credentials, or network connection is used.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_stage5_network import ROOT, compile_native


@unittest.skipUnless(os.name == "nt", "Native Windows/MSVC test harness")
class MonitorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="warp-monitor-")
        cls.work = Path(cls.temporary.name)
        fake = cls.work / "fake/mbedtls"
        fake.mkdir(parents=True)
        for name, declaration in (("md5", "int mbedtls_md5(const unsigned char*, std::size_t, unsigned char*);"),
                                  ("sha256", "int mbedtls_sha256(const unsigned char*, std::size_t, unsigned char*, int);")):
            (fake / (name + ".h")).write_text("#pragma once\n#include <cstddef>\n" + declaration + "\n")
        cls.binary = compile_native(cls.work, "monitor",
            [ROOT / "tests/monitor_native.cpp"] + [ROOT / "src" / name for name in
                ("monitor.cpp", "scheduler.cpp", "network.cpp", "network_protocol.cpp", "keenetic.cpp",
                 "keenetic_settings.cpp", "keenetic_protocol.cpp")],
            includes=[fake.parent, ROOT / ".pio/libdeps/c3-test-no-oled/ArduinoJson/src"])

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def scenario(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_majority_for_every_list_size_one_to_eight(self): self.scenario("classifier")
    def test_all_failure_policies_and_configurable_cycle_thresholds(self): self.scenario("configurable")
    def test_streak_resets_on_success_outage_wifi_and_time(self): self.scenario("streak")
    def test_fifth_full_cycle_required_and_partial_majority_ignored(self): self.scenario("full_cycle")
    def test_fresh_internet_and_healed_targets_cancel_restart(self): self.scenario("fresh_internet")
    def test_disable_pause_enable_settle_verify_and_cooldown(self): self.scenario("success")
    def test_failed_verification_retains_cause_and_observes_cooldown(self): self.scenario("failed_verify")
    def test_autorecovery_disabled_keeps_checks_and_allows_schedule(self): self.scenario("disabled_option")
    def test_schedule_needs_time_and_fresh_internet_and_serializes(self): self.scenario("schedule_guard")
    def test_scheduled_event_reboot_and_collision_with_recovery(self): self.scenario("scheduled_event")
    def test_manually_disabled_interface_is_preserved(self): self.scenario("manual_down")
    def test_lost_disable_reply_compensates_without_repeating_disable(self): self.scenario("uncertain_disable")
    def test_wifi_loss_during_disable_restores_without_internet(self): self.scenario("lost_disable")
    def test_wifi_loss_after_disable_and_after_enable(self): self.scenario("loss_in_pause")
    def test_reboot_restores_pending_intent_even_when_autorecovery_disabled(self): self.scenario("reboot")
    def test_three_enable_attempts_backoff_and_later_compensation(self): self.scenario("bounded_retry")
    def test_journal_failures_prevent_disable_and_preserve_obligation(self): self.scenario("storage_failures")
    def test_fatal_certificate_error_keeps_intent_and_blocks_commands(self): self.scenario("fatal_enable")
    def test_all_phase_timers_cross_millis_wrap(self): self.scenario("wrap")
    def test_stalled_fresh_check_has_bounded_wait(self): self.scenario("freshness_timeout")


@unittest.skipUnless(os.name == "nt", "Native Windows/MSVC test harness")
class RecoveryStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="warp-recovery-nvs-")
        cls.work = Path(cls.temporary.name)
        fake = cls.work / "fake"
        fake.mkdir()
        (fake / "nvs.h").write_text("""#pragma once
#include <cstddef>
constexpr int ESP_OK = 0, ESP_ERR_NVS_NOT_FOUND = -2, NVS_READONLY = 1, NVS_READWRITE = 2;
using nvs_handle_t = unsigned;
int nvs_open(const char*, int, nvs_handle_t*);
void nvs_close(nvs_handle_t);
int nvs_get_blob(nvs_handle_t, const char*, void*, std::size_t*);
int nvs_set_blob(nvs_handle_t, const char*, const void*, std::size_t);
int nvs_erase_key(nvs_handle_t, const char*);
int nvs_commit(nvs_handle_t);
""")
        cls.binary = compile_native(cls.work, "recovery_store",
            [ROOT / "tests/recovery_store_native.cpp", ROOT / "src/recovery_store.cpp",
             ROOT / "src/keenetic_settings.cpp", ROOT / "src/network_protocol.cpp"], includes=[fake])

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def scenario(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_durable_intent_idempotence_reboot_and_minimal_writes(self): self.scenario("durable")
    def test_endpoint_interface_binding_and_corrupt_records(self): self.scenario("binding")
    def test_read_write_erase_and_commit_errors(self): self.scenario("failures")


if __name__ == "__main__":
    unittest.main()
