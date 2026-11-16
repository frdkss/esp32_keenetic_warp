"""Compile the actual protected USB probe with fake ESP APIs and real CNG HMAC."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from test_stage5_network import ROOT, compile_native


@unittest.skipUnless(os.name == "nt", "Native Windows/MSVC harness")
class ProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="warp-probe-")
        cls.work = Path(cls.temporary.name)
        fake = cls.work / "fake"
        (fake / "mbedtls").mkdir(parents=True)
        headers = ("Arduino.h", "esp_app_desc.h", "esp_chip_info.h", "esp_efuse.h", "esp_efuse_table.h",
                   "esp_flash.h", "esp_flash_encrypt.h", "esp_mac.h", "esp_ota_ops.h", "esp_secure_boot.h",
                   "nvs_flash.h", "esp_random.h", "mbedtls/md.h", "mbedtls/platform_util.h", "mbedtls/sha256.h")
        for name in headers:
            (fake / name).write_text('#pragma once\n#include "probe_fakes.h"\n')
        source = (ROOT / "src/update_probe.cpp").read_text()
        names = sorted(set(re.findall(r"ESP_EFUSE_[A-Z0-9_]+", source)) - {
            "ESP_EFUSE_KEY_PURPOSE_USER", "ESP_EFUSE_KEY_PURPOSE_XTS_AES_128_KEY", "ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST0"})
        disabled = {"ESP_EFUSE_DIS_ICACHE", "ESP_EFUSE_DIS_USB_SERIAL_JTAG", "ESP_EFUSE_DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE",
                    "ESP_EFUSE_DIS_DOWNLOAD_MODE", "ESP_EFUSE_SECURE_BOOT_KEY_REVOKE0", "ESP_EFUSE_SECURE_BOOT_AGGRESSIVE_REVOKE"}
        fields = "\n".join(f"inline const esp_efuse_desc_t fake_{name}{{{0 if name in disabled else 7 if name in ('ESP_EFUSE_SOFT_DIS_JTAG', 'ESP_EFUSE_SPI_BOOT_CRYPT_CNT') else 1}}};\n"
                            f"inline const esp_efuse_desc_t* {name}[] = {{&fake_{name}, nullptr}};" for name in names)
        (fake / "probe_fakes.h").write_text(FAKES.replace("// EFUSE_FIELDS", fields))
        cls.binary = compile_native(cls.work, "probe", [ROOT / "tests/update_probe_native.cpp", ROOT / "src/update_probe.cpp"],
                                    includes=[fake], defines=["WARP_PROTECTED_BUILD=1", "OLED_ENABLED=0"])

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    def scenario(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return result.stdout

    def test_production_probe_hmac_matches_python_and_contains_live_monitor_state(self):
        frame = self.scenario("proof").strip()
        self.assertTrue(frame.startswith(b"WARP9 "))
        payload, tag = frame[6:].rsplit(b" ", 1)
        self.assertEqual(tag.decode(), hmac.digest(bytes(range(64)), b"WARP-USB-PROBE-1\0" + payload, "sha256").hex())
        proof = json.loads(payload)
        self.assertEqual(proof["cycle"], 42)
        self.assertEqual(proof["controls"], 2)
        self.assertEqual(proof["targets"], 3)
        self.assertEqual(proof["table_sha"], hashlib.sha256(b"P" * 3072).hexdigest())
        self.assertEqual(proof["plain_sha"], hashlib.sha256(b"P" * 128).hexdigest())
        self.assertEqual(proof["nonce"], "a" * 64)

    def test_bounded_input_timeout_overflow_bad_nonce_and_stalled_reader(self):
        for name in ("overflow", "partial", "bad_nonce", "stalled"):
            with self.subTest(name=name): self.scenario(name)

    def test_completed_cycle_count_remains_visible_while_next_cycle_is_running(self):
        payload, tag = self.scenario("in_progress").strip()[6:].rsplit(b" ", 1)
        self.assertEqual(json.loads(payload)["cycle"], 42)
        self.assertEqual(tag.decode(), hmac.digest(bytes(range(64)), b"WARP-USB-PROBE-1\0" + payload, "sha256").hex())

    def test_runtime_error_and_router_http_are_in_the_authenticated_proof(self):
        payload, tag = self.scenario("runtime_error").strip()[6:].rsplit(b" ", 1)
        proof = json.loads(payload)
        self.assertEqual((proof["runtime_error"], proof["router_http"]), (21, 401))
        self.assertEqual(tag.decode(), hmac.digest(bytes(range(64)), b"WARP-USB-PROBE-1\0" + payload, "sha256").hex())

    def test_unprotected_stub_supports_diagnostic_arguments_without_exposing_a_probe(self):
        source = self.work / 'unprotected.cpp'
        source.write_text('#include "warp/update_probe.h"\nint main(){warp::update::configureService({});warp::update::tick(true,{},true,warp::ErrorReason::None,0);return warp::update::sending()?1:0;}\n')
        binary = compile_native(self.work, 'unprotected', [source, ROOT / 'src/update_probe.cpp'],
                                includes=[self.work/'fake'], defines=['WARP_PROTECTED_BUILD=0','OLED_ENABLED=0'])
        result = subprocess.run([str(binary)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')

    def test_unprotected_board_and_missing_nvs_key_emit_no_proof(self):
        self.scenario("unprotected")
        self.scenario("missing_key")

    def test_authenticated_maintenance_replay_timeout_bad_mac_and_busy(self):
        for name in ("maintenance_valid", "maintenance_bad", "maintenance_expired", "maintenance_busy"):
            with self.subTest(name=name):
                self.scenario(name)


FAKES = r'''#pragma once
#define NOMINMAX
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
inline std::uint32_t fakeMillis = 0;
inline bool fakeProtected = true, fakeMissingKey = false;
inline void* fakeKeyPointer = nullptr;
inline unsigned fakeZeroized = 0;
inline unsigned long millis() { return fakeMillis; }
inline unsigned char fakeRandom = 0x56;
inline void esp_fill_random(void* p, std::size_t n) { std::memset(p, fakeRandom++, n); }
struct FakeSerial {
    std::string input, output;
    int room = 37;
    explicit operator bool() const { return true; }
    int available() const { return static_cast<int>(input.size()); }
    int read() { int c = input.front(); input.erase(0, 1); return c; }
    int availableForWrite() const { return room; }
    std::size_t write(const std::uint8_t* p, std::size_t n) { output.append(reinterpret_cast<const char*>(p), n); return n; }
};
inline FakeSerial Serial;
constexpr int ESP_OK = 0;
struct esp_efuse_desc_t { unsigned value; };
// EFUSE_FIELDS
inline int esp_efuse_read_field_blob(const esp_efuse_desc_t** p, void* out, std::size_t) { *static_cast<unsigned*>(out) = p[0]->value; return 0; }
enum esp_efuse_block_t { EFUSE_BLK_KEY0 = 4, EFUSE_BLK_KEY1, EFUSE_BLK_KEY2, EFUSE_BLK_KEY3, EFUSE_BLK_KEY4, EFUSE_BLK_KEY5, EFUSE_BLK_KEY_MAX };
enum { ESP_EFUSE_KEY_PURPOSE_USER = 0, ESP_EFUSE_KEY_PURPOSE_XTS_AES_128_KEY = 4, ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST0 = 9 };
inline int esp_efuse_get_key_purpose(esp_efuse_block_t b) { return b == EFUSE_BLK_KEY0 ? 4 : b == EFUSE_BLK_KEY1 ? 9 : 0; }
inline bool esp_efuse_get_key_dis_read(esp_efuse_block_t b) { return b == EFUSE_BLK_KEY0; }
inline bool esp_efuse_get_key_dis_write(esp_efuse_block_t) { return true; }
inline bool esp_efuse_get_keypurpose_dis_write(esp_efuse_block_t) { return true; }
inline bool esp_flash_encryption_enabled() { return fakeProtected; }
inline bool esp_secure_boot_enabled() { return fakeProtected; }
constexpr int CHIP_ESP32C3 = 5;
struct esp_chip_info_t { int model = 5; unsigned revision = 4; };
inline void esp_chip_info(esp_chip_info_t* p) { *p = {}; }
inline int esp_flash_get_size(void*, std::uint32_t* p) { *p = 4194304; return 0; }
inline int esp_efuse_mac_get_default(unsigned char* p) { std::memset(p, 0x12, 6); return 0; }
inline int esp_efuse_read_block(esp_efuse_block_t, void* p, int, int) { std::memset(p, 0x23, 32); return 0; }
struct esp_partition_t { unsigned address = 0x20000, size = 0x3E0000; };
inline esp_partition_t fakePartition;
inline const esp_partition_t* esp_ota_get_running_partition() { return &fakePartition; }
inline int esp_partition_get_sha256(const esp_partition_t*, unsigned char* p) { std::memset(p, 0x34, 32); return 0; }
inline int esp_partition_read_raw(const esp_partition_t*, unsigned, void* p, std::size_t n) { std::memset(p, 'C', n); return 0; }
inline int esp_partition_read(const esp_partition_t*, unsigned, void* p, std::size_t n) { std::memset(p, 'P', n); return 0; }
inline int esp_flash_read_encrypted(void*, unsigned, void* p, std::size_t n) { std::memset(p, 'P', n); return 0; }
struct esp_app_desc_t { unsigned char app_elf_sha256[32]{}; char version[32] = "0.3.0"; };
inline esp_app_desc_t fakeDescription;
inline const esp_app_desc_t* esp_app_get_description() { return &fakeDescription; }
constexpr int ESP_PARTITION_TYPE_DATA = 1, ESP_PARTITION_SUBTYPE_DATA_NVS_KEYS = 4;
inline const esp_partition_t* esp_partition_find_first(int, int, const char*) { return &fakePartition; }
struct nvs_sec_cfg_t { unsigned char eky[32], tky[32]; };
inline int nvs_flash_read_security_cfg(const esp_partition_t*, nvs_sec_cfg_t* cfg) {
    if (fakeMissingKey) return -1;
    for (unsigned i = 0; i < 32; ++i) { cfg->eky[i] = static_cast<unsigned char>(i); cfg->tky[i] = static_cast<unsigned char>(i + 32); }
    fakeKeyPointer = cfg; return 0;
}
inline void mbedtls_platform_zeroize(void* p, std::size_t n) { std::memset(p, 0, n); ++fakeZeroized; }
struct mbedtls_sha256_context { std::vector<unsigned char> data; };
inline int nativeDigest(const std::vector<unsigned char>& key, const unsigned char* p, std::size_t n, unsigned char* out) {
    BCRYPT_ALG_HANDLE provider = nullptr;
    if (BCryptOpenAlgorithmProvider(&provider, BCRYPT_SHA256_ALGORITHM, nullptr, key.empty() ? 0 : BCRYPT_ALG_HANDLE_HMAC_FLAG) < 0) return -1;
    const auto status = BCryptHash(provider, key.empty() ? nullptr : const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()),
        const_cast<PUCHAR>(p), static_cast<ULONG>(n), out, 32);
    BCryptCloseAlgorithmProvider(provider, 0); return status < 0 ? -1 : 0;
}
inline int mbedtls_sha256(const unsigned char* p, std::size_t n, unsigned char* out, int) { return nativeDigest({}, p, n, out); }
inline void mbedtls_sha256_init(mbedtls_sha256_context* c) { c->data.clear(); }
inline int mbedtls_sha256_starts(mbedtls_sha256_context* c, int) { c->data.clear(); return 0; }
inline int mbedtls_sha256_update(mbedtls_sha256_context* c, const unsigned char* p, std::size_t n) { c->data.insert(c->data.end(), p, p+n); return 0; }
inline int mbedtls_sha256_finish(mbedtls_sha256_context* c, unsigned char* out) { return nativeDigest({}, c->data.data(), c->data.size(), out); }
inline void mbedtls_sha256_free(mbedtls_sha256_context*) {}
constexpr int MBEDTLS_MD_SHA256 = 6;
struct mbedtls_md_context_t { std::vector<unsigned char> key, data; };
inline void mbedtls_md_init(mbedtls_md_context_t* c) { c->key.clear(); c->data.clear(); }
inline int mbedtls_md_info_from_type(int) { return 0; }
inline int mbedtls_md_setup(mbedtls_md_context_t*, int, int) { return 0; }
inline int mbedtls_md_hmac_starts(mbedtls_md_context_t* c, const unsigned char* p, std::size_t n) { c->key.assign(p, p+n); return 0; }
inline int mbedtls_md_hmac_update(mbedtls_md_context_t* c, const unsigned char* p, std::size_t n) { c->data.insert(c->data.end(), p, p+n); return 0; }
inline int mbedtls_md_hmac_finish(mbedtls_md_context_t* c, unsigned char* out) { return nativeDigest(c->key, c->data.data(), c->data.size(), out); }
inline void mbedtls_md_free(mbedtls_md_context_t*) {}
'''

if __name__ == "__main__": unittest.main()
