#include "warp/network_esp.h"
#include "warp/network_protocol.h"
#include "warp/keenetic_esp.h"
#include "warp/tls_transport.h"
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <memory>
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/task.h"
#include "lwip/dns.h"
#include "lwip/sockets.h"
#include "lwip/tcpip.h"
#include "mbedtls/platform_util.h"

namespace warp {
namespace {
std::atomic<std::uint32_t> syncs{0};
void synced(timeval*) { ++syncs; }
std::int64_t steadyMs() { return esp_timer_get_time() / 1000; }
void pauseIo() { vTaskDelay(pdMS_TO_TICKS(5)); }
bool pendingIo(int result) {
    return result == MBEDTLS_ERR_SSL_WANT_READ || result == MBEDTLS_ERR_SSL_WANT_WRITE;
}
using detail::Transport;
}

void EspNetworkPlatform::event(void* arg, esp_event_base_t base, std::int32_t id, void*) {
    auto& self = *static_cast<EspNetworkPlatform*>(arg);
    if ((base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) ||
        (base == IP_EVENT && id == IP_EVENT_STA_LOST_IP)) {
        self.connected_ = false;
        ++self.losses_;
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) self.connected_ = true;
}
bool EspNetworkPlatform::beginWifi(CredentialsView credentials) {
    if (initialized_) return false;
    initialized_ = true;
    requests_ = xQueueCreate(1, sizeof(Job));
    replies_ = xQueueCreate(1, sizeof(Reply));
    if (!requests_ || !replies_) return false;
    if (esp_netif_init() != ESP_OK) return false;
    const auto eventResult = esp_event_loop_create_default();
    if (eventResult != ESP_OK && eventResult != ESP_ERR_INVALID_STATE) return false;
    if (!esp_netif_create_default_wifi_sta()) return false;
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    init.nvs_enable = 0;  // No second copy of the PSK in Wi-Fi NVS.
    if (esp_wifi_init(&init) != ESP_OK ||
        esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, event, this) != ESP_OK ||
        esp_event_handler_register(IP_EVENT, ESP_EVENT_ANY_ID, event, this) != ESP_OK ||
        esp_wifi_set_storage(WIFI_STORAGE_RAM) != ESP_OK ||
        esp_wifi_set_mode(WIFI_MODE_STA) != ESP_OK) return false;
    wifi_config_t config{};
    std::copy(credentials.wifiSsid.begin(), credentials.wifiSsid.end(), config.sta.ssid);
    std::copy(credentials.wifiPassword.begin(), credentials.wifiPassword.end(), config.sta.password);
    const auto configResult = esp_wifi_set_config(WIFI_IF_STA, &config);
    mbedtls_platform_zeroize(&config, sizeof(config));
    if (configResult != ESP_OK || esp_wifi_start() != ESP_OK) return false;
    TaskHandle_t handle = nullptr;
    return xTaskCreate(worker, "site-probe", 12288, this, 1, &handle) == pdPASS;
}
void EspNetworkPlatform::connectWifi() { esp_wifi_connect(); }
void EspNetworkPlatform::disconnectWifi() { esp_wifi_disconnect(); }
bool EspNetworkPlatform::startTimeSync(const char* timezone) {
    if (setenv("TZ", timezone, 1) != 0) return false;
    tzset();
    if (sntpInitialized_) return esp_netif_sntp_start() == ESP_OK;
    esp_sntp_config_t config = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
    config.wait_for_sync = false;
    config.sync_cb = synced;
    sntpInitialized_ = esp_netif_sntp_init(&config) == ESP_OK;
    return sntpInitialized_;
}
std::uint32_t EspNetworkPlatform::timeSyncGeneration() const { return syncs.load(); }
std::int64_t EspNetworkPlatform::epochSeconds() const { return static_cast<std::int64_t>(time(nullptr)); }
bool EspNetworkPlatform::startProbe(std::string_view url, std::uint32_t connectMs, std::uint32_t readMs) {
    if (url.size() > maxUrlBytes || !requests_ || !replies_) return false;
    bool expected = false;
    if (!active_.compare_exchange_strong(expected, true)) return false;
    Reply discarded;
    while (xQueueReceive(replies_, &discarded, 0) == pdTRUE) {}
    Job job;
    std::copy(url.begin(), url.end(), job.url.begin());
    job.connectMs = connectMs;
    job.readMs = readMs;
    job.generation = ++generation_;
    if (xQueueSend(requests_, &job, 0) == pdTRUE) return true;
    active_ = false;
    return false;
}
bool EspNetworkPlatform::pollProbe(CheckResult& result) {
    Reply reply;
    if (xQueueReceive(replies_, &reply, 0) != pdTRUE || reply.generation != generation_.load()) return false;
    result = reply.result;
    return true;
}
void EspNetworkPlatform::cancelProbe() { ++generation_; }
bool EspNetworkPlatform::cancelled(const Job& job) const {
    return generation_.load() != job.generation || !connected_.load();
}
void EspNetworkPlatform::worker(void* arg) {
    auto& self = *static_cast<EspNetworkPlatform*>(arg);
    Job job;
    for (;;) {
        if (xQueueReceive(self.requests_, &job, portMAX_DELAY) == pdTRUE) {
            const Reply reply{self.execute(job), job.generation};
            xQueueOverwrite(self.replies_, &reply);
            self.active_ = false;
        }
    }
}
void EspNetworkPlatform::finishDns(const char*, const ip_addr_t* address, void* arg) {
    auto& state = *static_cast<DnsState*>(arg);
    state.resolved = address != nullptr;
    if (address) state.address = *address;
    state.pending.store(false, std::memory_order_release);
}
void EspNetworkPlatform::beginDns(void* arg) {
    auto& state = *static_cast<DnsState*>(arg);
    const auto rc = dns_gethostbyname(state.host.data(), &state.address, finishDns, arg);
    if (rc == ERR_OK) finishDns(nullptr, &state.address, arg);
    else if (rc != ERR_INPROGRESS) finishDns(nullptr, nullptr, arg);
}

CheckResult EspNetworkPlatform::execute(const Job& job) {
    CheckResult result{ErrorReason::None};
    const auto started = steadyMs();
    const auto connectDeadline = started + job.connectMs;
    auto finish = [&](ErrorReason error) {
        result.error = error;
        result.durationMs = static_cast<std::uint32_t>(steadyMs() - started);
        result.reachable = error == ErrorReason::None && result.httpStatus >= 200 && result.httpStatus <= 399;
        return result;
    };
    net::Url url;
    if (!net::parseUrl(job.url.data(), url)) return finish(ErrorReason::InvalidUrl);
    if (cancelled(job)) return finish(ErrorReason::Cancelled);
    result.attempted = true;
    ip_addr_t address{};
    if (!ipaddr_aton(url.host.data(), &address)) {
        // There is only one permanent DNS slot. Never free or reuse an outstanding callback context.
        while (dns_.pending.load(std::memory_order_acquire)) {
            if (cancelled(job)) return finish(ErrorReason::Cancelled);
            if (steadyMs() >= connectDeadline) return finish(ErrorReason::DnsTimeout);
            pauseIo();
        }
        dns_.host = url.host;
        dns_.resolved = false;
        dns_.pending.store(true, std::memory_order_release);
        if (tcpip_try_callback(beginDns, &dns_) != ERR_OK) {
            dns_.pending = false;
            return finish(ErrorReason::ResourceExhausted);
        }
        while (dns_.pending.load(std::memory_order_acquire)) {
            if (cancelled(job)) return finish(ErrorReason::Cancelled);
            if (steadyMs() >= connectDeadline) return finish(ErrorReason::DnsTimeout);
            pauseIo();
        }
        if (!dns_.resolved) return finish(ErrorReason::DnsFailure);
        address = dns_.address;
    }
    // Allocate TLS contexts off the worker stack; at most one exists.
    std::unique_ptr<Transport> io(new (std::nothrow) Transport);
    if (!io) return finish(ErrorReason::ResourceExhausted);
    sockaddr_storage destination{};
    socklen_t destinationSize;
    int family;
#if LWIP_IPV6
    if (IP_IS_V6(&address)) {
        auto& addr = reinterpret_cast<sockaddr_in6&>(destination);
        addr.sin6_family = family = AF_INET6;
        addr.sin6_port = htons(url.port);
        std::memcpy(&addr.sin6_addr, ip_2_ip6(&address)->addr, sizeof(addr.sin6_addr));
        destinationSize = sizeof(addr);
    } else
#endif
    {
        auto& addr = reinterpret_cast<sockaddr_in&>(destination);
        addr.sin_family = family = AF_INET;
        addr.sin_port = htons(url.port);
        addr.sin_addr.s_addr = ip_2_ip4(&address)->addr;
        destinationSize = sizeof(addr);
    }
    io->socket.fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (io->socket.fd < 0) { result.transportCode = errno; return finish(ErrorReason::ConnectionFailure); }
    if (fcntl(io->socket.fd, F_SETFL, O_NONBLOCK) < 0) {
        result.transportCode = errno; return finish(ErrorReason::ConnectionFailure);
    }
    int rc = connect(io->socket.fd, reinterpret_cast<sockaddr*>(&destination), destinationSize);
    if (rc < 0 && errno != EINPROGRESS) { result.transportCode = errno; return finish(ErrorReason::ConnectionFailure); }
    while (rc < 0) {
        if (cancelled(job)) return finish(ErrorReason::Cancelled);
        if (steadyMs() >= connectDeadline) return finish(ErrorReason::ConnectTimeout);
        fd_set writable;
        FD_ZERO(&writable);
        FD_SET(io->socket.fd, &writable);
        timeval timeout{0, 5000};
        rc = select(io->socket.fd + 1, nullptr, &writable, nullptr, &timeout);
        if (rc < 0) { result.transportCode = errno; return finish(ErrorReason::ConnectionFailure); }
        if (rc == 0) { rc = -1; continue; }
        int error = 0;
        socklen_t length = sizeof(error);
        if (getsockopt(io->socket.fd, SOL_SOCKET, SO_ERROR, &error, &length) < 0 || error) {
            result.transportCode = error ? error : errno;
            return finish(ErrorReason::ConnectionFailure);
        }
    }
    if (url.secure) {
        rc = io->setupTls(url.host.data());
        if (rc) { result.tlsCode = rc; return finish(ErrorReason::TlsFailure); }
        for (;;) {
            if (cancelled(job)) return finish(ErrorReason::Cancelled);
            if (steadyMs() >= connectDeadline) return finish(ErrorReason::ConnectTimeout);
            rc = mbedtls_ssl_handshake(&io->ssl);
            if (rc == 0) break;
            if (!pendingIo(rc)) {
                result.tlsCode = rc;
                result.certificateFlags = static_cast<int>(mbedtls_ssl_get_verify_result(&io->ssl));
                return finish(ErrorReason::TlsFailure);
            }
            pauseIo();
        }
        result.certificateFlags = static_cast<int>(mbedtls_ssl_get_verify_result(&io->ssl));
        if (result.certificateFlags) return finish(ErrorReason::TlsFailure);
    }
    // GET headers reflect the configured resource; stop before downloading its body.
    std::array<char, 1100> request{};
    const auto size = std::snprintf(request.data(), request.size(),
        "GET %s HTTP/1.1\r\nHost: %s%s%s:%u\r\nConnection: close\r\nAccept: */*\r\nUser-Agent: warp-monitor/0.5\r\n\r\n",
        url.path.data(), url.ipv6 ? "[" : "", url.host.data(), url.ipv6 ? "]" : "", url.port);
    if (size < 0 || static_cast<std::size_t>(size) >= request.size()) return finish(ErrorReason::InvalidUrl);
    const auto readDeadline = steadyMs() + job.readMs;  // Total write + headers budget, not an idle timeout.
    std::size_t sent = 0;
    while (sent < static_cast<std::size_t>(size)) {
        if (cancelled(job)) return finish(ErrorReason::Cancelled);
        if (steadyMs() >= readDeadline) return finish(ErrorReason::ReadTimeout);
        rc = io->write(reinterpret_cast<const unsigned char*>(request.data()) + sent, size - sent);
        if (rc > 0) sent += rc;
        else if (pendingIo(rc)) pauseIo();
        else { result.tlsCode = url.secure ? rc : 0; result.transportCode = errno;
               return finish(url.secure ? ErrorReason::TlsFailure : ErrorReason::ConnectionFailure); }
    }
    net::ResponseHeaders headers;
    std::array<unsigned char, 512> buffer{};
    while (!headers.done()) {
        if (cancelled(job)) return finish(ErrorReason::Cancelled);
        if (steadyMs() >= readDeadline) return finish(ErrorReason::ReadTimeout);
        rc = io->read(buffer.data(), buffer.size());
        if (rc > 0) {
            for (int i = 0; i < rc && !headers.done() && headers.error() == ErrorReason::None; ++i) headers.feed(buffer[i]);
            if (headers.error() != ErrorReason::None) return finish(headers.error());
        } else if (pendingIo(rc)) pauseIo();
        else if (rc == 0 || rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return finish(ErrorReason::InvalidResponse);
        else { result.tlsCode = url.secure ? rc : 0; result.transportCode = errno;
               return finish(url.secure ? ErrorReason::TlsFailure : ErrorReason::ConnectionFailure); }
    }
    result.httpStatus = headers.status();
    return finish(result.httpStatus >= 200 && result.httpStatus <= 399 ? ErrorReason::None : ErrorReason::HttpFailure);
}
bool EspKeeneticTransport::start(const keenetic::Settings& settings, std::string_view request) {
    if (!keenetic::validSettings(settings) || request.empty() || request.size() >= keenetic::maxRequestBytes) return false;
    if (!initialized_) {
        initialized_ = true;
        requests_ = xQueueCreate(1, sizeof(Job*));
        replies_ = xQueueCreate(1, sizeof(std::uint32_t));
        TaskHandle_t task = nullptr;
        if (!requests_ || !replies_ || xTaskCreate(worker, "keenetic", 12288, this, 1, &task) != pdPASS) {
            if (requests_) vQueueDelete(requests_);
            if (replies_) vQueueDelete(replies_);
            requests_ = replies_ = nullptr;
            return false;
        }
    }
    if (!requests_ || !replies_) return false;
    if (active_) {
        std::uint32_t discarded;
        if (xQueueReceive(replies_, &discarded, 0) != pdTRUE) return false;
        active_ = false;
    }
    std::unique_ptr<Job> job(new (std::nothrow) Job);
    if (!job) return false;
    job->settings = settings;
    std::copy(request.begin(), request.end(), job->request.begin());
    job->size = request.size(); job->generation = ++generation_;
    auto* pointer = job.get();
    if (xQueueSend(requests_, &pointer, 0) != pdTRUE) {
        keenetic::erase(job.get(), sizeof(Job)); return false;
    }
    job.release();
    active_ = true; delivered_ = false;
    return true;
}
const keenetic::Response* EspKeeneticTransport::poll() {
    if (!active_ || delivered_) return nullptr;
    std::uint32_t completed;
    if (xQueueReceive(replies_, &completed, 0) != pdTRUE) return nullptr;
    active_ = false; delivered_ = true;
    if (completed != generation_.load()) { response_.clear(); return nullptr; }
    return &response_;
}
void EspKeeneticTransport::cancel() { ++generation_; }
void EspKeeneticTransport::worker(void* argument) {
    auto& self = *static_cast<EspKeeneticTransport*>(argument);
    Job* job = nullptr;
    for (;;) {
        if (xQueueReceive(self.requests_, &job, portMAX_DELAY) != pdTRUE) continue;
        const auto generation = job->generation;
        self.execute(*job);
        keenetic::erase(job, sizeof(Job)); delete job; job = nullptr;
        xQueueOverwrite(self.replies_, &generation);
    }
}
void EspKeeneticTransport::execute(const Job& job) {
    response_.clear();
    auto& diagnostic = response_.diagnostic;
    const auto started = steadyMs();
    const auto connectDeadline = started + job.settings.connectMs;
    auto cancelled = [&] { return generation_.load() != job.generation; };
    auto finish = [&](ErrorReason error) {
        diagnostic.error = error;
        diagnostic.durationMs = static_cast<std::uint32_t>(steadyMs() - started);
        if (error != ErrorReason::None) {
            keenetic::erase(response_.cookie.data(), response_.cookie.size());
            keenetic::erase(response_.body.data(), response_.body.size()); response_.bodySize = 0;
        }
    };
    if (cancelled()) { finish(ErrorReason::Cancelled); return; }
    // Connect ONLY to the provisioned IPv4, with independent validated SNI/Host.
    sockaddr_in address{};
    address.sin_family = AF_INET; address.sin_port = htons(job.settings.port);
    if (inet_pton(AF_INET, job.settings.address.data(), &address.sin_addr) != 1) { finish(ErrorReason::InvalidUrl); return; }
    std::unique_ptr<Transport> io(new (std::nothrow) Transport);
    if (!io) { finish(ErrorReason::ResourceExhausted); return; }
    diagnostic.attempted = true;
    io->socket.fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (io->socket.fd < 0 || fcntl(io->socket.fd, F_SETFL, O_NONBLOCK) < 0) {
        diagnostic.transportCode = errno; finish(ErrorReason::ConnectionFailure); return;
    }
    int rc = connect(io->socket.fd, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    if (rc < 0 && errno != EINPROGRESS) { diagnostic.transportCode = errno; finish(ErrorReason::ConnectionFailure); return; }
    while (rc < 0) {
        if (cancelled()) { finish(ErrorReason::Cancelled); return; }
        if (steadyMs() >= connectDeadline) { finish(ErrorReason::ConnectTimeout); return; }
        fd_set writable; FD_ZERO(&writable); FD_SET(io->socket.fd, &writable);
        timeval timeout{0, 5000};
        rc = select(io->socket.fd + 1, nullptr, &writable, nullptr, &timeout);
        if (rc < 0) { diagnostic.transportCode = errno; finish(ErrorReason::ConnectionFailure); return; }
        if (!rc) { rc = -1; continue; }
        int error = 0; socklen_t size = sizeof(error);
        if (getsockopt(io->socket.fd, SOL_SOCKET, SO_ERROR, &error, &size) < 0 || error) {
            diagnostic.transportCode = error ? error : errno; finish(ErrorReason::ConnectionFailure); return;
        }
    }
    rc = io->setupTls(job.settings.tlsName.data());
    if (rc) { diagnostic.tlsCode = rc; finish(ErrorReason::TlsFailure); return; }
    for (;;) {
        if (cancelled()) { finish(ErrorReason::Cancelled); return; }
        if (steadyMs() >= connectDeadline) { finish(ErrorReason::ConnectTimeout); return; }
        rc = mbedtls_ssl_handshake(&io->ssl);
        if (!rc) break;
        if (!pendingIo(rc)) {
            diagnostic.tlsCode = rc;
            diagnostic.certificateFlags = static_cast<int>(mbedtls_ssl_get_verify_result(&io->ssl));
            finish(ErrorReason::TlsFailure); return;
        }
        pauseIo();
    }
    diagnostic.certificateFlags = static_cast<int>(mbedtls_ssl_get_verify_result(&io->ssl));
    if (diagnostic.certificateFlags) { finish(ErrorReason::TlsFailure); return; }
    const auto readDeadline = steadyMs() + job.settings.readMs;
    std::size_t sent = 0;
    while (sent < job.size) {
        if (cancelled()) { finish(ErrorReason::Cancelled); return; }
        if (steadyMs() >= readDeadline) { finish(ErrorReason::ReadTimeout); return; }
        rc = io->write(reinterpret_cast<const unsigned char*>(job.request.data()) + sent, job.size - sent);
        if (rc > 0) sent += rc;
        else if (pendingIo(rc)) pauseIo();
        else { diagnostic.tlsCode = rc; finish(ErrorReason::TlsFailure); return; }
    }
    keenetic::ResponseParser parser(response_);
    std::array<unsigned char, 512> buffer{};
    while (!parser.done() && parser.error() == ErrorReason::None) {
        if (cancelled()) { finish(ErrorReason::Cancelled); return; }
        if (steadyMs() >= readDeadline) { finish(ErrorReason::ReadTimeout); return; }
        rc = io->read(buffer.data(), buffer.size());
        if (rc > 0) {
            for (int i = 0; i < rc; ++i) parser.feed(static_cast<char>(buffer[i]));
            keenetic::erase(buffer.data(), buffer.size());
        } else if (pendingIo(rc)) pauseIo();
        else if (!rc || rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) { parser.eof(); break; }
        else { diagnostic.tlsCode = rc; finish(ErrorReason::TlsFailure); return; }
    }
    finish(parser.error());
}
}  // namespace warp
