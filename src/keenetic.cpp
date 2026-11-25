#include "warp/keenetic.h"
#include "warp/network.h"
#include "warp/network_protocol.h"
#include <algorithm>
#include <cstdio>
#include <cstring>

namespace warp {
OperationResult KeeneticClient::begin(CredentialsView credentials, const keenetic::Settings& settings) {
    if (configured_ || !transport_ || !keenetic::validSettings(settings) ||
        credentials.routerLogin.empty() || credentials.routerLogin.size() >= login_.size() ||
        credentials.routerPassword.empty() || credentials.routerPassword.size() >= password_.size() ||
        credentials.routerLogin.find('\0') != credentials.routerLogin.npos ||
        credentials.routerPassword.find('\0') != credentials.routerPassword.npos) {
        return {ErrorReason::NotConfigured};
    }
    settings_ = settings;
    std::copy(credentials.routerLogin.begin(), credentials.routerLogin.end(), login_.begin());
    std::copy(credentials.routerPassword.begin(), credentials.routerPassword.end(), password_.begin());
    configured_ = true;
    securitySeen_ = network_.securityGeneration();
    return result_ = {ErrorReason::None};
}
OperationResult KeeneticClient::startOperation(bool change, bool enabled) {
    if (!configured_) return {ErrorReason::NotConfigured};
    if (busy()) return {ErrorReason::Busy};
    if (blocked_) return result_;
    if (!network_.wifiConnected()) return result_ = {ErrorReason::WifiDisconnected};
    if (!network_.timeSynchronized()) return result_ = {ErrorReason::TimeNotSynchronized};
    if (securitySeen_ != network_.securityGeneration()) {
        securitySeen_ = network_.securityGeneration();
        authenticated_ = identified_ = false;
        keenetic::erase(cookie_.data(), cookie_.size());
    }
    change_ = change; enabled_ = enabled; renewed_ = false;
    state_ = {};
    resume_ = Step::Read;
    step_ = authenticated_ ? (identified_ ? Step::Read : Step::Identity) : Step::Challenge;
    diagnostic_ = {ErrorReason::Pending};
    return result_ = {ErrorReason::Pending};
}
OperationResult KeeneticClient::readWarpState() { return startOperation(false, false); }
OperationResult KeeneticClient::setWarpEnabled(bool enabled) { return startOperation(true, enabled); }
void KeeneticClient::finish(ErrorReason reason) {
    result_ = {reason}; diagnostic_.error = reason;
    step_ = Step::Idle; pending_ = false;
    keenetic::erase(loginBody_.data(), loginBody_.size());
    if (reason != ErrorReason::None) {
        state_.valid = false;
        authenticated_ = identified_ = false;
        keenetic::erase(cookie_.data(), cookie_.size());
    }
    switch (reason) {
    case ErrorReason::TlsFailure: case ErrorReason::AuthenticationFailed: case ErrorReason::PermissionDenied:
    case ErrorReason::InvalidJson: case ErrorReason::InvalidResponse: case ErrorReason::RciFailure:
    case ErrorReason::InterfaceNotFound: case ErrorReason::UnsupportedRouter: case ErrorReason::StateMismatch:
    case ErrorReason::ResponseTooLarge:
        blocked_ = true; break;  // Requires an explicit corrected configuration/restart, no command guessing.
    default: break;
    }
}
bool KeeneticClient::send() {
    const bool authPost = step_ == Step::Login;
    const bool mutation = step_ == Step::Change;
    const char* path = step_ == Step::Challenge || authPost ? "/auth" :
        step_ == Step::Identity ? "/rci/show/version" : mutation ? "/rci/interface" : "/rci/show/interface";
    std::array<char, 128> command{};
    if (mutation) std::snprintf(command.data(), command.size(), "{\"name\":\"%s\",\"up\":%s}",
        settings_.interfaceName.data(), enabled_ ? "true" : "false");
    const char* body = authPost ? loginBody_.data() : mutation ? command.data() : "";
    const auto bodySize = std::strlen(body);
    std::array<char, keenetic::maxRequestBytes> request{};
    const auto count = std::snprintf(request.data(), request.size(),
        "%s %s HTTP/1.1\r\nHost: %s:%u\r\nConnection: close\r\nAccept: application/json\r\n"
        "Accept-Encoding: identity\r\n%s%s%sContent-Type: application/json\r\nContent-Length: %u\r\n\r\n%s",
        authPost || mutation ? "POST" : "GET", path, settings_.tlsName.data(), settings_.port,
        cookie_[0] ? "Cookie: " : "", cookie_.data(), cookie_[0] ? "\r\n" : "", static_cast<unsigned>(bodySize), body);
    if (count < 0 || static_cast<std::size_t>(count) >= request.size()) {
        keenetic::erase(request.data(), request.size()); finish(ErrorReason::ResourceExhausted); return false;
    }
    const bool started = transport_->start(settings_, {request.data(), static_cast<std::size_t>(count)});
    keenetic::erase(request.data(), request.size());
    return started;
}
void KeeneticClient::tick(std::uint32_t now) {
    if (!configured_) return;
    const bool securityChanged = securitySeen_ != network_.securityGeneration();
    securitySeen_ = network_.securityGeneration();
    const auto unavailable = !network_.wifiConnected() ? ErrorReason::WifiDisconnected :
        !network_.timeSynchronized() ? ErrorReason::TimeNotSynchronized : ErrorReason::None;
    if (unavailable != ErrorReason::None || securityChanged) {
        if (busy()) { transport_->cancel(); finish(unavailable != ErrorReason::None ? unavailable : ErrorReason::TimeNotSynchronized); }
        authenticated_ = identified_ = false; state_.valid = false;
        keenetic::erase(cookie_.data(), cookie_.size());
        return;
    }
    if (!busy()) return;
    if (!pending_) {
        if (send()) { pending_ = true; stamp_ = now; }
        else if (busy()) finish(ErrorReason::ResourceExhausted);
        return;
    }
    const auto* response = transport_->poll();
    if (!response) {
        if (net::elapsed(now, stamp_, settings_.connectMs + settings_.readMs + 1000)) {
            transport_->cancel(); finish(ErrorReason::ReadTimeout);
        }
        return;
    }
    pending_ = false;
    diagnostic_ = response->diagnostic;
    if (diagnostic_.error != ErrorReason::None) { finish(diagnostic_.error); return; }
    const int http = diagnostic_.httpStatus;
    if (http == 403) { finish(ErrorReason::PermissionDenied); return; }
    // A missing RCI command means the firmware is not the one this client was verified against.
    if (http == 404 && step_ != Step::Challenge && step_ != Step::Login) { finish(ErrorReason::UnsupportedRouter); return; }
    if (http == 401 && step_ != Step::Challenge) {
        if (step_ == Step::Login || renewed_) { finish(ErrorReason::AuthenticationFailed); return; }
        renewed_ = true;
        resume_ = step_ == Step::Verify ? Step::Verify : Step::Read;
        authenticated_ = identified_ = false;
        keenetic::erase(cookie_.data(), cookie_.size());
        step_ = Step::Challenge; return;
    }
    if (response->cookieSeen && !keenetic::mergeCookies(cookie_, response->cookie.data())) {
        finish(ErrorReason::InvalidResponse); return;
    }
    if (step_ == Step::Challenge) {
        const std::string_view scheme(response->authScheme.data());
        if (http != 401 || !response->realm[0] || !response->challenge[0] ||
            scheme.substr(0, scheme.find_first_of(" \t")) != "x-ndw2-interactive") {
            finish(ErrorReason::AuthenticationFailed); return;
        }
        std::array<char, 65> proof{};
        const bool made = keenetic::makeProof(login_.data(), password_.data(), response->realm.data(),
            response->challenge.data(), proof) && keenetic::makeLoginBody(login_.data(), proof.data(), loginBody_);
        keenetic::erase(proof.data(), proof.size());
        if (!made) { finish(ErrorReason::ResourceExhausted); return; }
        step_ = Step::Login; return;
    }
    if (http != 200) { finish(step_ == Step::Login ? ErrorReason::AuthenticationFailed : ErrorReason::HttpFailure); return; }
    if (step_ == Step::Login) {
        keenetic::erase(loginBody_.data(), loginBody_.size());
        if (!cookie_[0]) { finish(ErrorReason::AuthenticationFailed); return; }
        authenticated_ = true; step_ = Step::Identity; return;
    }
    const std::string_view body(response->body.data(), response->bodySize);
    if (step_ == Step::Identity) {
        const auto error = keenetic::parseIdentity(body, identity_);
        if (error != ErrorReason::None) { finish(error); return; }
        identified_ = true; step_ = resume_; return;
    }
    if (step_ == Step::Change) {
        const auto error = keenetic::parseCommand(body);
        if (error != ErrorReason::None) { finish(error); return; }
        state_.valid = false; step_ = Step::Verify; return;
    }
    const auto error = keenetic::parseState(body, settings_.interfaceName.data(), state_);
    if (error != ErrorReason::None) { finish(error); return; }
    if (step_ == Step::Verify) { finish(state_.enabled == enabled_ ? ErrorReason::None : ErrorReason::StateMismatch); return; }
    // Always preflight the chosen interface before a write. Already-correct state is success.
    if (!change_ || state_.enabled == enabled_) { finish(ErrorReason::None); return; }
    step_ = Step::Change;
}
}  // namespace warp
