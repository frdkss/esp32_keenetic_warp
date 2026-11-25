#include "warp/keenetic_protocol.h"
#include "warp/network_protocol.h"
#include <ArduinoJson.h>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include "mbedtls/md5.h"
#include "mbedtls/sha256.h"

static_assert(ARDUINOJSON_VERSION_MAJOR == 7 && ARDUINOJSON_VERSION_MINOR == 4 &&
              ARDUINOJSON_VERSION_REVISION == 2, "ArduinoJson version drift");
namespace warp::keenetic {
namespace {
std::string_view trim(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
    return value;
}
bool equal(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        const auto ch = a[i] >= 'A' && a[i] <= 'Z' ? a[i] + ('a' - 'A') : a[i];
        if (ch != b[i]) return false;
    }
    return true;
}
template<std::size_t N> bool copy(std::array<char, N>& out, std::string_view value) {
    if (value.empty() || value.size() >= N || out[0]) return false;
    std::copy(value.begin(), value.end(), out.begin());
    return true;
}
bool token(std::string_view text) {
    if (text.empty()) return false;
    for (unsigned char ch : text) if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
        (ch >= '0' && ch <= '9') || std::string_view("!#$%&'*+-.^_`|~").find(ch) != text.npos)) return false;
    return true;
}
class Allocator : public ArduinoJson::Allocator {
    struct alignas(std::max_align_t) Block { std::size_t size; };
    std::size_t used_{0};
    static constexpr std::size_t budget = 65536;
public:
    void* allocate(std::size_t size) override {
        if (size > budget - used_) return nullptr;
        auto* b = static_cast<Block*>(std::malloc(sizeof(Block) + size));
        if (!b) return nullptr;
        b->size = size; used_ += size; return b + 1;
    }
    void deallocate(void* p) override {
        if (!p) return;
        auto* b = static_cast<Block*>(p) - 1;
        used_ -= b->size; erase(p, b->size); std::free(b);
    }
    void* reallocate(void* p, std::size_t size) override {
        if (!p) return allocate(size);
        auto* b = static_cast<Block*>(p) - 1;
        const auto old = b->size;
        if (size > budget - (used_ - old)) return nullptr;
        // Avoid a realloc leaving a second copy of router data in freed memory.
        void* next = allocate(size);
        if (!next) return nullptr;
        std::memcpy(next, p, std::min(old, size)); deallocate(p); return next;
    }
};
struct Reader {
    std::string_view text;
    int read() {
        if (text.empty()) return -1;
        const auto ch = static_cast<unsigned char>(text.front()); text.remove_prefix(1); return ch;
    }
    std::size_t readBytes(char* out, std::size_t count) {
        const auto size = std::min(count, text.size());
        std::memcpy(out, text.data(), size); text.remove_prefix(size); return size;
    }
};
ErrorReason decode(std::string_view body, JsonDocument& document) {
    if (body.empty() || body.size() > maxBodyBytes || body.find('\0') != body.npos) return ErrorReason::InvalidJson;
    Reader reader{body};
    const auto error = deserializeJson(document, reader, DeserializationOption::NestingLimit(12));
    if (error) return error == DeserializationError::NoMemory ? ErrorReason::ResourceExhausted : ErrorReason::InvalidJson;
    for (char ch : reader.text) if (ch != ' ' && ch != '\r' && ch != '\n' && ch != '\t') return ErrorReason::InvalidJson;
    if (!document.is<JsonObject>()) return ErrorReason::InvalidResponse;
    return ErrorReason::None;
}
bool rciError(JsonVariantConst value) {
    if (value.is<JsonObjectConst>()) {
        for (JsonPairConst pair : value.as<JsonObjectConst>()) {
            const std::string_view key(pair.key().c_str());
            if ((key == "status" && pair.value().is<const char*>() && pair.value() == "error") ||
                (key == "error" && !pair.value().isNull()) || rciError(pair.value())) return true;
        }
    } else if (value.is<JsonArrayConst>()) {
        for (JsonVariantConst item : value.as<JsonArrayConst>()) if (rciError(item)) return true;
    }
    return false;
}
bool jsonText(JsonVariantConst value, std::string_view expected) {
    if (!value.is<const char*>()) return false;
    const auto text = value.as<JsonString>();
    return std::string_view(text.c_str(), text.size()) == expected;
}
// Router-supplied identity is printed to Serial, so accept only plain identifier characters.
bool identifierText(JsonVariantConst value, std::array<char, 33>& out) {
    if (!value.is<const char*>()) return false;
    const auto text = value.as<JsonString>();
    const std::string_view view(text.c_str(), text.size());
    if (view.empty() || view.size() >= out.size()) return false;
    for (unsigned char ch : view) {
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
            ch == '.' || ch == '-' || ch == '_')) return false;
    }
    out.fill(0);
    std::copy(view.begin(), view.end(), out.begin());
    return true;
}
bool number(std::string_view text, std::size_t& pos, unsigned& out) {
    const auto start = pos;
    out = 0;
    while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9' && pos - start < 4) out = out * 10 + (text[pos++] - '0');
    return pos > start;
}
// KeeneticOS 5.1 and newer. The RCI title is the firmware version, for example 5.1.8.
bool supportedVersion(std::string_view version) {
    unsigned major = 0, minor = 0;
    std::size_t pos = 0;
    if (!number(version, pos, major) || pos >= version.size() || version[pos++] != '.' || !number(version, pos, minor)) return false;
    return major > 5 || (major == 5 && minor >= 1);
}
}
bool mergeCookies(std::array<char, 1025>& jar, std::string_view pairs, bool keepEmpty) {
    while (!pairs.empty()) {
        const auto end = pairs.find(';');
        const auto pair = trim(pairs.substr(0, end));
        const auto eq = pair.find('=');
        if (eq == pair.npos || !token(pair.substr(0, eq))) return false;
        for (unsigned char ch : pair.substr(eq + 1)) if (ch < 0x21 || ch >= 0x7f || ch == ',' || ch == '"' || ch == '\\') return false;
        std::array<char, 1025> next{};
        std::size_t size = 0;
        auto append = [&](std::string_view item) {
            const auto needed = size + (size ? 2 : 0) + item.size();
            if (needed >= next.size()) return false;
            if (size) { next[size++] = ';'; next[size++] = ' '; }
            std::memcpy(next.data() + size, item.data(), item.size()); size += item.size(); return true;
        };
        std::string_view existing(jar.data());
        while (!existing.empty()) {
            const auto stop = existing.find(';');
            const auto item = trim(existing.substr(0, stop));
            if (item.substr(0, item.find('=')) != pair.substr(0, eq) && !append(item)) return false;
            if (stop == existing.npos) break;
            existing.remove_prefix(stop + 1);
        }
        if ((keepEmpty || eq + 1 < pair.size()) && !append(pair)) return false;
        erase(jar.data(), jar.size()); jar = next; erase(next.data(), next.size());
        if (end == pairs.npos) break;
        pairs.remove_prefix(end + 1);
    }
    return true;
}
bool ResponseParser::append(char byte) {
    if (response_.bodySize == maxBodyBytes) { fail(ErrorReason::ResponseTooLarge); return false; }
    response_.body[response_.bodySize++] = byte; return true;
}
void ResponseParser::feed(char byte) {
    if (error_ != ErrorReason::None) return;
    if (done()) { fail(ErrorReason::InvalidResponse); return; }
    if (phase_ == Phase::Body) {
        if (append(byte) && hasLength_ && --remaining_ == 0) phase_ = Phase::Done;
        return;
    }
    if (phase_ == Phase::ChunkData) {
        if (append(byte) && --remaining_ == 0) phase_ = Phase::ChunkCr;
        return;
    }
    if (phase_ == Phase::ChunkCr || phase_ == Phase::ChunkLf) {
        if (++headerBytes_ > 8192) { fail(ErrorReason::ResponseTooLarge); return; }
        if (byte != (phase_ == Phase::ChunkCr ? '\r' : '\n')) { fail(ErrorReason::InvalidResponse); return; }
        phase_ = phase_ == Phase::ChunkCr ? Phase::ChunkLf : Phase::ChunkSize; return;
    }
    if (++headerBytes_ > 8192) { fail(ErrorReason::ResponseTooLarge); return; }
    if (byte == '\n' && cr_) {
        cr_ = false; line(); erase(line_.data(), line_.size()); lineSize_ = 0; return;
    }
    if (cr_ || byte == '\n' || static_cast<unsigned char>(byte) == 127 ||
        (static_cast<unsigned char>(byte) < 32 && byte != '\r' && byte != '\t')) {
        fail(ErrorReason::InvalidResponse); return;
    }
    if (byte == '\r') { cr_ = true; return; }
    if (lineSize_ == line_.size()) { fail(ErrorReason::ResponseTooLarge); return; }
    line_[lineSize_++] = byte;
}
void ResponseParser::line() {
    const std::string_view text(line_.data(), lineSize_);
    if (phase_ == Phase::Status) {
        if (text.size() < 13 || (text.substr(0, 9) != "HTTP/1.1 " && text.substr(0, 9) != "HTTP/1.0 ") ||
            text[9] < '1' || text[9] > '5' || text[10] < '0' || text[10] > '9' ||
            text[11] < '0' || text[11] > '9' || text[12] != ' ') { fail(ErrorReason::InvalidResponse); return; }
        response_.diagnostic.httpStatus = (text[9] - '0') * 100 + (text[10] - '0') * 10 + text[11] - '0';
        phase_ = Phase::Headers; return;
    }
    if (phase_ == Phase::ChunkSize) {
        if (text.empty() || text.size() > 8 || ++chunks_ > 1024) { fail(ErrorReason::InvalidResponse); return; }
        remaining_ = 0;
        for (char ch : text) {
            const int digit = ch >= '0' && ch <= '9' ? ch - '0' : ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 :
                ch >= 'A' && ch <= 'F' ? ch - 'A' + 10 : -1;
            if (digit < 0 || remaining_ > maxBodyBytes / 16) { fail(ErrorReason::InvalidResponse); return; }
            remaining_ = remaining_ * 16 + digit;
        }
        if (remaining_ > maxBodyBytes - response_.bodySize) { fail(ErrorReason::ResponseTooLarge); return; }
        phase_ = remaining_ ? Phase::ChunkData : Phase::Trailers; return;
    }
    if (phase_ == Phase::Trailers) {
        // This profile does not use trailers; reject unexpected metadata.
        if (!text.empty()) fail(ErrorReason::InvalidResponse); else phase_ = Phase::Done;
        return;
    }
    if (text.empty()) {
        const int status = response_.diagnostic.httpStatus;
        if (status < 200) {
            if (status == 101 || ++interim_ > 4 || hasLength_ || chunked_ || response_.cookieSeen ||
                response_.realm[0] || response_.challenge[0] || response_.authScheme[0]) {
                fail(ErrorReason::InvalidResponse); return;
            }
            phase_ = Phase::Status; return;
        }
        if (hasLength_ && chunked_) { fail(ErrorReason::InvalidResponse); return; }
        if (status == 204 || status == 304) {
            if (chunked_ || (hasLength_ && length_)) fail(ErrorReason::InvalidResponse); else phase_ = Phase::Done;
        } else if (chunked_) phase_ = Phase::ChunkSize;
        else { remaining_ = length_; phase_ = hasLength_ && !length_ ? Phase::Done : Phase::Body; }
        return;
    }
    const auto colon = text.find(':');
    if (colon == text.npos || !token(text.substr(0, colon))) { fail(ErrorReason::InvalidResponse); return; }
    const auto name = text.substr(0, colon), value = trim(text.substr(colon + 1));
    if (equal(name, "content-length")) {
        if (hasLength_ || value.empty()) { fail(ErrorReason::InvalidResponse); return; }
        hasLength_ = true;
        for (char ch : value) {
            if (ch < '0' || ch > '9') { fail(ErrorReason::InvalidResponse); return; }
            if (length_ > maxBodyBytes / 10) { fail(ErrorReason::ResponseTooLarge); return; }
            length_ = length_ * 10 + ch - '0';
            if (length_ > maxBodyBytes) { fail(ErrorReason::ResponseTooLarge); return; }
        }
    } else if (equal(name, "transfer-encoding")) {
        if (chunked_ || !equal(value, "chunked")) fail(ErrorReason::InvalidResponse); else chunked_ = true;
    } else if (equal(name, "content-encoding")) {
        if (!equal(value, "identity")) fail(ErrorReason::InvalidResponse);
    } else if (equal(name, "x-ndm-realm")) {
        if (!copy(response_.realm, value)) fail(ErrorReason::InvalidResponse);
    } else if (equal(name, "x-ndm-challenge")) {
        if (!copy(response_.challenge, value)) fail(ErrorReason::InvalidResponse);
    } else if (equal(name, "www-authenticate")) {
        // Only the scheme is used here. Keenetic may append long authentication
        // parameters; realm/challenge are validated from the X-NDM headers.
        const auto scheme = value.substr(0, value.find_first_of(" \t"));
        if (!token(scheme) || !copy(response_.authScheme, scheme)) fail(ErrorReason::InvalidResponse);
    } else if (equal(name, "set-cookie")) {
        response_.cookieSeen = true;
        const auto pair = trim(value.substr(0, value.find(';')));
        if (!mergeCookies(response_.cookie, pair, true)) fail(ErrorReason::InvalidResponse);
    }
}
void ResponseParser::eof() {
    if (phase_ == Phase::Body && !hasLength_) phase_ = Phase::Done;
    else if (!done()) fail(ErrorReason::InvalidResponse);
}
ErrorReason parseIdentity(std::string_view body, Identity& identity) {
    identity = {};
    Allocator allocator; JsonDocument d(&allocator);
    auto error = decode(body, d);
    if (error != ErrorReason::None) return error;
    if (rciError(d.as<JsonVariantConst>())) return ErrorReason::RciFailure;
    // Model is informational only; compatibility depends on the firmware version.
    if (!identifierText(d["hw_id"], identity.model) || !identifierText(d["title"], identity.version)) return ErrorReason::UnsupportedRouter;
    return supportedVersion(identity.version.data()) ? ErrorReason::None : ErrorReason::UnsupportedRouter;
}
ErrorReason parseState(std::string_view body, std::string_view interface, WarpState& state) {
    state = {};
    Allocator allocator; JsonDocument d(&allocator);
    auto error = decode(body, d);
    if (error != ErrorReason::None) return error;
    if (rciError(d.as<JsonVariantConst>())) return ErrorReason::RciFailure;
    const auto value = d[interface].as<JsonObjectConst>();
    if (value.isNull()) return ErrorReason::InterfaceNotFound;
    if (!jsonText(value["id"], interface) || !jsonText(value["type"], "Wireguard") ||
        (!jsonText(value["state"], "up") && !jsonText(value["state"], "down")) ||
        (!jsonText(value["link"], "up") && !jsonText(value["link"], "down")) ||
        (!jsonText(value["connected"], "yes") && !jsonText(value["connected"], "no"))) return ErrorReason::InvalidResponse;
    state = {true, jsonText(value["state"], "up"), jsonText(value["link"], "up"), jsonText(value["connected"], "yes")};
    return ErrorReason::None;
}
ErrorReason parseCommand(std::string_view body) {
    Allocator allocator; JsonDocument d(&allocator);
    auto error = decode(body, d);
    if (error != ErrorReason::None) return error;
    if (rciError(d.as<JsonVariantConst>())) return ErrorReason::RciFailure;
    if (d.size() != 1 || !d["up"].is<JsonObject>() || d["up"].size() != 1 ||
        !d["up"]["status"].is<JsonArray>()) return ErrorReason::InvalidResponse;
    const auto statuses = d["up"]["status"].as<JsonArrayConst>();
    if (statuses.size() != 1) return ErrorReason::InvalidResponse;
    const auto status = statuses[0];
    if (!jsonText(status["status"], "message") || !jsonText(status["code"], "72155286") ||
        !jsonText(status["ident"], "Network::Interface::Base") || !status["message"].is<const char*>()) return ErrorReason::InvalidResponse;
    return ErrorReason::None;
}
bool makeProof(std::string_view login, std::string_view password, std::string_view realm,
               std::string_view challenge, std::array<char, 65>& proof) {
    std::array<unsigned char, 650> input{};
    std::array<unsigned char, 16> md5{};
    std::array<unsigned char, 32> sha{};
    proof.fill(0);
    std::size_t size = 0;
    auto add = [&](std::string_view text) {
        if (text.size() > input.size() - size) return false;
        std::memcpy(input.data() + size, text.data(), text.size()); size += text.size(); return true;
    };
    bool ok = !login.empty() && !password.empty() && !realm.empty() && !challenge.empty() &&
        add(login) && add(":") && add(realm) && add(":") && add(password) && mbedtls_md5(input.data(), size, md5.data()) == 0;
    const char hex[] = "0123456789abcdef";
    erase(input.data(), input.size()); size = 0;
    if (ok) {
        ok = add(challenge);
        if (ok && size + 32 <= input.size()) {
            for (auto byte : md5) { input[size++] = hex[byte >> 4]; input[size++] = hex[byte & 15]; }
            ok = mbedtls_sha256(input.data(), size, sha.data(), 0) == 0;
        } else ok = false;
    }
    if (ok) for (std::size_t i = 0; i < sha.size(); ++i) { proof[i * 2] = hex[sha[i] >> 4]; proof[i * 2 + 1] = hex[sha[i] & 15]; }
    erase(input.data(), input.size()); erase(md5.data(), md5.size()); erase(sha.data(), sha.size()); return ok;
}
bool makeLoginBody(std::string_view login, std::string_view proof, std::array<char, 1025>& body) {
    Allocator allocator; JsonDocument d(&allocator);
    d["login"] = login; d["password"] = proof;
    body.fill(0);
    if (d.overflowed() || measureJson(d) >= body.size()) return false;
    return serializeJson(d, body.data(), body.size()) > 0;
}
}  // namespace warp::keenetic
