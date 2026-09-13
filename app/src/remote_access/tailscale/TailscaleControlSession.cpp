
#if defined(__SWITCH__)
#include "../../utils/Settings.hpp"
#include "../../vpn/VpnFileLogger.hpp"
namespace {
void logTsSession(VpnFileLogger::Severity severity, std::string_view message) {
    VpnFileLogger::append(Settings::instance().working_dir() + "/vpn.log",
                          "TS", severity, message);
}
}
#define LOG_SESSION_INFO(msg) logTsSession(VpnFileLogger::Severity::Info, msg)
#define LOG_SESSION_WARN(msg) logTsSession(VpnFileLogger::Severity::Warning, msg)
#define LOG_SESSION_ERROR(msg) logTsSession(VpnFileLogger::Severity::Error, msg)
#else
#define LOG_SESSION_INFO(msg) do {} while(0)
#define LOG_SESSION_WARN(msg) do {} while(0)
#define LOG_SESSION_ERROR(msg) do {} while(0)
#endif
#include "TailscaleControlSession.hpp"

#include "TailscaleControlCodec.hpp"
#include "TailscaleHttpUpgrade.hpp"
#include "TailscaleHttp2.hpp"
#include "TailscaleTypes.hpp"

extern "C" {
#include <monocypher.h>
}

#if defined(__SWITCH__)
extern "C" {
void tailscale_internal_crypto_x25519_public_key(uint8_t[32], const uint8_t[32]);
}
#define TS_CONTROL_X25519_PUB tailscale_internal_crypto_x25519_public_key
#else
#define TS_CONTROL_X25519_PUB crypto_x25519_public_key
#endif

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <utility>
#include <vector>

namespace artemis::tailscale {
namespace {

constexpr std::size_t kMaxResponseHeader = 16 * 1024;
constexpr std::size_t kReadChunk = 2048;

bool readHttpHeader(ITransport& transport, std::string* header,
                    std::string* error) {
    header->clear();
    std::array<std::uint8_t, 1> byte{};
    while (header->size() < kMaxResponseHeader) {
        const int received = transport.read(byte.data(), 1, error);
        if (received < 0) return false;
        if (received == 0) {
            if (error) *error = "control connection closed during HTTP upgrade";
            return false;
        }
        header->push_back(static_cast<char>(byte[0]));
        if (header->ends_with("\r\n\r\n")) return true;
    }
    if (error) *error = "oversized HTTP upgrade response";
    return false;
}

bool readExact(ITransport& transport, std::span<std::uint8_t> output,
               std::string* error) {
    std::size_t offset = 0;
    while (offset < output.size()) {
        const int received =
            transport.read(output.data() + offset, output.size() - offset, error);
        if (received < 0) return false;
        if (received == 0) {
            if (error) *error = "control connection closed mid-handshake";
            return false;
        }
        offset += static_cast<std::size_t>(received);
    }
    return true;
}


bool isCompleteJsonObject(std::string_view s) {
    int depth = 0;
    bool inString = false;
    bool escape = false;
    bool foundStart = false;
    for (char c : s) {
        if (escape) {
            escape = false;
            continue;
        }
        if (c == '\\') {
            escape = true;
            continue;
        }
        if (c == '"') {
            inString = !inString;
            continue;
        }
        if (inString)
            continue;
        if (c == '{') {
            depth++;
            foundStart = true;
        } else if (c == '}') {
            depth--;
            if (foundStart && depth == 0)
                return true;
        }
    }
    return false;
}

} // namespace

TailscaleControlSession::TailscaleControlSession(
    std::function<std::unique_ptr<ITransport>()> transportFactory,
    std::string host, std::uint16_t port, Key32 controlPublic,
    std::string hostname, RecordReader recordReader)
    : transportFactory_(std::move(transportFactory)), host_(std::move(host)),
      port_(port), controlPublic_(controlPublic),
      hostname_(std::move(hostname)), recordReader_(std::move(recordReader)) {
    if (!recordReader_ && !transportFactory_) {
        transportFactory_ = [] { return std::make_unique<TcpTransport>(); };
    }
}

bool TailscaleControlSession::connect(const Identity& identity,
                                      std::span<const std::uint8_t> authKey,
                                      std::string* error) {
    transport_.reset();
    noise_.reset();
    plaintextQueue_.clear();
    dataAccumulator_.clear();
    ready_ = false;

    if (recordReader_) {
        ready_ = true;
        return true;
    }

    const bool unconfigured = host_.empty() || port_ == 0 ||
                              std::all_of(controlPublic_.begin(),
                                          controlPublic_.end(),
                                          [](std::uint8_t byte) {
                                              return byte == 0;
                                          });
    if (unconfigured) {
        if (error) *error = "Tailscale control endpoint is not configured";
        return false;
    }
    if (!transportFactory_) {
        if (error) *error = "Tailscale transport is unavailable";
        return false;
    }
    LOG_SESSION_INFO("Connecting to control host: " + host_ + ":" + std::to_string(port_));
    transport_ = transportFactory_();
    if (!transport_ || !transport_->connect(host_, port_, error)) {
        LOG_SESSION_ERROR("Transport connection failed: " + (error ? *error : ""));
        transport_.reset();
        if (error && error->empty()) *error = "cannot reach Tailscale control";
        return false;
    }

    Key32 ephemeral{};
    {
        std::random_device source;
        for (auto& byte : ephemeral) byte = static_cast<std::uint8_t>(source());
    }
    noise_ = std::make_unique<NoiseClient>(identity.machinePrivate,
                                           controlPublic_, ephemeral);

    std::vector<std::uint8_t> initiation;
    if (!noise_->begin(&initiation, error)) {
        transport_->close();
        transport_.reset();
        return false;
    }
    const auto request = buildTs2021UpgradeRequest(host_, initiation);
    if (request.empty()) {
        if (error) *error = "cannot build TS2021 upgrade request";
        transport_->close();
        transport_.reset();
        return false;
    }
    if (!transport_->write(std::span<const std::uint8_t>(
                               reinterpret_cast<const std::uint8_t*>(request.data()),
                               request.size()),
                           error)) {
        transport_->close();
        transport_.reset();
        return false;
    }
    std::string header;
    if (!readHttpHeader(*transport_, &header, error) ||
        !validateTs2021UpgradeResponse(header, error)) {
        transport_->close();
        transport_.reset();
        return false;
    }
    std::array<std::uint8_t, NoiseClient::kResponseSize> response{};
    if (!readExact(*transport_, response, error)) {
        transport_->close();
        transport_.reset();
        if (error && error->empty()) *error = "incomplete TS2021 handshake";
        return false;
    }
    LOG_SESSION_INFO("TS2021 Noise handshake completed.");
    if (!noise_->complete(response, error)) {
        transport_->close();
        transport_.reset();
        return false;
    }

    Key32 nodePublic{};
    TS_CONTROL_X25519_PUB(nodePublic.data(), identity.nodePrivate.data());

    Key32 discoPublic{};
    TS_CONTROL_X25519_PUB(discoPublic.data(), identity.discoPrivate.data());

    const bool hasAuthKey = !authKey.empty();
    const int capVer = compat::kCandidateCapabilityVersion > 0
                           ? compat::kCandidateCapabilityVersion
                           : 68;

    // 1. Send HTTP/2 connection preface + initial SETTINGS frame
    const auto preface = buildHttp2ClientPreface();
    std::vector<std::uint8_t> framed;
    if (!noise_->frame(preface, &framed, error) ||
        !transport_->write(framed, error)) {
        transport_->close();
        transport_.reset();
        return false;
    }

    std::uint32_t streamId = 1;
    if (hasAuthKey) {
        // Register the machine with Tailscale
        RegisterRequestData regData;
        regData.nodePublic = nodePublic;
        regData.authKey = std::string(
            reinterpret_cast<const char*>(authKey.data()), authKey.size());
        regData.hostname = hostname_.empty() ? "artemis-switch" : hostname_;
        regData.capabilityVersion = capVer;

        const std::string regJson = encodeRegisterRequest(regData);
        if (!regJson.empty()) {
            const auto headers =
                buildHttp2PostHeaders(streamId, host_, "/machine/register");
            if (!noise_->frame(headers, &framed, error) ||
                !transport_->write(framed, error)) {
                transport_->close();
                transport_.reset();
                return false;
            }

            const auto dataFrame = buildHttp2DataFrame(
                streamId,
                std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t*>(regJson.data()),
                    regJson.size()),
                true);
            if (!noise_->frame(dataFrame, &framed, error) ||
                !transport_->write(framed, error)) {
                transport_->close();
                transport_.reset();
                return false;
            }

            // Wait for registration response on stream 1 before opening map stream
            bool regComplete = false;
            while (!regComplete) {
                auto h2Frame = http2Decoder_.take();
                if (h2Frame) {
                    if (h2Frame->type == 0x04) { // SETTINGS
                        if ((h2Frame->flags & 0x01) == 0) {
                            const auto ack = buildHttp2SettingsAck();
                            std::vector<std::uint8_t> framedAck;
                            if (noise_->frame(ack, &framedAck, error))
                                transport_->write(framedAck, error);
                        }
                        continue;
                    }
                    if (h2Frame->type == 0x00 && h2Frame->streamId == streamId) { // DATA
                        LOG_SESSION_INFO("Registration confirmed by server (" +
                                         std::to_string(h2Frame->payload.size()) + " bytes).");
                        regComplete = true;
                        break;
                    }
                    continue;
                }
                std::string chunk;
                if (!readNextNoiseRecord(&chunk, error)) {
                    transport_->close();
                    transport_.reset();
                    return false;
                }
                http2Decoder_.append(std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t*>(chunk.data()),
                    chunk.size()));
            }
            streamId += 2;
        }
    }

    // 2. Start the streaming netmap request to /machine/map
    MapRequestData mapData;
    mapData.nodePublic = nodePublic;
    mapData.discoPublic = discoPublic;
    mapData.stream = true;
    mapData.capabilityVersion = capVer;

    const std::string mapJson = encodeMapRequest(mapData);
    if (!mapJson.empty()) {
        const auto headers =
            buildHttp2PostHeaders(streamId, host_, "/machine/map");
        if (!noise_->frame(headers, &framed, error) ||
            !transport_->write(framed, error)) {
            transport_->close();
            transport_.reset();
            return false;
        }

        const auto dataFrame = buildHttp2DataFrame(
            streamId,
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(mapJson.data()),
                mapJson.size()),
            true); // endStream = true so server generates MapResponse
        if (!noise_->frame(dataFrame, &framed, error) ||
            !transport_->write(framed, error)) {
            transport_->close();
            transport_.reset();
            return false;
        }
    }

    LOG_SESSION_INFO("Control session connected and HTTP/2 stream established.");
    ready_ = true;
    return true;
}

bool TailscaleControlSession::readNextNoiseRecord(std::string* record,
                                                  std::string* error) {
    while (plaintextQueue_.empty()) {
        std::array<std::uint8_t, kReadChunk> buffer{};
        const int received =
            transport_->read(buffer.data(), buffer.size(), error);
        if (received < 0) return false;
        if (received == 0) {
            if (error) *error = "control connection closed";
            return false;
        }
        if (!noise_ ||
            !noise_->consume(std::span<const std::uint8_t>(
                                 buffer.data(), static_cast<std::size_t>(received)),
                             &plaintextQueue_, error))
            return false;
    }
    const auto& first = plaintextQueue_.front();
    record->assign(first.begin(), first.end());
    plaintextQueue_.erase(plaintextQueue_.begin());
    return true;
}

bool TailscaleControlSession::poll(PeerDelta* delta,
                                   std::optional<std::vector<Peer>>* fullPeers,
                                   std::string* localAddress,
                                   std::optional<std::vector<DerpRegion>>* derpMap,
                                   std::string* error) {
    if (!ready_ || (!recordReader_ && !transport_) || !delta || !fullPeers ||
        !localAddress || !derpMap) {
        if (error) *error = "Tailscale control session is not connected";
        return false;
    }
    if (fullPeers->has_value()) fullPeers->reset();
    derpMap->reset();
    delta->changed.clear();
    delta->removedStableIds.clear();
    localAddress->clear();

    std::string record;
    if (recordReader_) {
        if (!recordReader_(&record, error)) return false;
    } else {
        for (;;) {
            auto h2Frame = http2Decoder_.take();
            if (h2Frame) {
                if (h2Frame->type == 0x04) { // SETTINGS
                    if ((h2Frame->flags & 0x01) == 0) { // Not ACK
                        const auto ack = buildHttp2SettingsAck();
                        std::vector<std::uint8_t> framedAck;
                        if (noise_->frame(ack, &framedAck, error))
                            transport_->write(framedAck, error);
                    }
                    continue;
                }
                if (h2Frame->type == 0x06) { // PING
                    if ((h2Frame->flags & 0x01) == 0) { // Not ACK
                        const auto pong = buildHttp2PingAck(h2Frame->payload);
                        std::vector<std::uint8_t> framedPong;
                        if (noise_->frame(pong, &framedPong, error))
                            transport_->write(framedPong, error);
                    }
                    continue;
                }
                if (h2Frame->type == 0x00) { // DATA
                    if (!mapFrameDecoder_.append(h2Frame->payload, error))
                        return false;
                    auto frame = mapFrameDecoder_.take(error);
                    if (frame) {
                        record = std::move(*frame);
                        break;
                    }
                }
                continue;
            }
            std::string chunk;
            if (!readNextNoiseRecord(&chunk, error)) return false;
            http2Decoder_.append(std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(chunk.data()),
                chunk.size()));
        }
    }

    LOG_SESSION_INFO("Processing netmap JSON (" + std::to_string(record.size()) + " bytes): " + record.substr(0, std::min<size_t>(record.size(), 80)));
    auto update = mapCodec_.decode(record, error);
    if (!update) {
        LOG_SESSION_ERROR("MapCodec decode failed: " + (error ? *error : ""));
        return false;
    }
    if (!update->localAddress.empty()) {
        LOG_SESSION_INFO("Extracted local IP from netmap: " + update->localAddress);
    }
    if (update->keepAlive) return true;
    if (update->fullPeers) *fullPeers = std::move(*update->fullPeers);
    if (!update->localAddress.empty()) *localAddress = update->localAddress;
    if (update->derpMap) *derpMap = std::move(*update->derpMap);
    delta->changed = std::move(update->delta.changed);
    delta->removedStableIds = std::move(update->delta.removedStableIds);
    return true;
}

void TailscaleControlSession::close() noexcept {
    if (transport_) transport_->close();
    transport_.reset();
    noise_.reset();
    plaintextQueue_.clear();
    ready_ = false;
    recordReader_ = nullptr;
}

} // namespace artemis::tailscale
