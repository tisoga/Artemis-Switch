#include "TailscaleWgxRoute.hpp"
#include "TailscalePeerDirectory.hpp"

#if defined(__SWITCH__) && defined(ENABLE_TAILSCALE)
extern "C" {
#include "wgx.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
}
#include "TailscaleDerp.hpp"
#include "TailscaleTransport.hpp"
#include "../../vpn/SocketFdLock.hpp"
#include "../../utils/Settings.hpp"
#include "../../vpn/VpnFileLogger.hpp"
#include <wg_lwip_relay.hpp>

#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>

// Same shim pattern as TailscaleControlSession: the Switch build links
// X25519 through wg-nx rather than monocypher directly.
extern "C" {
void tailscale_internal_crypto_x25519_public_key(uint8_t[32], const uint8_t[32]);
}
#endif

#include <algorithm>
#include <charconv>
#include <cstring>

namespace artemis::tailscale {

bool SimulatedWgxBackend::startTunnel(const Key32& privateKey,
                                      const std::string& localIp,
                                      std::string* error) {
    const bool allZero =
        std::all_of(privateKey.begin(), privateKey.end(),
                    [](std::uint8_t byte) { return byte == 0; });
    if (allZero) {
        if (error)
            *error = "Simulated backend: private key is uninitialized";
        return false;
    }
    if (localIp.empty() || !PeerDirectory::isLiteralIPv4(localIp)) {
        if (error)
            *error = "Simulated backend: invalid local IP address: " + localIp;
        return false;
    }
    privateKey_ = privateKey;
    localIp_ = localIp;
    running_ = true;
    return true;
}

bool SimulatedWgxBackend::addOrUpdatePeer(uint32_t peerId,
                                          const Key32& publicKey,
                                          const std::string& peerIp,
                                          std::string* error) {
    if (!running_) {
        if (error)
            *error = "Simulated backend: tunnel not running";
        return false;
    }
    if (peerId == 0) {
        if (error)
            *error = "Simulated backend: peer ID must be non-zero";
        return false;
    }
    const bool allZero =
        std::all_of(publicKey.begin(), publicKey.end(),
                    [](std::uint8_t byte) { return byte == 0; });
    if (allZero) {
        if (error)
            *error = "Simulated backend: public key is uninitialized";
        return false;
    }
    if (peerIp.empty() || !PeerDirectory::isLiteralIPv4(peerIp)) {
        if (error)
            *error = "Simulated backend: invalid peer IP address: " + peerIp;
        return false;
    }
    activePeerIp_ = peerIp;
    return true;
}

bool SimulatedWgxBackend::startTcpProxy(const std::string& peerIp,
                                        std::span<const std::uint16_t> ports,
                                        std::string* error) {
    if (!running_) {
        if (error)
            *error = "Simulated backend: tunnel not running";
        return false;
    }
    if (ports.empty()) {
        if (error)
            *error = "Simulated backend: no TCP ports specified";
        return false;
    }
    activePeerIp_ = peerIp;
    tcpPorts_.assign(ports.begin(), ports.end());
    tcpActive_ = true;
    return true;
}

bool SimulatedWgxBackend::startUdpRelay(const std::string& peerIp,
                                        std::span<const std::uint16_t> ports,
                                        std::string* error) {
    if (!running_ || !tcpActive_) {
        if (error)
            *error =
                "Simulated backend: cannot start UDP without active TCP route";
        return false;
    }
    if (ports.empty()) {
        if (error)
            *error = "Simulated backend: no UDP ports specified";
        return false;
    }
    activePeerIp_ = peerIp;
    udpPorts_.assign(ports.begin(), ports.end());
    udpActive_ = true;
    return true;
}

void SimulatedWgxBackend::stopUdpRelay() noexcept {
    udpActive_ = false;
    udpPorts_.clear();
}

bool SimulatedWgxBackend::ensureDerpRoute(const Key32& peerNodeKey,
                                          int homeDerpRegion,
                                          const std::vector<DerpRegion>& derpMap,
                                          const Key32& localPrivateKey,
                                          std::string* error) {
    (void)derpMap;
    (void)localPrivateKey;
    if (!running_) {
        if (error)
            *error = "Simulated backend: tunnel not running";
        return false;
    }
    const bool keyZero =
        std::all_of(peerNodeKey.begin(), peerNodeKey.end(),
                    [](std::uint8_t byte) { return byte == 0; });
    if (keyZero) {
        if (error)
            *error = "Simulated backend: peer node key is uninitialized";
        return false;
    }
    if (homeDerpRegion <= 0) {
        if (error)
            *error = "Simulated backend: peer has no home DERP region";
        return false;
    }
    derpReady_ = true;
    return true;
}

void SimulatedWgxBackend::stop() noexcept {
    stopUdpRelay();
    tcpActive_ = false;
    tcpPorts_.clear();
    running_ = false;
    derpReady_ = false;
    activePeerIp_.clear();
}

bool SimulatedWgxBackend::isRunning() const noexcept { return running_; }
bool SimulatedWgxBackend::isTcpActive() const noexcept { return tcpActive_; }
bool SimulatedWgxBackend::isUdpActive() const noexcept { return udpActive_; }
bool SimulatedWgxBackend::isDerpReady() const noexcept { return derpReady_; }


#if defined(__SWITCH__) && defined(ENABLE_TAILSCALE)

namespace {
void realIngressCallback(void*, const void*, size_t) {}
void tailscaleRelayLog(wgnx::LogLevel, const char*) {}

void logTsRoute(VpnFileLogger::Severity severity, std::string_view message) {
    VpnFileLogger::append(Settings::instance().working_dir() + "/vpn.log",
                          "TS", severity, message);
}

// Bounded byte-wise HTTP response header reader for the DERP upgrade.
// Mirrors the control session's reader; the header ends at the first CRLFCRLF.
bool readDerpUpgradeHeader(ITransport& transport, std::string* header,
                           std::string* error) {
    constexpr std::size_t kMaxHeader = 16 * 1024;
    header->clear();
    std::array<std::uint8_t, 1> byte{};
    while (header->size() < kMaxHeader) {
        const int received = transport.read(byte.data(), 1, error);
        if (received < 0)
            return false;
        if (received == 0) {
            if (error)
                *error = "DERP connection closed during HTTP upgrade";
            return false;
        }
        header->push_back(static_cast<char>(byte[0]));
        if (header->ends_with("\r\n\r\n"))
            return true;
    }
    if (error)
        *error = "oversized DERP upgrade response";
    return false;
}
} // namespace

class RealWgxBackend final : public IWgxBackend {
public:
    ~RealWgxBackend() override { stop(); }

    static void realEgressCallback(void* user, uint32_t peer_id, const void* packet, size_t length) {
        auto* backend = static_cast<RealWgxBackend*>(user);
        // Single active peer: the relay destination is the node key captured
        // at ensureDerpRoute time, not the wgx-internal numeric peer id.
        (void)peer_id;
        if (backend && packet && length > 0)
            backend->sendEgress(packet, length);
    }

    // WireGuard encrypted egress -> DERP SendPacket addressed by peer node key.
    // Runs on the WireGuard worker thread: never blocks on anything except a
    // short TLS write under its own mutex.
    void sendEgress(const void* packet, size_t length) {
        if (length > kDerpMaxPacketSize)
            return;
        // WireGuard message header: one LE u32 type (1 initiation, 2
        // response, 3 cookie, 4 transport). Logged once per type so a
        // malformed stack shows up in vpn.log instead of silent drops.
        if (length >= 4) {
            const auto* bytes = static_cast<const std::uint8_t*>(packet);
            const std::uint32_t msgType =
                static_cast<std::uint32_t>(bytes[0]) |
                (static_cast<std::uint32_t>(bytes[1]) << 8U) |
                (static_cast<std::uint32_t>(bytes[2]) << 16U) |
                (static_cast<std::uint32_t>(bytes[3]) << 24U);
            const unsigned slot = msgType < 8 ? msgType : 0;
            if (!egressTypes_[slot]) {
                egressTypes_[slot] = true;
                logTsRoute(VpnFileLogger::Severity::Info,
                           "DERP relay sending WireGuard type=" +
                               std::to_string(msgType) + " len=" +
                               std::to_string(length));
            }
        }
        std::lock_guard lock(derpWriteMutex_);
        if (!derpAlive_ || !derp_ || !havePeer_)
            return;
        const auto* bytes = static_cast<const std::uint8_t*>(packet);
        if (derp_->sendPacket(std::span<const std::uint8_t>(peerNodeKey_.data(), peerNodeKey_.size()),
                              std::span<const std::uint8_t>(bytes, length), nullptr)) {
            if (!egressLogged_) {
                egressLogged_ = true;
                logTsRoute(VpnFileLogger::Severity::Info,
                           "DERP relay sending peer packets");
            }
        }
    }

    bool startTunnel(const Key32& privateKey, const std::string& localIp,
                     std::string* error) override {
        stop();
        struct in_addr localAddr{};
        if (inet_pton(AF_INET, localIp.c_str(), &localAddr) != 1) {
            if (error) *error = "Invalid local IPv4 for wgx: " + localIp;
            return false;
        }

        context_ = wgx_create(privateKey.data(), localAddr.s_addr,
                              realEgressCallback, realIngressCallback, this);
        if (!context_) {
            if (error) *error = "wgx_create failed";
            return false;
        }

        localIp_ = localIp;
        tunnelCreated_ = true;
        return true;
    }

    bool addOrUpdatePeer(uint32_t peerId, const Key32& publicKey,
                         const std::string& peerIp, std::string* error) override {
        if (!context_ || !tunnelCreated_) {
            if (error) *error = "wgx tunnel is not created";
            return false;
        }
        struct in_addr peerAddr{};
        if (inet_pton(AF_INET, peerIp.c_str(), &peerAddr) != 1) {
            if (error) *error = "Invalid peer IPv4: " + peerIp;
            return false;
        }

        if (wgx_add_or_update_peer(context_, peerId, publicKey.data(),
                                   peerAddr.s_addr) != 0) {
            if (error) *error = "wgx_add_or_update_peer failed";
            return false;
        }

        // Publish the active peer BEFORE the blocking handshake below: replies
        // arriving mid-handshake must inject against this id, otherwise the
        // handshake can never complete and always burns the retry budget.
        activePeerId_ = peerId;
        activePeerIp_ = peerIp;

        // Start WireGuard tunnel now that peer is registered (peer_count > 0)
        if (!running_) {
            if (wgx_start(context_) != 0) {
                if (error) *error = "wgx_start failed";
                return false;
            }
            running_ = true;
        }

        // Blocking handshake over the relay established above: sub-second
        // when the peer is alive, bounded (~20s) when it is dead. A timeout
        // fails the route with a clear error instead of blackholing the
        // GameStream handshake that follows.
        logTsRoute(VpnFileLogger::Severity::Info,
                   "starting WireGuard handshake with peer");
        if (wgx_connect_peer(context_, peerId) != 0) {
            const std::string failure =
                "WireGuard handshake with peer timed out over DERP";
            if (error)
                *error = failure;
            logTsRoute(VpnFileLogger::Severity::Error, failure);
            return false;
        }
        logTsRoute(VpnFileLogger::Severity::Info,
                   "WireGuard handshake with peer completed");

        return true;
    }

    bool ensureDerpRoute(const Key32& peerNodeKey, int homeDerpRegion,
                         const std::vector<DerpRegion>& derpMap,
                         const Key32& localPrivateKey,
                         std::string* error) override {
        const bool peerKeyZero =
            std::all_of(peerNodeKey.begin(), peerNodeKey.end(),
                        [](std::uint8_t byte) { return byte == 0; });
        if (peerKeyZero) {
            if (error) *error = "DERP route requires a valid peer node key";
            return false;
        }
        const bool privateKeyZero =
            std::all_of(localPrivateKey.begin(), localPrivateKey.end(),
                        [](std::uint8_t byte) { return byte == 0; });
        if (privateKeyZero) {
            if (error)
                *error = "DERP route requires the local node private key";
            return false;
        }
        if (homeDerpRegion <= 0) {
            if (error)
                *error = "peer has no home DERP region; the control-plane "
                         "netmap is incomplete";
            return false;
        }
        const DerpRegion* region = nullptr;
        for (const auto& candidate : derpMap) {
            if (candidate.regionId == homeDerpRegion) {
                region = &candidate;
                break;
            }
        }
        if (!region || region->nodes.empty()) {
            if (error)
                *error = "DERP region " + std::to_string(homeDerpRegion) +
                         " is missing from the control-plane map; cannot relay";
            return false;
        }

        // Already relaying for this peer through this region: keep the live
        // session instead of flapping the relay on every route re-activation.
        if (derpAlive_ && derp_ && havePeer_ &&
            peerNodeKey_ == peerNodeKey &&
            activeDerpRegion_ == homeDerpRegion)
            return true;
        stopDerp();

        Key32 localPublic{};
        tailscale_internal_crypto_x25519_public_key(localPublic.data(),
                                                    localPrivateKey.data());

        logTsRoute(VpnFileLogger::Severity::Info,
                   "dialing DERP region " + std::to_string(homeDerpRegion) +
                       " (" + std::to_string(region->nodes.size()) +
                       " node(s)) for peer");
        std::string lastError = "no DERP node attempted";
        for (const auto& node : region->nodes) {
            logTsRoute(VpnFileLogger::Severity::Info,
                       "DERP dialing " + node.host + ":" +
                           std::to_string(node.port));
            auto transport = std::make_unique<SwitchTlsTransport>();
            if (!transport->connect(node.host, node.port, &lastError)) {
                logTsRoute(VpnFileLogger::Severity::Warning,
                           "DERP TLS to " + node.host + " failed: " +
                               lastError);
                continue;
            }
            const std::string request = buildDerpUpgradeRequest(node.host);
            const std::span<const std::uint8_t> requestBytes(
                reinterpret_cast<const std::uint8_t*>(request.data()),
                request.size());
            if (!transport->write(requestBytes, &lastError)) {
                logTsRoute(VpnFileLogger::Severity::Warning,
                           "DERP upgrade write to " + node.host +
                               " failed: " + lastError);
                continue;
            }
            std::string header;
            if (!readDerpUpgradeHeader(*transport, &header, &lastError)) {
                logTsRoute(VpnFileLogger::Severity::Warning,
                           "DERP upgrade read from " + node.host +
                               " failed: " + lastError);
                continue;
            }
            if (!validateDerpUpgradeResponse(header, &lastError)) {
                logTsRoute(VpnFileLogger::Severity::Warning,
                           "DERP upgrade rejected by " + node.host + ": " +
                               lastError);
                continue;
            }
            auto session = std::make_unique<DerpSession>(
                std::move(transport), localPrivateKey, localPublic);
            if (!session->connect(&lastError)) {
                logTsRoute(VpnFileLogger::Severity::Warning,
                           "DERP auth with " + node.host +
                               " failed: " + lastError);
                continue;
            }
            derp_ = std::move(session);
            peerNodeKey_ = peerNodeKey;
            havePeer_ = true;
            activeDerpRegion_ = homeDerpRegion;
            activeDerpHost_ = node.host;
            derpAlive_ = true;
            derpRunning_ = true;
            derpThread_ = std::thread(&RealWgxBackend::derpReader, this);
            logTsRoute(VpnFileLogger::Severity::Info,
                       "DERP relay connected via " + node.host);
            // NOTE: no WatchConns subscription here. Frame 0x10 from a plain
            // client is a protocol violation: the relay closes the session
            // the instant it arrives, which used to masquerade as a peer
            // handshake timeout. PeerPresent/PeerGone below stay handled in
            // case the server volunteers any.
            return true;
        }
        const std::string failure =
            "DERP region " + std::to_string(homeDerpRegion) +
            " unreachable: " + lastError;
        if (error)
            *error = failure;
        logTsRoute(VpnFileLogger::Severity::Error, failure);
        return false;
    }

    bool startTcpProxy(const std::string& peerIp,
                       std::span<const std::uint16_t> ports,
                       std::string* error) override {
        if (!context_ || !running_) {
            if (error) *error = "wgx tunnel is not running";
            return false;
        }

        if (relay_) {
            auto guard = SocketFdLock::instance().guard();
            relay_.reset();
        }

        wgnx::LwipRelayConfig relayConfig;
        relayConfig.log_callback = tailscaleRelayLog;
        auto* wgTunnel = *reinterpret_cast<WgTunnel**>(context_);
        relay_ = std::make_unique<wgnx::LwipRelay>(wgTunnel, relayConfig);

        auto guard = SocketFdLock::instance().guard();
        if (!relay_->start(localIp_, peerIp)) {
            relay_.reset();
            if (error) *error = "LwipRelay start failed for " + peerIp;
            return false;
        }

        for (const auto port : ports) {
            if (relay_->startTcpRelay(port, port) == 0) {
                relay_.reset();
                if (error) *error = "Failed to start TCP relay port " + std::to_string(port);
                return false;
            }
        }

        activePeerIp_ = peerIp;
        return true;
    }

    bool startUdpRelay(const std::string& peerIp,
                       std::span<const std::uint16_t> ports,
                       std::string* error) override {
        (void)peerIp;
        if (!relay_ || !relay_->isRunning()) {
            if (error) *error = "Cannot start UDP relays: TCP proxy is not running";
            return false;
        }
        if (udpPrepared_)
            return true;

        auto guard = SocketFdLock::instance().guard();
        for (const auto port : ports) {
            if (relay_->startUdpRelay(port, port) == 0) {
                if (error) *error = "Failed to start UDP relay port " + std::to_string(port);
                return false;
            }
        }
        udpPrepared_ = true;
        return true;
    }

    void stopUdpRelay() noexcept override {
        udpPrepared_ = false;
    }

    // DERP frame pump: the only thread that blocks in the relay transport.
    // RecvPackets from the active peer are decrypted by DERP framing already
    // (server-routed by node key) and handed to WireGuard as encrypted input.
    // Ping frames are echoed so the relay keeps this client marked present.
    // Any other frame type is protocol housekeeping and safely ignored here.
    void derpReader() {
        std::string error;
        bool firstPacketLogged = false;
        bool foreignLogged = false;
        bool shortLogged = false;
        while (derpRunning_) {
            auto* session = derp_.get();
            if (!session)
                break;
            auto frame = session->recvFrame(&error);
            if (!frame) {
                if (derpRunning_)
                    logTsRoute(VpnFileLogger::Severity::Warning,
                               "DERP session ended: " +
                                   (error.empty() ? "connection closed" : error));
                break;
            }
            switch (frame->type) {
            case DerpFrameType::RecvPacket: {
                const auto& payload = frame->payload;
                if (payload.size() <= kDerpKeyLen) {
                    if (!shortLogged) {
                        shortLogged = true;
                        logTsRoute(VpnFileLogger::Severity::Warning,
                                   "DERP relay sent a runt packet (" +
                                       std::to_string(payload.size()) +
                                       " bytes)");
                    }
                    break;
                }
                if (!context_ ||
                    std::memcmp(payload.data(), peerNodeKey_.data(),
                                kDerpKeyLen) != 0) {
                    // A packet from a node we are not talking to (stale
                    // session, wrong peer key) — never inject it.
                    if (!foreignLogged) {
                        foreignLogged = true;
                        logTsRoute(VpnFileLogger::Severity::Warning,
                                   "DERP relay sent a packet from an unknown "
                                   "node; ignoring");
                    }
                    break;
                }
                wgx_inject_encrypted(
                    context_, activePeerId_.load(std::memory_order_acquire),
                    payload.data() + kDerpKeyLen,
                    payload.size() - kDerpKeyLen);
                if (!firstPacketLogged) {
                    firstPacketLogged = true;
                    logTsRoute(VpnFileLogger::Severity::Info,
                               "DERP relay delivering peer packets");
                }
                break;
            }
            case DerpFrameType::Ping: {
                std::lock_guard lock(derpWriteMutex_);
                if (derpAlive_ && derp_)
                    derp_->writeRaw(DerpFrameType::Pong, frame->payload,
                                    nullptr);
                break;
            }
            case DerpFrameType::Pong:
            case DerpFrameType::KeepAlive:
                break;
            case DerpFrameType::PeerPresent:
            case DerpFrameType::PeerGone: {
                // Presence traffic names 32-byte node keys; log a short
                // prefix so runs can be correlated with the admin console
                // without dumping full keys into the log.
                const auto& payload = frame->payload;
                std::string who = "unknown";
                if (payload.size() >= 32) {
                    constexpr char kHex[] = "0123456789abcdef";
                    who.clear();
                    for (int i = 0; i < 8; ++i) {
                        who.push_back(kHex[payload[i] >> 4U]);
                        who.push_back(kHex[payload[i] & 0x0fU]);
                    }
                }
                logTsRoute(VpnFileLogger::Severity::Info,
                           std::string(
                               frame->type == DerpFrameType::PeerPresent
                                   ? "DERP reports node present: "
                                   : "DERP reports node gone: ") +
                               who);
                break;
            }
            case DerpFrameType::Health:
            default:
                break;
            }
        }
        // The relay is gone (or was never usable). Mark it dead so egress
        // drops fast and the next route activation reconnects instead of
        // stalling the WireGuard handshake into a UI hang.
        derpAlive_ = false;
    }

    void stopDerp() noexcept {
        derpRunning_ = false;
        {
            // Serialize against egress writes: closing the TLS connection
            // while a SendPacket write is in flight corrupts the session.
            std::lock_guard lock(derpWriteMutex_);
            if (derp_)
                derp_->close();
        }
        if (derpThread_.joinable())
            derpThread_.join();
        // The reader is gone; reset under the write mutex so a concurrent
        // egress callback cannot observe half-torn relay state.
        std::lock_guard lock(derpWriteMutex_);
        derp_.reset();
        derpAlive_ = false;
        havePeer_ = false;
        egressLogged_ = false;
        for (auto& seen : egressTypes_)
            seen = false;
        activeDerpRegion_ = 0;
        activeDerpHost_.clear();
    }

    void stop() noexcept override {
        stopDerp();
        running_ = false;
        if (relay_) {
            auto guard = SocketFdLock::instance().guard();
            relay_.reset();
        }
        if (context_) {
            wgx_destroy(context_);
            context_ = nullptr;
        }
        tunnelCreated_ = false;
        localIp_.clear();
        activePeerIp_.clear();
        activePeerId_ = 0;
        udpPrepared_ = false;
    }

    bool isRunning() const noexcept override {
        return tunnelCreated_ && context_ != nullptr;
    }

private:
    WgxContext* context_ = nullptr;
    std::unique_ptr<wgnx::LwipRelay> relay_;
    // Written under the route mutex (addOrUpdatePeer/stop), read by the DERP
    // pump thread: atomic so relay teardown never races packet injection.
    std::atomic_uint32_t activePeerId_{0};
    bool tunnelCreated_ = false;
    std::string localIp_;
    std::string activePeerIp_;
    std::atomic_bool running_ = false;
    bool udpPrepared_ = false;
    // DERP relay state. derpWriteMutex_ serializes TLS writes between the
    // WireGuard egress callback and Ping/Pong echoes; the reader thread is
    // the only code that blocks in recvFrame.
    std::unique_ptr<DerpSession> derp_;
    std::thread derpThread_;
    std::mutex derpWriteMutex_;
    std::atomic_bool derpRunning_{false};
    std::atomic_bool derpAlive_{false};
    Key32 peerNodeKey_{};
    bool havePeer_ = false;
    bool egressLogged_ = false;
    bool egressTypes_[8] = {false};
    int activeDerpRegion_ = 0;
    std::string activeDerpHost_;
};
#endif

TailscaleWgxRoute::TailscaleWgxRoute(std::shared_ptr<IWgxBackend> backend,
                                     PeerResolver peerResolver,
                                     LocalInfoProvider localInfoProvider)
    : backend_(std::move(backend)), peerResolver_(std::move(peerResolver)),
      localInfoProvider_(std::move(localInfoProvider)) {
#if defined(__SWITCH__) && defined(ENABLE_TAILSCALE)
    if (!backend_) {
        backend_ = std::make_shared<RealWgxBackend>();
    }
#endif
}

void TailscaleWgxRoute::setPeerResolver(PeerResolver resolver) {
    std::lock_guard lock(mutex_);
    peerResolver_ = std::move(resolver);
}

void TailscaleWgxRoute::setLocalInfoProvider(LocalInfoProvider provider) {
    std::lock_guard lock(mutex_);
    localInfoProvider_ = std::move(provider);
}

void TailscaleWgxRoute::setDerpMapProvider(DerpMapProvider provider) {
    std::lock_guard lock(mutex_);
    derpMapProvider_ = std::move(provider);
}

void TailscaleWgxRoute::setBackend(std::shared_ptr<IWgxBackend> backend) {
    std::lock_guard lock(mutex_);
    backend_ = std::move(backend);
}

bool TailscaleWgxRoute::start(const RemoteRouteTarget& target,
                              std::string* error) {
    std::lock_guard lock(mutex_);
#if defined(__SWITCH__) && defined(ENABLE_TAILSCALE)
    logTsRoute(VpnFileLogger::Severity::Info,
               "route start: peer=" + target.peerId +
                   " addr=" + target.peerAddress);
#endif
    if (!backend_) {
        if (error)
            *error =
                "Tailscale encrypted packet path is not release-ready; refusing "
                "to advertise a routable connection";
        return false;
    }

    if (target.peerAddress.empty() ||
        !PeerDirectory::isLiteralIPv4(target.peerAddress)) {
        if (error)
            *error = "Tailscale route target has no valid IPv4 address: " +
                     target.peerAddress;
        return false;
    }

    Key32 localPrivateKey{};
    std::string localIp;
    if (localInfoProvider_) {
        auto localInfo = localInfoProvider_();
        if (!localInfo) {
            if (error)
                *error = "Tailscale local identity is not available";
            return false;
        }
        localIp = localInfo->first;
        localPrivateKey = localInfo->second;
    } else {
        if (error)
            *error = "Tailscale local identity provider is not configured";
        return false;
    }

    Key32 peerKey{};
    int homeDerpRegion = 0;
    if (peerResolver_) {
        auto peer = peerResolver_(target.peerId);
        if (!peer) {
            if (error)
                *error = "Tailscale peer not found in netmap: " + target.peerId;
            return false;
        }
        const bool keyEmpty =
            std::all_of(peer->nodeKey.begin(), peer->nodeKey.end(),
                        [](std::uint8_t b) { return b == 0; });
        if (keyEmpty) {
            if (error)
                *error = "Tailscale peer has no valid node key: " + target.peerId;
            return false;
        }
        peerKey = peer->nodeKey;
        homeDerpRegion = peer->homeDerp;
#if defined(__SWITCH__) && defined(ENABLE_TAILSCALE)
        {
            constexpr char kHex[] = "0123456789abcdef";
            std::string keyPrefix;
            for (int i = 0; i < 8; ++i) {
                keyPrefix.push_back(kHex[peerKey[i] >> 4U]);
                keyPrefix.push_back(kHex[peerKey[i] & 0x0fU]);
            }
            logTsRoute(VpnFileLogger::Severity::Info,
                       "peer " + target.peerId + ": online=" +
                           (peer->online ? "yes" : "no") + " homeDerp=" +
                           std::to_string(peer->homeDerp) + " endpoints=" +
                           std::to_string(peer->endpoints.size()) +
                           " nodekey=" + keyPrefix + "...");
        }
#endif
    } else {
        if (error)
            *error = "Tailscale peer resolver is not configured";
        return false;
    }

    if (!backend_->isRunning()) {
        if (!backend_->startTunnel(localPrivateKey, localIp, error))
            return false;
    }

    // The encrypted packet path must be relayed (DERP) BEFORE the WireGuard
    // handshake runs: wg_connect_peer blocks until the handshake completes,
    // and with no relay underneath it burns the whole retry budget (up to
    // 90s) holding the route mutex. Advertising a route without a working
    // relay is what used to blackhole GameStream handshakes into a hang.
    const std::vector<DerpRegion> derpMap =
        derpMapProvider_ ? derpMapProvider_() : std::vector<DerpRegion>{};
    if (!backend_->ensureDerpRoute(peerKey, homeDerpRegion, derpMap,
                                   localPrivateKey, error))
        return false;

    uint32_t peerNumId = static_cast<uint32_t>(
        std::hash<std::string>{}(target.peerId) & 0x7FFFFFFF);
    if (peerNumId == 0)
        peerNumId = 1;

    if (!backend_->addOrUpdatePeer(peerNumId, peerKey, target.peerAddress,
                                   error))
        return false;

    if (!backend_->startTcpProxy(target.peerAddress, kTailscaleTcpPorts, error))
        return false;

    activeTarget_ = target;
    streamingPrepared_ = false;
    return true;
}

bool TailscaleWgxRoute::prepareForStreaming(const RemoteRouteTarget& target,
                                            std::string* error) {
    std::lock_guard lock(mutex_);
    if (!activeTarget_ || activeTarget_->peerId != target.peerId) {
        if (error)
            *error = "Cannot prepare streaming: route is not active for peer " +
                     target.peerId;
        return false;
    }
    if (!backend_ || !backend_->isRunning()) {
        if (error)
            *error = "Cannot prepare streaming: tunnel backend is not running";
        return false;
    }
    if (!backend_->startUdpRelay(target.peerAddress, kTailscaleUdpPorts, error))
        return false;

    streamingPrepared_ = true;
    return true;
}

void TailscaleWgxRoute::stop() noexcept {
    std::lock_guard lock(mutex_);
    if (backend_)
        backend_->stop();
    activeTarget_.reset();
    streamingPrepared_ = false;
}

bool TailscaleWgxRoute::isActive() const noexcept {
    std::lock_guard lock(mutex_);
    return activeTarget_.has_value() && backend_ && backend_->isRunning();
}

bool TailscaleWgxRoute::isStreamingPrepared() const noexcept {
    std::lock_guard lock(mutex_);
    return streamingPrepared_;
}

std::string TailscaleWgxRoute::activePeerId() const {
    std::lock_guard lock(mutex_);
    return activeTarget_ ? activeTarget_->peerId : std::string{};
}

} // namespace artemis::tailscale
