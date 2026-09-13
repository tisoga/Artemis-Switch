#include "TailscaleWgxRoute.hpp"
#include "TailscalePeerDirectory.hpp"

#if defined(__SWITCH__) && defined(ENABLE_TAILSCALE)
extern "C" {
#include "wgx.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>
}
#include "../../vpn/SocketFdLock.hpp"
#include <wg_lwip_relay.hpp>
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

void SimulatedWgxBackend::stop() noexcept {
    stopUdpRelay();
    tcpActive_ = false;
    tcpPorts_.clear();
    running_ = false;
    activePeerIp_.clear();
}

bool SimulatedWgxBackend::isRunning() const noexcept { return running_; }
bool SimulatedWgxBackend::isTcpActive() const noexcept { return tcpActive_; }
bool SimulatedWgxBackend::isUdpActive() const noexcept { return udpActive_; }


#if defined(__SWITCH__) && defined(ENABLE_TAILSCALE)

namespace {
void realIngressCallback(void*, const void*, size_t) {}
void tailscaleRelayLog(wgnx::LogLevel, const char*) {}
} // namespace

class RealWgxBackend final : public IWgxBackend {
public:
    ~RealWgxBackend() override { stop(); }

    static void realEgressCallback(void* user, uint32_t peer_id, const void* packet, size_t length) {
        auto* backend = static_cast<RealWgxBackend*>(user);
        if (backend) {
            backend->sendEgress(peer_id, packet, length);
        }
    }

    void sendEgress(uint32_t peerId, const void* packet, size_t length) {
        (void)peerId;
        if (udpSocket_ >= 0 && activePeerConfigured_) {
            ::sendto(udpSocket_, packet, length, 0,
                     reinterpret_cast<const sockaddr*>(&peerEndpoint_),
                     sizeof(peerEndpoint_));
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

        udpSocket_ = static_cast<int>(::socket(AF_INET, SOCK_DGRAM, 0));
        if (udpSocket_ >= 0) {
            const int flags = fcntl(udpSocket_, F_GETFL, 0);
            if (flags >= 0)
                fcntl(udpSocket_, F_SETFL, flags | O_NONBLOCK);

            struct sockaddr_in bindAddr{};
            bindAddr.sin_family = AF_INET;
            bindAddr.sin_addr.s_addr = INADDR_ANY;
            bindAddr.sin_port = 0;
            ::bind(udpSocket_, reinterpret_cast<sockaddr*>(&bindAddr), sizeof(bindAddr));
        }

        context_ = wgx_create(privateKey.data(), localAddr.s_addr,
                              realEgressCallback, realIngressCallback, this);
        if (!context_) {
            if (error) *error = "wgx_create failed";
            if (udpSocket_ >= 0) { ::close(udpSocket_); udpSocket_ = -1; }
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

        // Start WireGuard tunnel now that peer is registered (peer_count > 0)
        if (!running_) {
            if (wgx_start(context_) != 0) {
                if (error) *error = "wgx_start failed";
                return false;
            }
            running_ = true;
            rxThread_ = std::thread(&RealWgxBackend::rxWorker, this);
        }

        wgx_connect_peer(context_, peerId);

        ::memset(&peerEndpoint_, 0, sizeof(peerEndpoint_));
        peerEndpoint_.sin_family = AF_INET;
        peerEndpoint_.sin_port = htons(41641); // Tailscale default WireGuard port
        peerEndpoint_.sin_addr = peerAddr;
        activePeerId_ = peerId;
        activePeerIp_ = peerIp;
        activePeerConfigured_ = true;
        return true;
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

    void rxWorker() {
        while (running_) {
            if (udpSocket_ >= 0 && context_ && activePeerId_ != 0) {
                uint8_t buffer[2048];
                sockaddr_in fromAddr{};
                socklen_t fromLen = sizeof(fromAddr);
                const ssize_t received = ::recvfrom(
                    udpSocket_, buffer, sizeof(buffer), 0,
                    reinterpret_cast<sockaddr*>(&fromAddr), &fromLen);
                if (received > 0) {
                    wgx_inject_encrypted(context_, activePeerId_, buffer,
                                         static_cast<size_t>(received));
                }
            }
            if (relay_) {
                relay_->tick();
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }

    void stop() noexcept override {
        running_ = false;
        if (rxThread_.joinable()) {
            rxThread_.join();
        }
        if (udpSocket_ >= 0) {
            ::close(udpSocket_);
            udpSocket_ = -1;
        }
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
        activePeerConfigured_ = false;
        udpPrepared_ = false;
    }

    bool isRunning() const noexcept override {
        return tunnelCreated_ && context_ != nullptr;
    }

private:
    WgxContext* context_ = nullptr;
    std::unique_ptr<wgnx::LwipRelay> relay_;
    int udpSocket_ = -1;
    sockaddr_in peerEndpoint_{};
    uint32_t activePeerId_ = 0;
    bool activePeerConfigured_ = false;
    bool tunnelCreated_ = false;
    std::thread rxThread_;
    std::string localIp_;
    std::string activePeerIp_;
    std::atomic_bool running_ = false;
    bool udpPrepared_ = false;
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

void TailscaleWgxRoute::setBackend(std::shared_ptr<IWgxBackend> backend) {
    std::lock_guard lock(mutex_);
    backend_ = std::move(backend);
}

bool TailscaleWgxRoute::start(const RemoteRouteTarget& target,
                              std::string* error) {
    std::lock_guard lock(mutex_);
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
    } else {
        if (error)
            *error = "Tailscale peer resolver is not configured";
        return false;
    }

    if (!backend_->isRunning()) {
        if (!backend_->startTunnel(localPrivateKey, localIp, error))
            return false;
    }

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
