#include "TailscaleWgxRoute.hpp"

#include <cassert>
#include <string>

using artemis::tailscale::Key32;
using artemis::tailscale::Peer;
using artemis::tailscale::SimulatedWgxBackend;
using artemis::tailscale::TailscaleWgxRoute;

namespace {

Key32 makeKey(std::uint8_t start) {
    Key32 key{};
    for (std::size_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<std::uint8_t>(start + i);
    return key;
}

} // namespace

int main() {
    // 1. Unconfigured route fails closed:
    {
        RemoteRouteTarget target;
        target.peerId = "ts-peer";
        target.peerAddress = "100.64.0.5";
        target.targetAddress = "100.64.0.5";

        std::string error;
        TailscaleWgxRoute route;
        assert(!route.start(target, &error));
        assert(!error.empty());
        assert(!route.prepareForStreaming(target, &error));
        route.stop();
        assert(!route.isActive());
    }

    // 2. Simulated backend full lifecycle:
    {
        auto backend = std::make_shared<SimulatedWgxBackend>();
        const auto localKey = makeKey(10);
        const auto peerKey = makeKey(40);

        TailscaleWgxRoute route(
            backend,
            [&peerKey](std::string_view peerId) -> std::optional<Peer> {
                if (peerId == "ts-peer-valid") {
                    Peer peer;
                    peer.stableId = "ts-peer-valid";
                    peer.nodeKey = peerKey;
                    peer.addresses = {"100.64.0.10"};
                    return peer;
                }
                return std::nullopt;
            },
            [&localKey]() -> std::optional<std::pair<std::string, Key32>> {
                return std::make_pair("100.64.0.2", localKey);
            });

        RemoteRouteTarget target;
        target.peerId = "ts-peer-valid";
        target.peerAddress = "100.64.0.10";
        target.targetAddress = "100.64.0.10";

        std::string error;
        assert(route.start(target, &error));
        assert(error.empty());
        assert(route.isActive());
        assert(route.activePeerId() == "ts-peer-valid");
        assert(backend->isRunning());
        assert(backend->isTcpActive());
        assert(!backend->isUdpActive());

        // Prepare streaming activates UDP media relays
        assert(route.prepareForStreaming(target, &error));
        assert(error.empty());
        assert(route.isStreamingPrepared());
        assert(backend->isUdpActive());

        // Stop cleanly tears down
        route.stop();
        assert(!route.isActive());
        assert(!route.isStreamingPrepared());
        assert(!backend->isRunning());
        assert(!backend->isTcpActive());
        assert(!backend->isUdpActive());
    }

    // 3. Validation guards against malformed/missing data:
    {
        auto backend = std::make_shared<SimulatedWgxBackend>();
        const auto localKey = makeKey(10);

        TailscaleWgxRoute route(
            backend,
            [](std::string_view peerId) -> std::optional<Peer> {
                if (peerId == "ts-zero-key") {
                    Peer peer;
                    peer.stableId = "ts-zero-key";
                    peer.nodeKey = Key32{}; // all zeros
                    peer.addresses = {"100.64.0.20"};
                    return peer;
                }
                return std::nullopt;
            },
            [&localKey]() -> std::optional<std::pair<std::string, Key32>> {
                return std::make_pair("100.64.0.2", localKey);
            });

        std::string error;

        // Missing peer in netmap
        RemoteRouteTarget missingPeer{"ts-unknown", "100.64.0.30", "100.64.0.30"};
        assert(!route.start(missingPeer, &error));
        assert(!error.empty());

        // Peer with uninitialized/all-zero node key
        RemoteRouteTarget zeroKeyPeer{"ts-zero-key", "100.64.0.20", "100.64.0.20"};
        error.clear();
        assert(!route.start(zeroKeyPeer, &error));
        assert(!error.empty());

        // Invalid IP address
        RemoteRouteTarget badIpPeer{"ts-zero-key", "invalid-ip", "invalid-ip"};
        error.clear();
        assert(!route.start(badIpPeer, &error));
        assert(!error.empty());

        // Prepare streaming fails if route was not started
        error.clear();
        assert(!route.prepareForStreaming(missingPeer, &error));
        assert(!error.empty());
    }

    return 0;
}
