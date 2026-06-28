#ifndef DPI_TYPES_H
#define DPI_TYPES_H

#include <cstdint>    // uint32_t, uint16_t, uint8_t, uint64_t
#include <string>     // std::string
#include <functional> // std::hash
#include <chrono>     // timestamps
#include <vector>     // std::vector
#include <atomic>     // std::atomic

/*
    types.h => shared data structure used across the entire DPI engine

    everything else includes this file so we keep it dependency free

    Contents:
        FiveTuple: unique key idientifying a network connection
        FiveTupleHash: hash function so FiveTuple workks in unordered map
        AppType: enum of detected applications (YouTube, Facebook, etc)
        ConnectionState: lifecycle of a tracked connection
        PacketAction: what to do with a packet (forward / drop)
        Connection: full state of one tracked flow
        PacketJob: self-containied packet passed between the threads
        DPIStats: engine wide counters
*/

namespace DPI
{
    /*
        FiveTuple -  uniquely identifies one network connection / flow

        all packets with the same values belong to the same conversation.
        We use this as the ket in our flow tabke (unordered map)
    */
    struct FiveTuple
    {
        uint32_t src_ip;   // source IP address (network byte order)
        uint32_t dst_ip;   // destination IP address
        uint16_t src_port; // source port (e.g. 54321 — ephemeral)
        uint16_t dst_port; // destination port (e.g. 443 for HTTPS)
        uint8_t protocol;  // IP protocol: 6=TCP, 17=UDP

        // Equality operator — needed for unordered_map lookup
        bool operator==(const FiveTuple &o) const
        {
            return src_ip == o.src_ip &&
                   dst_ip == o.dst_ip &&
                   src_port == o.src_port &&
                   dst_port == o.dst_port &&
                   protocol == o.protocol;
        }

        // Reverse tuple — server reply has src/dst flipped
        // Useful for bidirectional flow matching
        FiveTuple reverse() const
        {
            return {dst_ip, src_ip, dst_port, src_port, protocol};
        }

        // Human-readable form e.g. "192.168.1.1:54321 -> 1.2.3.4:443 (TCP)"
        std::string toString() const;
    };

    /*
        FiveTupleHash — custom hash function for using FiveTuple as an
        unordered_map key.

        We combine all five fields using the "hash mixing" trick:
        h ^= hash(field) + 0x9e3779b9 + (h<<6) + (h>>2)

        The magic constant 0x9e3779b9 is derived from the golden ratio.
        It spreads bits around to reduce hash collisions.

        This same hash is also used for load balancing — same FiveTuple
        always hashes to the same number, so same connection always goes
        to the same thread.
    */

    struct FiveTupleHash
    {
        size_t operator()(const FiveTuple &t) const
        {
            size_t h = 0;

            // Helper lambda: mix one value into accumulator h
            auto mix = [&](size_t val)
            {
                h ^= val + 0x9e3779b9 + (h << 6) + (h >> 2);
            };

            mix(std::hash<uint32_t>{}(t.src_ip));
            mix(std::hash<uint32_t>{}(t.dst_ip));
            mix(std::hash<uint16_t>{}(t.src_port));
            mix(std::hash<uint16_t>{}(t.dst_port));
            mix(std::hash<uint8_t>{}(t.protocol));

            return h;
        }
    };

    /*

        AppType- what application / service this flow is talking to

        detected by matching the SNI (domain name from the TLS handshake)
        against known patterns in the sniToAppType()

        APP_COOUNT must stay last - it lets s loop over all values
    */

    enum class AppType
    {
        UNKNOWN = 0, // not yet classified
        HTTP,        // plain HTTP (port 80, detected via Host: header)
        HTTPS,       // HTTPS but SNI not yet matched to a known app
        DNS,         // DNS queries (port 53)
        TLS,         // generic TLS (fallback)
        QUIC,        // QUIC/HTTP3 (UDP port 443)

        // --- Known applications (detected via SNI pattern matching) ---
        GOOGLE,
        FACEBOOK,
        YOUTUBE,
        TWITTER,
        INSTAGRAM,
        NETFLIX,
        AMAZON,
        MICROSOFT,
        APPLE,
        WHATSAPP,
        TELEGRAM,
        TIKTOK,
        SPOTIFY,
        ZOOM,
        DISCORD,
        GITHUB,
        CLOUDFLARE,

        APP_COUNT // ← keep this last, used for iteration
    };

    // Convert AppType to printable string (defined in types.cpp)
    std::string appTypeToString(AppType type);

    // Map an SNI hostname string to an AppType.
    // e.g. "www.youtube.com" -> AppType::YOUTUBE
    // e.g. "unknown-site.io" -> AppType::HTTPS  (has SNI but unrecognised)
    // e.g. ""                -> AppType::UNKNOWN (no SNI found yet)
    AppType sniToAppType(const std::string &sni);

    /*

        ConnectionStete - the lifeCycle of a tracked TCP connection

        NEW -> first packet seem (SYN or just first packet)
        ESTABLISHED -> TCP handshake complete (SYN + SYN-ACK + ACK seen)
        CLASSIFIED -> we found the SNY / app type
        BLOCKED -> rules say bocok this connection - dtop all future packets
        CLOSED -> FIN or RST seen - connection is over
    */
    enum class ConnectionState
    {
        NEW,
        ESTABLISHED,
        CLASSIFIED,
        BLOCKED,
        CLOSED
    };

    // PacketAcrtion => what the FP thread should do with a packet
    enum class PacketAction
    {
        FORWARD, // pass it on to the output file / internet
        DROP,    // block it — do not write to output
        INSPECT, // needs more data before a decision (future use)
        LOG_ONLY // forward but record it (future use)
    };

    /*
        Connection - full state on one tracked flow

        one connection object lives in the FP thread;s flow table
        It accumulates information across all packets of the same FiveTuple

        key fields:
            sni - domain name extracted from TLS client Hello
            app_type - what app we think this is (from sniToAppType)
            state - where in the lifecycle this connection is
            action - cached decision (once blocked, always blocked)
    */
    struct Connection
    {
        FiveTuple tuple;
        ConnectionState state = ConnectionState::NEW;
        AppType app_type = AppType::UNKNOWN;
        std::string sni; // e.g. "www.youtube.com"

        // Per-flow traffic counters
        uint64_t packets_in = 0;
        uint64_t packets_out = 0;
        uint64_t bytes_in = 0;
        uint64_t bytes_out = 0;

        // Timestamps (for timeout / stale connection cleanup)
        std::chrono::steady_clock::time_point first_seen;
        std::chrono::steady_clock::time_point last_seen;

        // Cached action — once we decide to block, we remember it
        PacketAction action = PacketAction::FORWARD;

        // TCP handshake tracking flags
        bool syn_seen = false;
        bool syn_ack_seen = false;
        bool fin_seen = false;
    };

    /*
        PacketJob - a self-contained packet  passed between threads via queues

        why copy data instead of using pointers ?
        because the reader thread moves on to the next packet immediately.
        if FP threads held pointers into reader memory, it woulr be a race.
        Copying the data vector mamkes each PacketJob fully independent.

        Key fields calculated at creation itme (in reader / dpi_engine)
            payload_offset - byte index where TCP/UDP payload startds
            payload_length - number of payload bytes

    */
    struct PacketJob
    {
        uint32_t packet_id = 0;
        uint32_t ts_sec = 0;
        uint32_t ts_usec = 0;

        FiveTuple tuple;           // the 5-tuple for this packet
        std::vector<uint8_t> data; // full packet bytes (eth+ip+tcp+payload)

        // Byte offsets into 'data' for each layer
        size_t eth_offset = 0;       // always 0
        size_t ip_offset = 14;       // always 14 (after Ethernet)
        size_t transport_offset = 0; // 14 + IP header length
        size_t payload_offset = 0;   // transport_offset + TCP/UDP header length
        size_t payload_length = 0;   // bytes from payload_offset to end

        uint8_t tcp_flags = 0; // copied from TCP header for easy access

        // Raw pointer into 'data' for quick payload access
        // Valid only as long as 'data' vector is alive
        const uint8_t *payload_data = nullptr;
    };

    /*
        DPIStets - engine wide atomic counters

        std::atomic<uint64_t> means multiple threads can inceement these simultanieously without corrupting the value (no mutex needed for the counters)

        non-copyable because atomics can't be copied - pass by reference / pointer
    */
    struct DPIStats
    {
        std::atomic<uint64_t> total_packets{0};
        std::atomic<uint64_t> total_bytes{0};
        std::atomic<uint64_t> forwarded_packets{0};
        std::atomic<uint64_t> dropped_packets{0};
        std::atomic<uint64_t> tcp_packets{0};
        std::atomic<uint64_t> udp_packets{0};
        std::atomic<uint64_t> other_packets{0};
        std::atomic<uint64_t> active_connections{0};

        // Delete copy constructor and assignment — atomics aren't copyable
        DPIStats() = default;
        DPIStats(const DPIStats &) = delete;
        DPIStats &operator=(const DPIStats &) = delete;
    };

}

#endif

/*
types.h defines the language of the entire project:

*FiveTuple       → identity of a connection

*FiveTupleHash   → how to store FiveTuple in a map
*AppType         → what app is this traffic
*ConnectionState → where in lifecycle
*PacketAction    → what to do with this packet
*Connection      → full state of one flow
*PacketJob       → one packet travelling between threads
*DPIStats        → engine-wide counters
*/


/*
 *   Packet arrives
 *        |
 *        v
 *   [Flow Table Lookup]
 *        |
 *        v
 *   action == DROP?
 *      /       \
 *    YES        NO
 *     |          |
 *     v          v
 *   Discard   Write to
 *             output.pcap
 */