/*

    main_simple.cpp - single threaded DPI engine

    this is the simple version of the DPI engine. No threads, no queues.
    One packet at a time, processed start to finish before the next.

Purpose:
        - validates that all our version of the DPI engine. No threads, no queues.

        - Easy to debug (no concurrency issues)

        - Fast enough for offline pcap analysis

    Usage:
        dpi_simple <input.pcap> <output.pcap> [options]

    Flow:
        PcapReader -> PacketParser -> FlowTable -> SNIExtractor
        -> sniToAppType → BlockingRules → write/drop → report
*/

#include <iostream>
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <algorithm>
#include <iomanip>

#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"

// Bring in the namespaces we use throughout
using namespace PacketAnalyzer;
using namespace DPI;

/*
    Flow - represents one tracked connection in our table

    One flow object exists per unique FiveTuple.
    It accumulates innformation across All packets of that connection.
*/
struct Flow
{
    FiveTuple tuple;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;         // domain extracted from TLS Client Hello
    uint64_t packets = 0;    // total packets seen for this flow
    uint64_t bytes = 0;      // total bytes seen for this flow
    bool blocked = false;    // true once a block rule matched
    bool classified = false; // true once we have a definitive app type
};

/*

    BlockingRules - stores which IPs, apps and domains are blocked

    Kept deliberatelyy simple here - no mutexes needed (single-threaded)
    The multi-threaded version (dpi_mt.cpp) uses the full RuleManager class.

*/

class BlockingRules
{
public:
    // Block all traffic from a source IP address
    // IP is given as a string e.g, "197.168.1.50"
    void blockIP(const std::string &ip)
    {
        blocked_ips_.insert(parseIP(ip));
        std::cout << "[Rules] Bocking IP: " << ip << '\n';
    }

    // Block all connections to a known application
    // app_name must match appTypeToString() exactly e.g. "YouTube"
    void blockApp(const std::string &app_name)
    {
        // Search all AppType values for one whose string matches
        for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++)
        {
            AppType app = static_cast<AppType>(i);
            if (appTypeToString(app) == app_name)
            {
                blocked_apps_.insert(app);
                std::cout << "[Rules] Blocking app: " << app_name << "\n";
                return;
            }
        }
        std::cerr << "[Rules] Unknown app name: " << app_name << "\n";
    }

    // Block any connection whose SNI contains this substring
    // e.g. "tiktok" blocks "www.tiktok.com", "ads.tiktokcdn.com", etc.
    void blockDomain(const std::string &domain)
    {
        blocked_domains_.push_back(domain);
        std::cout << "[Rules] Blocking domain pattern: " << domain << "\n";
    }

    // Check whether a packet/flow should be blocked.
    // Called once per flow when classification is complete,
    // and again on each subsequent packet (to catch newly added rules).
    bool isBlocked(uint32_t src_ip,
                   AppType app,
                   const std::string &sni) const
    {

        // Check 1: is the source IP on the blocklist?
        if (blocked_ips_.count(src_ip) > 0)
            return true;

        // Check 2: is the detected app on the blocklist?
        if (blocked_apps_.count(app) > 0)
            return true;

        // Check 3: does the SNI contain any blocked domain substring?
        for (const auto &pattern : blocked_domains_)
        {
            if (sni.find(pattern) != std::string::npos)
                return true;
        }

        return false;
    }

private:
    std::unordered_set<uint32_t> blocked_ips_; // numeric IPs
    std::unordered_set<AppType> blocked_apps_; // blocked App Types
    std::vector<std::string> blocked_domains_; // substring patterns

    // Convert "192.168.1.50" to a uint32_t for the fast set lookup
    // we store in the same byte order as FiveTuple (network order from parser)
    static uint32_t parseIP(const std::string &ip)
    {
        uint32_t result = 0;
        int octet = 0;
        int shift = 0;

        for (char c : ip)
        {
            if (c == '.')
            {
                result |= (octet << shift);
                shift += 8;
                octet = 0;
            }
            else if (c >= '0' && c <= '9')
            {
                octet = octet * 10 + (c - '0');
            }
        }
        result |= (octet << shift); // this is the last octet
        return result;
    }
};

/*

calculatePayloadOffset()

Given a raw packet and parsed headers, figure out where the TCP/UDP payload actually starts (byte index into raw.data)

We have to re-read the header lengths from raw bytes because
ParsedPacket doesn't store them (it only stores the finnal fields).

Layout:
    [0..13]    Ethernet header (always 14 bytes)
    [14..14+X] IP header (X = (raw[14] & 0x0F) * 4, usually 20)
    [14+X..]   TCP header (Y = (raw[14+X+12] >> 4) * 4, usually 20)
    [14+X+Y..] PAYLOAD ← this is what we want
*/
size_t calculatePayloadOffset(const RawPacket &raw,
                              const ParsedPacket &parsed)
{
    if (raw.data.size() < 14)
        return raw.data.size();

    // Ethernet is always 14 bytes
    size_t offset = 14;

    // IP header length: lower 4 bits of first IP byte × 4
    if (raw.data.size() <= offset)
        return raw.data.size();
    uint8_t ip_ihl = raw.data[offset] & 0x0F;
    size_t ip_hdr_len = ip_ihl * 4;
    offset += ip_hdr_len;

    if (parsed.has_tcp)
    {
        // TCP header length: upper 4 bits of byte 12 of TCP header × 4
        if (raw.data.size() <= offset + 12)
            return raw.data.size();
        uint8_t tcp_offset = (raw.data[offset + 12] >> 4) & 0x0F;
        size_t tcp_hdr_len = tcp_offset * 4;
        offset += tcp_hdr_len;
    }
    else if (parsed.has_udp)
    {
        // UDP header is always 8 bytes
        offset += 8;
    }

    return offset;
}

/*
    parseIPString()

    Convert a dotted-decimal IP string back to uintn32_t for use as a flow table key and rule check input

    We use this instead of relyinig on pArsedPacket's string form so FiveTuple keys match what BlockingRules stores.
*/
uint32_t parseIPString(const std::string &ip)
{
    uint32_t result = 0;
    int octet = 0;
    int shift = 0;

    for (char c : ip)
    {
        if (c == '.')
        {
            result |= (octet << shift);
            shift += 8;
            octet = 0;
        }
        else if (c >= '0' && c <= '9')
        {
            octet = octet * 10 + (c - '0');
        }
    }
    return result | (octet << shift);
}

// printUsage() — show command-line help
void printUsage(const char *program)
{
    std::cout
        << "\nDPI Engine (Simple) — Single-threaded Deep Packet Inspection\n"
        << "==============================================================\n\n"
        << "Usage:\n"
        << "  " << program << " <input.pcap> <output.pcap> [options]\n\n"
        << "Options:\n"
        << "  --block-ip <ip>        Block all traffic from source IP\n"
        << "  --block-app <app>      Block application (YouTube, TikTok, etc.)\n"
        << "  --block-domain <dom>   Block domain substring (e.g. tiktok)\n\n"
        << "Example:\n"
        << "  " << program
        << " capture.pcap filtered.pcap --block-app YouTube\n\n";
}

// printReport() — display statistics after processing
void printReport(uint64_t total,
                 uint64_t forwarded,
                 uint64_t dropped,
                 const std::unordered_map<FiveTuple, Flow, FiveTupleHash> &flows,
                 const std::unordered_map<AppType, uint64_t> &app_stats)
{

    std::cout
        << "\n╔══════════════════════════════════════════════════════════════╗\n"
        << "║                    PROCESSING REPORT                         ║\n"
        << "╠══════════════════════════════════════════════════════════════╣\n"
        << "║ Total Packets:    " << std::setw(12) << total
        << "                           ║\n"
        << "║ Forwarded:        " << std::setw(12) << forwarded
        << "                           ║\n"
        << "║ Dropped:          " << std::setw(12) << dropped
        << "                           ║\n"
        << "║ Unique Flows:     " << std::setw(12) << flows.size()
        << "                           ║\n"
        << "╠══════════════════════════════════════════════════════════════╣\n"
        << "║                  APPLICATION BREAKDOWN                       ║\n"
        << "╠══════════════════════════════════════════════════════════════╣\n";

    // Sort apps by packet count descending for easy reading
    std::vector<std::pair<AppType, uint64_t>> sorted(
        app_stats.begin(), app_stats.end());
    std::sort(sorted.begin(), sorted.end(),
              [](const auto &a, const auto &b)
              {
                  return a.second > b.second;
              });

    for (const auto &[app, count] : sorted)
    {
        double pct = total > 0 ? (100.0 * count / total) : 0.0;
        int bar_len = static_cast<int>(pct / 5.0); // 1 '#' per 5%
        std::string bar(bar_len, '#');

        std::cout
            << "║ " << std::setw(15) << std::left << appTypeToString(app)
            << std::setw(8) << std::right << count
            << " " << std::setw(5) << std::fixed
            << std::setprecision(1) << pct << "% "
            << std::setw(20) << std::left << bar << "  ║\n";
    }

    std::cout
        << "╚══════════════════════════════════════════════════════════════╝\n";

    // List every unique SNI we detected
    std::cout << "\n[Detected Domains / SNIs]\n";
    for (const auto &[tuple, flow] : flows)
    {
        if (!flow.sni.empty())
        {
            std::cout << "  " << flow.sni
                      << "  →  " << appTypeToString(flow.app_type);
            if (flow.blocked)
                std::cout << "  [BLOCKED]";
            std::cout << "\n";
        }
    }
}

int main(int argc, char *argv[])
{
    // Parse command-line arguments
    if (argc < 3)
    {
        printUsage(argv[0]);
        return 1;
    }

    std::string input_file = argv[1];
    std::string output_file = argv[2];

    BlockingRules rules;

    for (int i = 3; i < argc; i++)
    {
        std::string arg = argv[i];

        if (arg == "--block-ip" && i + 1 < argc)
        {
            rules.blockIP(argv[++i]);
        }
        else if (arg == "--block-app" && i + 1 < argc)
        {
            rules.blockApp(argv[++i]);
        }
        else if (arg == "--block-domain" && i + 1 < argc)
        {
            rules.blockDomain(argv[++i]);
        }
        else
        {
            std::cerr << "[main] Unknown argument: " << arg << "\n";
        }
    }

    // Open input PCAP file
    PcapReader reader;
    if (!reader.open(input_file))
    {
        std::cerr << "[main] Failed to open input: " << input_file << "\n";
        return 1;
    }

    // Open output PCAP file and write global header
    //
    // The output is also a valid .pcap file — Wireshark can open it.
    // We copy the global header from the input so timestamps, snaplen,
    // and link type are preserved exactly.
    std::ofstream output(output_file, std::ios::binary);
    if (!output.is_open())
    {
        std::cerr << "[main] Failed to open output: " << output_file << "\n";
        return 1;
    }

    // Copy the global header from input to output unchanged
    const PcapGlobalHeader &global_hdr = reader.getGlobalHeader();
    output.write(reinterpret_cast<const char *>(&global_hdr),
                 sizeof(PcapGlobalHeader));

    std::cout
        << "\n╔══════════════════════════════════════════════════════════════╗\n"
        << "║             DPI ENGINE v1.0 (Single-threaded)                 ║\n"
        << "╚══════════════════════════════════════════════════════════════╝\n\n"
        << "[DPI] Input:  " << input_file << "\n"
        << "[DPI] Output: " << output_file << "\n\n";

    // Flow table — maps FiveTuple → Flow
    //
    // This is the stateful core of the DPI engine.
    // All packets belonging to the same connection share one Flow entry.
    // FiveTupleHash ensures lookups are O(1) on average.
    std::unordered_map<FiveTuple, Flow, FiveTupleHash> flows;

    // Per-app packet counters for the final report
    std::unordered_map<AppType, uint64_t> app_stats;

    // Global counters
    uint64_t total_packets = 0;
    uint64_t forwarded = 0;
    uint64_t dropped = 0;

    // Main packet processing loop
    //
    // Each iteration: read one packet → parse → classify → forward/drop
    RawPacket raw;       // reused each iteration (avoids repeated allocation)
    ParsedPacket parsed; // reused each iteration

    std::cout << "[DPI] Processing packets...\n\n";

    while (reader.readNextPacket(raw))
    {
        total_packets++;

        // Step 1: Parse the raw bytes into structured fields ---
        if (!PacketParser::parse(raw, parsed))
        {
            // Malformed or unsupported packet — skip silently
            continue;
        }

        // We only handle IP packets with TCP or UDP transport
        if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp))
        {
            continue;
        }

        // Step 2: Build FiveTuple for flow table lookup ---
        FiveTuple tuple;
        tuple.src_ip = parseIPString(parsed.src_ip);
        tuple.dst_ip = parseIPString(parsed.dest_ip);
        tuple.src_port = parsed.src_port;
        tuple.dst_port = parsed.dest_port;
        tuple.protocol = parsed.protocol;

        // Step 3: Look up or create flow entry ---
        // operator[] creates a default Flow if key doesn't exist
        Flow &flow = flows[tuple];
        if (flow.packets == 0)
        {
            // First time we've seen this FiveTuple — initialise it
            flow.tuple = tuple;
        }
        flow.packets++;
        flow.bytes += raw.data.size();

        // Step 4: Try to classify the flow (only if not done yet) ---
        // We keep trying until classified=true because the Client Hello
        // might not arrive on the very first packet
        if (!flow.classified)
        {

            size_t payload_offset = calculatePayloadOffset(raw, parsed);
            size_t payload_length = (payload_offset < raw.data.size())
                                        ? raw.data.size() - payload_offset
                                        : 0;
            const uint8_t *payload = raw.data.data() + payload_offset;

            // TLS SNI extraction (HTTPS on port 443) ---
            if (parsed.has_tcp &&
                parsed.dest_port == 443 &&
                payload_length > 5)
            {

                auto sni = SNIExtractor::extract(payload, payload_length);
                if (sni)
                {
                    flow.sni = *sni;
                    flow.app_type = sniToAppType(*sni);
                    flow.classified = true;

                    std::cout << "[SNI]  " << *sni
                              << "  →  " << appTypeToString(flow.app_type)
                              << "\n";
                }
                else
                {
                    // HTTPS but Client Hello not yet seen —
                    // mark as generic HTTPS for now
                    if (flow.app_type == AppType::UNKNOWN)
                    {
                        flow.app_type = AppType::HTTPS;
                    }
                }
            }

            // HTTP Host header extraction (port 80) ---
            else if (parsed.has_tcp &&
                     parsed.dest_port == 80 &&
                     payload_length > 10)
            {

                auto host = HTTPHostExtractor::extract(payload, payload_length);
                if (host)
                {
                    flow.sni = *host;
                    flow.app_type = sniToAppType(*host);
                    flow.classified = true;

                    std::cout << "[HTTP] " << *host
                              << "  →  " << appTypeToString(flow.app_type)
                              << "\n";
                }
                else
                {
                    if (flow.app_type == AppType::UNKNOWN)
                    {
                        flow.app_type = AppType::HTTP;
                    }
                }
            }

            // DNS queries (port 53 UDP) ---
            else if (parsed.has_udp &&
                     (parsed.dest_port == 53 || parsed.src_port == 53))
            {

                auto domain = DNSExtractor::extractQuery(payload, payload_length);
                if (domain)
                {
                    flow.sni = *domain;
                    flow.app_type = AppType::DNS;
                    flow.classified = true;
                }
                else
                {
                    flow.app_type = AppType::DNS;
                }
            }
        }

        // Step 5: Check blocking rules ---
        // We check every packet — not just on classification — so that
        // newly added rules (in a live system) take effect immediately.
        // For this simple version, rules are fixed at startup.
        if (!flow.blocked)
        {
            flow.blocked = rules.isBlocked(tuple.src_ip,
                                           flow.app_type,
                                           flow.sni);
            if (flow.blocked)
            {
                std::cout << "[BLOCKED] "
                          << parsed.src_ip << ":" << parsed.src_port
                          << " -> "
                          << parsed.dest_ip << ":" << parsed.dest_port
                          << "  app=" << appTypeToString(flow.app_type);
                if (!flow.sni.empty())
                {
                    std::cout << "  sni=" << flow.sni;
                }
                std::cout << "\n";
            }
        }

        // Step 6: Update per-app statistics ---
        app_stats[flow.app_type]++;

        // Step 7: Forward or drop ---
        if (flow.blocked)
        {
            // Drop: just increment counter, don't write to output
            dropped++;
        }
        else
        {
            // Forward: write the packet header + data to output .pcap
            forwarded++;

            // Build the pcap packet header for the output file
            PcapPacketHeader out_hdr;
            out_hdr.ts_sec = raw.header.ts_sec;
            out_hdr.ts_usec = raw.header.ts_usec;
            out_hdr.incl_len = static_cast<uint32_t>(raw.data.size());
            out_hdr.orig_len = raw.header.orig_len;

            output.write(reinterpret_cast<const char *>(&out_hdr),
                         sizeof(PcapPacketHeader));
            output.write(reinterpret_cast<const char *>(raw.data.data()),
                         raw.data.size());
        }
    }

    // Cleanup and report
    reader.close();
    output.close();

    printReport(total_packets, forwarded, dropped, flows, app_stats);

    std::cout << "\n[DPI] Output written to: " << output_file << "\n";
    return 0;
}