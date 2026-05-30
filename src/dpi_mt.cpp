/*
    dpi_mt.cpp = Multi-threaded DPI Engine Entry Point

    This file wires all components together

    RuleManager-> bocking rules (ahred across all FP threads)
    FPManager -> created FP threads and their input queues
    LBManager -> creates LB threads, connects to FP queues
    Output thread -> writes forwarded packets to output.pcap
    Reader (main) ->> reads input .pccap, builds PacketJobs, feeds LBs

    Thread layout with default config (2 LBs, 2 FPs per LB)

    Main/Reader ──► LB0 ──► FP0
                ──► LB0 ──► FP1
                ──► LB1 ──► FP2
                ──► LB1 ──► FP3
                                └──► Output Queue ──► Output Thread


    Usage:
        dpi_engine <input.pcap> <output.pcap> [options]


        Options:
            --block-ip <ip>        block all traffic from source IP
            --block-app <app>      block application (YouTube, TikTok, etc.)
            --block-domain <dom>   block domain pattern (supports *.domain.com)
            --block-port <port>    block destination port
            --lbs <n>              number of load balancer threads (default 2)
            --fps <n>              FP threads per LB (default 2)

*/

#include <iostream>
#include <fstream>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>

#include "pcap_reader.h"
#include "packet_parser.h"
#include "types.h"
#include "rule_manager.h"
#include "fast_path.h"
#include "load_balancer.h"
#include "connection_tracker.h"
#include "thread_safe_queue.h"

using namespace PacketAnalyzer;
using namespace DPI;

/*
    parseIPString() - "192.168.1.1" -> uint32_t (network byte order)

    Duplicated here from main simple.cpp because dpi_mt.cpp is a
    standalone entry point that doesn't include main_simple.cpp
*/
static uint32_t parseIPString(const std::string &ip)
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

/*
    waitFOrQueueDrain()

    Busy waits until a queue's size drops to zero OR timeout_ms elapses
    Used between shutdown stages to let queues drain befire stopping
    the threads that consume them

    A small sleep per iteration avoide buring CPU in a tight loop.
*/
static void waitForQueueDrain(ThreadSafeQueue<PacketJob> &queue,
                              int timeout_ms = 2000)
{
    auto start = std::chrono::steady_clock::now();

    while (!queue.empty())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - start)
                           .count();

        if (elapsed > timeout_ms)
        {
            std::cerr << "[main] Queue drain timeout\n";
            break;
        }
    }
}

/*
     buildPacketJob()

     Converts a parsed packet into a self-contained PacketJob that can be
     safely passed across thread boundaries via the queue.

     Key responsibilities:
       - Copy raw bytes into job.data (owned by the job, not the reader)
       - Fill the FiveTuple from parsed string fields
       - Calculate payload_offset so FP threads don't redo this work
       - Set payload_data pointer into job.data (valid for job's lifetime)

*/
static PacketJob buildPacketJob(const RawPacket &raw,
                                const ParsedPacket &parsed,
                                uint32_t packet_id)
{
    PacketJob job;
    job.packet_id = packet_id;
    job.ts_sec = raw.header.ts_sec;
    job.ts_usec = raw.header.ts_usec;
    job.tcp_flags = parsed.tcp_flags;

    // --- Fill FiveTuple ---
    job.tuple.src_ip = parseIPString(parsed.src_ip);
    job.tuple.dst_ip = parseIPString(parsed.dest_ip);
    job.tuple.src_port = parsed.src_port;
    job.tuple.dst_port = parsed.dest_port;
    job.tuple.protocol = parsed.protocol;

    // --- Copy packet bytes ---
    // This copy is the price of thread safety — the reader moves to
    // the next packet immediately after push(), so we can't share
    // a pointer into reader memory.
    job.data = raw.data; // vector copy

    // --- Calculate layer offsets ---
    // Ethernet is always 14 bytes
    job.eth_offset = 0;
    job.ip_offset = 14;

    if (job.data.size() > 14)
    {
        // IP header length from IHL field (lower 4 bits of first IP byte)
        uint8_t ip_ihl = job.data[14] & 0x0F;
        size_t ip_hdr_len = ip_ihl * 4;
        job.transport_offset = 14 + ip_hdr_len;

        if (parsed.has_tcp &&
            job.data.size() > job.transport_offset + 12)
        {
            // TCP header length from data-offset field
            // (upper 4 bits of byte 12 of TCP header)
            uint8_t tcp_off = (job.data[job.transport_offset + 12] >> 4) & 0x0F;
            size_t tcp_hdr_len = tcp_off * 4;
            job.payload_offset = job.transport_offset + tcp_hdr_len;
        }
        else if (parsed.has_udp)
        {
            // UDP header is always exactly 8 bytes
            job.payload_offset = job.transport_offset + 8;
        }
        else
        {
            job.payload_offset = job.transport_offset;
        }

        // Calculate payload length and set the convenience pointer
        if (job.payload_offset < job.data.size())
        {
            job.payload_length = job.data.size() - job.payload_offset;
            job.payload_data = job.data.data() + job.payload_offset;
        }
        else
        {
            job.payload_length = 0;
            job.payload_data = nullptr;
        }
    }

    return job;
}

// printUsage()
static void printUsage(const char *prog)
{
    std::cout
        << "\n"
        << "╔══════════════════════════════════════════════════════════════╗\n"
        << "║           DPI ENGINE v2.0 — Multi-threaded                   ║\n"
        << "╚══════════════════════════════════════════════════════════════╝\n"
        << "\n"
        << "Usage:\n"
        << "  " << prog << " <input.pcap> <output.pcap> [options]\n"
        << "\n"
        << "Options:\n"
        << "  --block-ip <ip>        Block all traffic from source IP\n"
        << "  --block-app <app>      Block application (YouTube, TikTok...)\n"
        << "  --block-domain <dom>   Block domain (supports *.domain.com)\n"
        << "  --block-port <port>    Block destination port number\n"
        << "  --lbs <n>              Load balancer thread count (default 2)\n"
        << "  --fps <n>              FP threads per LB (default 2)\n"
        << "\n"
        << "Examples:\n"
        << "  " << prog << " capture.pcap out.pcap\n"
        << "  " << prog << " capture.pcap out.pcap --block-app YouTube\n"
        << "  " << prog << " capture.pcap out.pcap --block-domain *.tiktok.com"
        << " --lbs 4 --fps 4\n\n";
}

// printEngineConfig()
// Prints the banner and thread layout before processing starts.
static void printEngineConfig(int num_lbs, int fps_per_lb,
                              const std::string &input,
                              const std::string &output)
{
    int total_fps = num_lbs * fps_per_lb;

    std::cout
        << "\n"
        << "╔══════════════════════════════════════════════════════════════╗\n"
        << "║           DPI ENGINE v2.0 — Multi-threaded                   ║\n"
        << "╠══════════════════════════════════════════════════════════════╣\n"
        << "║  Load Balancers : " << std::setw(3) << num_lbs
        << "                                        ║\n"
        << "║  FPs per LB     : " << std::setw(3) << fps_per_lb
        << "                                        ║\n"
        << "║  Total FP threads: " << std::setw(3) << total_fps
        << "                                       ║\n"
        << "╠══════════════════════════════════════════════════════════════╣\n"
        << "║  Input : " << std::setw(52) << std::left << input << "║\n"
        << "║  Output: " << std::setw(52) << std::left << output << "║\n"
        << "╚══════════════════════════════════════════════════════════════╝\n"
        << std::right // reset alignment
        << "\n";
}

// main()
int main(int argc, char *argv[])
{

    // Step 1: Parse command-line arguments
    if (argc < 3)
    {
        printUsage(argv[0]);
        return 1;
    }

    std::string input_file = argv[1];
    std::string output_file = argv[2];

    // Thread count configuration
    int num_lbs = 2;    // default: 2 load balancer threads
    int fps_per_lb = 2; // default: 2 FP threads per LB = 4 FPs total

    // Blocking rules collected from command line
    std::vector<std::string> block_ips;
    std::vector<std::string> block_apps;
    std::vector<std::string> block_domains;
    std::vector<uint16_t> block_ports;

    for (int i = 3; i < argc; i++)
    {
        std::string arg = argv[i];

        if (arg == "--block-ip" && i + 1 < argc)
            block_ips.push_back(argv[++i]);
        else if (arg == "--block-app" && i + 1 < argc)
            block_apps.push_back(argv[++i]);
        else if (arg == "--block-domain" && i + 1 < argc)
            block_domains.push_back(argv[++i]);
        else if (arg == "--block-port" && i + 1 < argc)
            block_ports.push_back(static_cast<uint16_t>(std::stoi(argv[++i])));
        else if (arg == "--lbs" && i + 1 < argc)
            num_lbs = std::stoi(argv[++i]);
        else if (arg == "--fps" && i + 1 < argc)
            fps_per_lb = std::stoi(argv[++i]);
        else if (arg == "--help" || arg == "-h")
        {
            printUsage(argv[0]);
            return 0;
        }
        else
            std::cerr << "[main] Unknown argument: " << arg << "\n";
    }

    printEngineConfig(num_lbs, fps_per_lb, input_file, output_file);

    // Step 2: Open input PCAP file early so we can fail fast
    PcapReader reader;
    if (!reader.open(input_file))
    {
        std::cerr << "[main] Cannot open input: " << input_file << "\n";
        return 1;
    }

    // Step 3: Open output PCAP file and write global header
    std::ofstream output_file_stream(output_file, std::ios::binary);
    if (!output_file_stream.is_open())
    {
        std::cerr << "[main] Cannot open output: " << output_file << "\n";
        return 1;
    }

    // Copy the global header from input → output so the output is a
    // valid .pcap file with matching version, snaplen, and link type
    const PcapGlobalHeader &global_hdr = reader.getGlobalHeader();
    output_file_stream.write(
        reinterpret_cast<const char *>(&global_hdr),
        sizeof(PcapGlobalHeader));

    // Step 4: Create and configure the RuleManager
    RuleManager rule_manager;

    for (const auto &ip : block_ips)
        rule_manager.blockIP(ip);
    for (const auto &app : block_apps)
        rule_manager.blockApp(
            [&]() -> AppType
            {
                // Convert app name string → AppType enum
                for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++)
                {
                    AppType a = static_cast<AppType>(i);
                    if (appTypeToString(a) == app)
                        return a;
                }
                std::cerr << "[main] Unknown app: " << app << "\n";
                return AppType::UNKNOWN;
            }());
    for (const auto &dom : block_domains)
        rule_manager.blockDomain(dom);
    for (uint16_t port : block_ports)
        rule_manager.blockPort(port);

    // Step 5: Create output queue and mutex-protected output writer
    //
    // The output_callback is called by FP threads when they decide
    // FORWARD. We push the job into output_queue_ so a dedicated
    // output thread can write to the file without locking across FPs.
    ThreadSafeQueue<PacketJob> output_queue(50000); // large buffer for bursts
    std::mutex output_file_mutex;

    // Atomic counters updated by the output callback (called from FP threads)
    std::atomic<uint64_t> total_forwarded{0};
    std::atomic<uint64_t> total_dropped{0};

    // The callback: called by every FP thread for every packet decision
    auto output_callback = [&](const PacketJob &job, PacketAction action)
    {
        if (action == PacketAction::DROP)
        {
            total_dropped++;
            return; // discard — don't write to output
        }

        total_forwarded++;
        output_queue.push(job); // hand off to output writer thread
    };

    // Step 6: Create FPManager and LBManager
    //
    // Order matters:
    //   FPManager first — creates FP threads and their input queues
    //   LBManager second — needs the FP queue pointers to connect to them
    int total_fps = num_lbs * fps_per_lb;

    FPManager fp_manager(total_fps, &rule_manager, output_callback);
    LBManager lb_manager(num_lbs, fps_per_lb, fp_manager.getQueuePtrs());

    // Register all FP trackers with the global table for reporting
    GlobalConnectionTable global_conn_table(total_fps);
    for (int i = 0; i < total_fps; i++)
    {
        global_conn_table.registerTracker(
            i, &fp_manager.getFP(i).getConnectionTracker());
    }

    // Step 7: Start the output writer thread
    //
    // Runs independently, draining output_queue and writing to file.
    // Uses output_running flag so it can exit after all FP threads stop.
    std::atomic<bool> output_running{true};

    std::thread output_thread([&]()
                              {
        while (output_running.load() || !output_queue.empty()) {

            auto job_opt = output_queue.popWithTimeout(
                std::chrono::milliseconds(50));

            if (!job_opt) continue;  // timeout — check flags and loop

            // Write packet to output .pcap file
            // Mutex protects against any future multi-writer scenarios
            std::lock_guard<std::mutex> lock(output_file_mutex);

            PcapPacketHeader out_hdr;
            out_hdr.ts_sec   = job_opt->ts_sec;
            out_hdr.ts_usec  = job_opt->ts_usec;
            out_hdr.incl_len = static_cast<uint32_t>(job_opt->data.size());
            out_hdr.orig_len = static_cast<uint32_t>(job_opt->data.size());

            output_file_stream.write(
                reinterpret_cast<const char*>(&out_hdr),
                sizeof(PcapPacketHeader));
            output_file_stream.write(
                reinterpret_cast<const char*>(job_opt->data.data()),
                job_opt->data.size());
        } });

    // Step 8: Start all processing threads
    fp_manager.startAll();
    lb_manager.startAll();

    // Step 9: Reader loop — runs on the main thread
    //
    // Reads every packet from the input file, parses it, builds a
    // PacketJob, and pushes it to the appropriate LB queue.
    //
    // This is the only place where pcap reading and packet parsing happen.
    // All downstream work (classification, rule checking) is in FP threads.
    std::cout << "[Reader] Starting...\n";

    RawPacket raw;
    ParsedPacket parsed;
    uint32_t packet_id = 0;
    uint64_t total_read = 0;
    uint64_t tcp_count = 0;
    uint64_t udp_count = 0;

    while (reader.readNextPacket(raw))
    {

        // Parse raw bytes into structured fields
        if (!PacketParser::parse(raw, parsed))
        {
            continue; // malformed packet — skip silently
        }

        // Skip non-IP or non-TCP/UDP packets (ARP, ICMP, etc.)
        if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp))
        {
            continue;
        }

        // Build a self-contained PacketJob (copies data vector)
        PacketJob job = buildPacketJob(raw, parsed, packet_id++);

        // Update reader-side counters
        total_read++;
        if (parsed.has_tcp)
            tcp_count++;
        else
            udp_count++;

        // Push to the LB that owns this FiveTuple's hash bucket
        // push() blocks if the LB queue is full (backpressure)
        LoadBalancer &lb = lb_manager.getLBForPacket(job.tuple);
        lb.getInputQueue().push(std::move(job));
    }

    reader.close();
    std::cout << "[Reader] Finished — read " << total_read << " packets\n";

    // Step 10: Ordered shutdown
    //
    // Drain queues from front to back so no packets are lost:
    //   Reader done → LB queues drain → LB stop → FP queues drain
    //   → FP stop → output queue drains → output thread stop

    // Wait for all LB input queues to drain
    std::cout << "[main] Waiting for LB queues to drain...\n";
    for (int i = 0; i < num_lbs; i++)
    {
        waitForQueueDrain(lb_manager.getLB(i).getInputQueue());
    }

    // Stop LB threads — they won't push more packets to FP queues
    std::cout << "[main] Stopping LB threads...\n";
    lb_manager.stopAll();

    // Wait for all FP input queues to drain
    std::cout << "[main] Waiting for FP queues to drain...\n";
    for (int i = 0; i < total_fps; i++)
    {
        waitForQueueDrain(fp_manager.getFP(i).getInputQueue());
    }

    // Stop FP threads — they won't push more packets to output queue
    std::cout << "[main] Stopping FP threads...\n";
    fp_manager.stopAll();

    // Signal output thread to finish after draining output queue
    std::cout << "[main] Waiting for output queue to drain...\n";
    output_running.store(false);
    output_queue.shutdown();
    if (output_thread.joinable())
    {
        output_thread.join();
    }

    // Close the output file
    output_file_stream.close();

    // Step 11: Final report
    auto lb_stats = lb_manager.getAggregatedStats();
    auto fp_stats = fp_manager.getAggregatedStats();
    auto rule_stats = rule_manager.getStats();

    std::cout
        << "\n"
        << "╔══════════════════════════════════════════════════════════════╗\n"
        << "║                    PROCESSING REPORT                         ║\n"
        << "╠══════════════════════════════════════════════════════════════╣\n"
        << "║  Packets read:        "
        << std::setw(12) << total_read << "                        ║\n"
        << "║  TCP packets:         "
        << std::setw(12) << tcp_count << "                        ║\n"
        << "║  UDP packets:         "
        << std::setw(12) << udp_count << "                        ║\n"
        << "╠══════════════════════════════════════════════════════════════╣\n"
        << "║  Forwarded:           "
        << std::setw(12) << total_forwarded.load() << "                        ║\n"
        << "║  Dropped:             "
        << std::setw(12) << total_dropped.load() << "                        ║\n"
        << "╠══════════════════════════════════════════════════════════════╣\n"
        << "║  LB packets received: "
        << std::setw(12) << lb_stats.total_received << "                        ║\n"
        << "║  LB packets dispatch: "
        << std::setw(12) << lb_stats.total_dispatched << "                        ║\n"
        << "╠══════════════════════════════════════════════════════════════╣\n"
        << "║  FP packets processed:"
        << std::setw(12) << fp_stats.total_processed << "                        ║\n"
        << "║  FP packets forwarded:"
        << std::setw(12) << fp_stats.total_forwarded << "                        ║\n"
        << "║  FP packets dropped:  "
        << std::setw(12) << fp_stats.total_dropped << "                        ║\n"
        << "║  Active connections:  "
        << std::setw(12) << fp_stats.total_connections << "                        ║\n"
        << "╠══════════════════════════════════════════════════════════════╣\n"
        << "║  Blocking rules:                                             ║\n"
        << "║    IPs:     " << std::setw(6) << rule_stats.blocked_ips
        << "  Apps:   " << std::setw(6) << rule_stats.blocked_apps
        << "  Domains: " << std::setw(6) << rule_stats.blocked_domains
        << "           ║\n"
        << "╚══════════════════════════════════════════════════════════════╝\n";

    // Per-thread breakdown
    std::cout << "\n[Thread Statistics]\n";
    for (int i = 0; i < num_lbs; i++)
    {
        auto s = lb_manager.getLB(i).getStats();
        std::cout << "  LB" << i << ": dispatched=" << s.packets_dispatched << "\n";
    }
    for (int i = 0; i < total_fps; i++)
    {
        auto s = fp_manager.getFP(i).getStats();
        std::cout << "  FP" << i << ": processed=" << s.packets_processed
                  << "  forwarded=" << s.packets_forwarded
                  << "  dropped=" << s.packets_dropped
                  << "  sni=" << s.sni_extractions << "\n";
    }

    // Classification breakdown
    std::cout << fp_manager.generateClassificationReport();

    std::cout << "\n[main] Output written to: " << output_file << "\n";
    return 0;
}