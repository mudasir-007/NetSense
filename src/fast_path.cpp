#include "fast_path.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>

/*
    fast_path.cpp

    The FastPathProcessor is the hottest code pathh in the engine.
    Every packet goes through ProcessPacket() which muct be fast.

    Key optimisations:
        - BLOCKED connections exit after one hash lookup + state check
        - CLASSIFIED connections skip payload inspection entirely
        - State cleanup runs every CLEANUP INTERVAL packets, not every packet
        - SNI extraction only attempted on port 443 with enough payload bytes
        - HTTP eaxtraction only attempted or port 80
*/
namespace DPI
{
    // FastPathProcessor Constructor
    FastPathProcessor::FastPathProcessor(int fp_id,
                                         RuleManager *rule_manager,
                                         PacketOutputCallback output_callback)
        : fp_id_(fp_id), input_queue_(10000) // bounded at 10k for backpressure
          ,
          conn_tracker_(fp_id) // each FP has its own private tracker
          ,
          rule_manager_(rule_manager), output_callback_(std::move(output_callback))
    {
    }

    FastPathProcessor::~FastPathProcessor()
    {
        stop();
    }

    // start() - launch the FP thread
    void FastPathProcessor::start()
    {
        if (running_.load())
            return;

        running_.store(true);
        thread_ = std::thread(&FastPathProcessor::run, this);

        std::cout << "[FP" << fp_id_ << "] Started\n";
    }

    /*
        stop() - signal exit and join

        Same pattern as LoadBalancer::stop()
            set flag -> shutdown queue -> join thread
    */
    void FastPathProcessor::stop()
    {
        if (!running_.load())
            return;

        running_.store(false);
        input_queue_.shutdown();

        if (thread_.joinable())
        {
            thread_.join();
        }

        std::cout << "[FP" << fp_id_ << "] Stopped"
                  << " (processed " << packets_processed_.load() << " packets)\n";
    }

    /*
        run() - the FP thread's main loop

        Pperiodically calls cleanupState() every CLEANUP_INTERVAL packets
        to remove idle/closed connections and prevebt memory growth
    */
    void FastPathProcessor::run()
    {
        uint64_t packets_since_cleanup = 0;

        while (running_.load())
        {

            // Block up to 100ms for a packet
            auto job_opt = input_queue_.popWithTimeout(
                std::chrono::milliseconds(100));

            if (!job_opt)
            {
                // Timeout — good opportunity to clean up stale connections
                // even if we haven't hit CLEANUP_INTERVAL yet
                conn_tracker_.cleanupStale(std::chrono::seconds(300));
                packets_since_cleanup = 0;
                continue;
            }

            // Process the packet and get the forwarding decision
            PacketAction action = processPacket(*job_opt);

            // Call the output callback — engine decides what to do with it
            if (output_callback_)
            {
                output_callback_(*job_opt, action);
            }

            // Update directional stats counters
            if (action == PacketAction::DROP)
            {
                packets_dropped_++;
            }
            else
            {
                packets_forwarded_++;
            }

            packets_processed_++;
            packets_since_cleanup++;

            // Periodic stale connection cleanup
            if (packets_since_cleanup >= CLEANUP_INTERVAL)
            {
                conn_tracker_.cleanupStale(std::chrono::seconds(300));
                packets_since_cleanup = 0;
            }
        }
    }

    /*
        processPacket() - the hot path, called for every packet

        Returns FORWARD or DROP
        tries to exit as early as possible for the common cases
    */
    PacketAction FastPathProcessor::processPacket(PacketJob &job)
    {

        // --- Step 1: look up or create flow entry ---
        // O(1) average hash map lookup
        Connection *conn = conn_tracker_.getOrCreateConnection(job.tuple);
        if (!conn)
        {
            // Should never happen — defensive fallback
            return PacketAction::FORWARD;
        }

        // --- Step 2: fast exit for already-blocked connections ---
        // After the first block decision, all subsequent packets take this path.
        // Cost: one state comparison. No rule checking, no SNI parsing.
        if (conn->state == ConnectionState::BLOCKED)
        {
            return PacketAction::DROP;
        }

        // --- Step 3: update counters and timestamp ---
        // We treat all packets as outbound (client → server direction)
        // since in a pcap file we see both directions mixed together.
        conn_tracker_.updateConnection(conn, job.data.size(), true);

        // --- Step 4: update TCP connection state machine ---
        if (job.tuple.protocol == 6)
        { // TCP protocol number
            updateTCPState(conn, job.tcp_flags);
        }

        // --- Step 5: payload inspection (only if not yet classified) ---
        // Once we have a definitive classification, skip this entirely.
        // For blocked connections we already exited above.
        if (conn->state != ConnectionState::CLASSIFIED &&
            job.payload_length > 0)
        {
            inspectPayload(job, conn);
        }

        // --- Step 6: check blocking rules ---
        // This is called every packet (not just on classification) so that
        // rules added after a connection starts still take effect.
        return checkRules(job, conn);
    }

    /*
        inspectPayload() - try to classift this floww by loaaking at the payload bytes

        Tries each extractor in order, stopping as soon as one succeeds.
        Falls back to port-based classification if none succees;
    */
    void FastPathProcessor::inspectPayload(PacketJob &job, Connection *conn)
    {

        // Guard: make sure payload_offset is valid before we use it
        if (job.payload_offset >= job.data.size())
            return;
        if (job.payload_length == 0)
            return;

        // --- Try TLS SNI extraction (HTTPS traffic) ---
        // Only worth trying on port 443 with enough bytes for a Client Hello
        if (job.tuple.dst_port == 443 && job.payload_length > 5)
        {
            if (tryExtractSNI(job, conn))
                return; // classified — done
        }

        // --- Try HTTP Host header extraction ---
        // Only worth trying on port 80 with enough bytes for a request line
        if (job.tuple.dst_port == 80 && job.payload_length > 10)
        {
            if (tryExtractHTTPHost(job, conn))
                return; // classified — done
        }

        // --- DNS classification ---
        // Port 53 UDP — classify immediately, extract query for SNI field
        if (job.tuple.dst_port == 53 || job.tuple.src_port == 53)
        {
            const uint8_t *payload = job.data.data() + job.payload_offset;

            auto query = DNSExtractor::extractQuery(payload, job.payload_length);
            if (query)
            {
                // Store the DNS query in sni field for reporting purposes
                conn_tracker_.classifyConnection(conn, AppType::DNS, *query);
            }
            else
            {
                conn_tracker_.classifyConnection(conn, AppType::DNS, "");
            }
            return;
        }

        // --- Port-based fallback ---
        // We didn't extract anything useful — assign a generic type.
        // Don't mark as CLASSIFIED so we keep trying on later packets
        // (the Client Hello might not have arrived yet).
        if (conn->app_type == AppType::UNKNOWN)
        {
            if (job.tuple.dst_port == 443)
            {
                conn->app_type = AppType::HTTPS; // generic HTTPS for now
            }
            else if (job.tuple.dst_port == 80)
            {
                conn->app_type = AppType::HTTP; // generic HTTP for now
            }
        }
    }

    /*
        tryExtractSNI() - attempt TLS client Hello parsing

        Returns true if SNI was found and flow was classified.
        UPdates sni_extractions_ and classification_hits_ counters.
    */
    bool FastPathProcessor::tryExtractSNI(const PacketJob &job,
                                          Connection *conn)
    {
        const uint8_t *payload = job.data.data() + job.payload_offset;

        auto sni = SNIExtractor::extract(payload, job.payload_length);
        if (!sni)
            return false; // not a Client Hello or no SNI extension

        sni_extractions_++;

        // Map the hostname to an application type
        AppType app = sniToAppType(*sni);

        // Store classification in the connection entry
        conn_tracker_.classifyConnection(conn, app, *sni);

        // Count as a classification hit if we identified a specific app
        // (not just generic HTTPS)
        if (app != AppType::UNKNOWN && app != AppType::HTTPS)
        {
            classification_hits_++;
        }

        return true;
    }

    /*
        tryExtractHTTPHost() - attempt HTTP host header parsing
        Returns true if Host header was found and flow was classified.
    */
    bool FastPathProcessor::tryExtractHTTPHost(const PacketJob &job,
                                               Connection *conn)
    {
        const uint8_t *payload = job.data.data() + job.payload_offset;

        auto host = HTTPHostExtractor::extract(payload, job.payload_length);
        if (!host)
            return false; // not an HTTP request or no Host header

        AppType app = sniToAppType(*host);
        conn_tracker_.classifyConnection(conn, app, *host);

        if (app != AppType::UNKNOWN && app != AppType::HTTP)
        {
            classification_hits_++;
        }

        return true;
    }

    /*
        checkRules() - evaluate all blocking rules for this packet

        Returns DROP if any rule matches and blocks the connection.
        Returns FORWARD otherwise.

        On a match: calls blockConnection() to cache the DROP decision
        so future paxkets for this flow skip rule checking entirely.
    */
    PacketAction FastPathProcessor::checkRules(const PacketJob &job,
                                               Connection *conn)
    {
        if (!rule_manager_)
            return PacketAction::FORWARD;

        // Ask the rule manager to evaluate all four rule categories
        auto block_reason = rule_manager_->shouldBlock(
            job.tuple.src_ip,
            job.tuple.dst_port,
            conn->app_type,
            conn->sni);

        if (!block_reason)
            return PacketAction::FORWARD; // no rule matched

        // A rule matched — log it and cache the block decision
        std::cout << "[FP" << fp_id_ << "] BLOCK ";

        switch (block_reason->type)
        {
        case RuleManager::BlockReason::IP_RULE:
            std::cout << "IP=" << block_reason->detail;
            break;
        case RuleManager::BlockReason::PORT_RULE:
            std::cout << "Port=" << block_reason->detail;
            break;
        case RuleManager::BlockReason::APP_RULE:
            std::cout << "App=" << block_reason->detail;
            break;
        case RuleManager::BlockReason::DOMAIN_RULE:
            std::cout << "Domain=" << block_reason->detail;
            break;
        }

        std::cout << " sni=" << conn->sni
                  << " app=" << appTypeToString(conn->app_type)
                  << "\n";

        // Cache the block decision — all future packets exit at step 2
        conn_tracker_.blockConnection(conn);

        return PacketAction::DROP;
    }

    /*
        updateTCPState() - advance the TCP connection state machine

        Tracks the three-way handshake so we can mark connections ESTABLISHED
        and detect connection teardown (FIN/RST -> CLOSED)

        State transisions:
           NEW + SYN             → conn->syn_seen = true
           NEW + SYN+ACK         → conn->syn_ack_seen = true
           syn_seen + syn_ack_seen + ACK → ESTABLISHED
           any state + FIN       → conn->fin_seen = true
           fin_seen + ACK        → CLOSED
           any state + RST       → CLOSED immediately
    */
    void FastPathProcessor::updateTCPState(Connection *conn, uint8_t flags)
    {
        // TCP flag bitmasks (same as TCPFlags namespace in packet_parser.h)
        constexpr uint8_t SYN = 0x02;
        constexpr uint8_t ACK = 0x10;
        constexpr uint8_t FIN = 0x01;
        constexpr uint8_t RST = 0x04;

        // Track handshake progress
        if ((flags & SYN) && !(flags & ACK))
        {
            // Pure SYN — connection initiation from client
            conn->syn_seen = true;
        }

        if ((flags & SYN) && (flags & ACK))
        {
            // SYN+ACK — server response to client SYN
            conn->syn_ack_seen = true;
        }

        // Handshake complete: we've seen SYN, SYN-ACK, and now a plain ACK
        if (conn->syn_seen && conn->syn_ack_seen &&
            (flags & ACK) && !(flags & SYN) &&
            conn->state == ConnectionState::NEW)
        {
            conn->state = ConnectionState::ESTABLISHED;
        }

        // RST — abrupt connection reset, close immediately
        if (flags & RST)
        {
            conn->state = ConnectionState::CLOSED;
            conn_tracker_.closeConnection(conn->tuple);
            return;
        }

        // FIN — graceful close initiated
        if (flags & FIN)
        {
            conn->fin_seen = true;
        }

        // FIN + ACK seen — connection is fully closed
        if (conn->fin_seen && (flags & ACK))
        {
            conn->state = ConnectionState::CLOSED;
            conn_tracker_.closeConnection(conn->tuple);
        }
    }

    // getStats()
    FastPathProcessor::FPStats FastPathProcessor::getStats() const
    {
        FPStats stats;
        stats.packets_processed = packets_processed_.load();
        stats.packets_forwarded = packets_forwarded_.load();
        stats.packets_dropped = packets_dropped_.load();
        stats.connections_tracked = conn_tracker_.getActiveCount();
        stats.sni_extractions = sni_extractions_.load();
        stats.classification_hits = classification_hits_.load();
        return stats;
    }

    // FPManager Constructor
    FPManager::FPManager(int num_fps,
                         RuleManager *rule_manager,
                         PacketOutputCallback output_callback)
    {

        fps_.reserve(num_fps);
        for (int i = 0; i < num_fps; i++)
        {
            fps_.push_back(std::make_unique<FastPathProcessor>(
                i, rule_manager, output_callback));
        }

        std::cout << "[FPManager] Created " << num_fps << " fast path thread(s)\n";
    }

    FPManager::~FPManager()
    {
        stopAll();
    }

    void FPManager::startAll()
    {
        for (auto &fp : fps_)
            fp->start();
    }

    void FPManager::stopAll()
    {
        for (auto &fp : fps_)
            fp->stop();
    }

    // getQueuePtrs() — raw pointers to FP input queues for LBManager
    std::vector<ThreadSafeQueue<PacketJob> *> FPManager::getQueuePtrs()
    {
        std::vector<ThreadSafeQueue<PacketJob> *> ptrs;
        ptrs.reserve(fps_.size());
        for (auto &fp : fps_)
        {
            ptrs.push_back(&fp->getInputQueue());
        }
        return ptrs;
    }

    // getAggregatedStats()
    FPManager::AggregatedStats FPManager::getAggregatedStats() const
    {
        AggregatedStats totals{0, 0, 0, 0};
        for (const auto &fp : fps_)
        {
            auto s = fp->getStats();
            totals.total_processed += s.packets_processed;
            totals.total_forwarded += s.packets_forwarded;
            totals.total_dropped += s.packets_dropped;
            totals.total_connections += s.connections_tracked;
        }
        return totals;
    }

    // generateClassificationReport()
    // Aggregates app distribution and SNI list across all FP trackers
    // and formats it into a bordered console table.
    std::string FPManager::generateClassificationReport() const
    {

        // Collect app counts and domain counts from all FP flow tables
        std::unordered_map<AppType, size_t> app_counts;
        std::unordered_map<std::string, AppType> sni_map;

        for (const auto &fp : fps_)
        {
            fp->getConnectionTracker().forEach([&](const Connection &conn)
                                               {
            app_counts[conn.app_type]++;
            if (!conn.sni.empty()) {
                sni_map[conn.sni] = conn.app_type;
            } });
        }

        size_t total = 0;
        for (const auto &p : app_counts)
            total += p.second;

        // Sort apps by count descending
        std::vector<std::pair<AppType, size_t>> sorted_apps(
            app_counts.begin(), app_counts.end());
        std::sort(sorted_apps.begin(), sorted_apps.end(),
                  [](const auto &a, const auto &b)
                  {
                      return a.second > b.second;
                  });

        std::ostringstream ss;
        ss << "\n╔══════════════════════════════════════════════════════════════╗\n"
           << "║              APPLICATION CLASSIFICATION REPORT                ║\n"
           << "╠══════════════════════════════════════════════════════════════╣\n"
           << "║ Total Flows:    " << std::setw(12) << total
           << "                           ║\n"
           << "╠══════════════════════════════════════════════════════════════╣\n";

        for (const auto &[app, count] : sorted_apps)
        {
            double pct = total > 0 ? (100.0 * count / total) : 0.0;
            int bar_len = static_cast<int>(pct / 5.0);
            std::string bar(bar_len, '#');

            ss << "║ " << std::setw(15) << std::left << appTypeToString(app)
               << std::setw(8) << std::right << count
               << " " << std::setw(5) << std::fixed
               << std::setprecision(1) << pct << "% "
               << std::setw(20) << std::left << bar << "  ║\n";
        }

        ss << "╠══════════════════════════════════════════════════════════════╣\n"
           << "║                   DETECTED DOMAINS / SNIs                    ║\n"
           << "╠══════════════════════════════════════════════════════════════╣\n";

        for (const auto &[sni, app] : sni_map)
        {
            std::string display = sni;
            if (display.size() > 35)
                display = display.substr(0, 32) + "...";

            ss << "║  " << std::setw(38) << std::left << display
               << std::setw(18) << std::left << appTypeToString(app) << "  ║\n";
        }

        ss << "╚══════════════════════════════════════════════════════════════╝\n";

        return ss.str();
    }

}