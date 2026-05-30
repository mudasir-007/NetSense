/*

        ┌─────────────────────────────────────────────┐
        │  while (running)                            │
        │    │                                        │
        │    ▼                                        │
        │  popWithTimeout(100ms)                      │
        │    │                                        │
        │    ├── nullopt (timeout) ──► continue       │
        │    │                         (check running_│
        │    │                          cleanup stale)│
        │    ▼                                        │
        │  getOrCreateConnection(tuple)               │
        │    │                                        │
        │    ▼                                        │
        │  conn->state == BLOCKED?                    │
        │    ├── YES ──► DROP immediately             │
        │    │           (no further work needed)     │
        │    ▼                                        │
        │  updateTCPState(flags)                      │
        │    │                                        │
        │    ▼                                        │
        │  conn->state != CLASSIFIED?                 │
        │    ├── YES ──► inspectPayload()             │
        │    │            ├── tryExtractSNI()         │
        │    │            ├── tryExtractHTTPHost()    │
        │    │            └── fallback (port-based)   │
        │    ▼                                        │
        │  checkRules(conn)                           │
        │    ├── match ──► blockConnection()──► DROP  │
        │    └── no match ──────────────────► FORWARD │
        │                                             │
        │  output_callback(job, action)               │
        └─────────────────────────────────────────────┘
*/

#ifndef FAST_PATH_H
#define FAST_PATH_H

#include "types.h"
#include "thread_safe_queue.h"
#include "connection_tracker.h"
#include "rule_manager.h"
#include "sni_extractor.h"
#include <thread>
#include <atomic>
#include <memory>
#include <functional>
#include <vector>

/*
    fast_path.h

    Two classes:
        FastPathProcessor - one FP thread doing the actual DPI Work:
            - Received PaketHOb from It's input queue (fed by LB thread)
            - Looks up or creates a connection entry in its private flow table
            - inspects payload: TLS SNI, HTTP Host, DNS Query
            - Checks blocking rules via the shared RuleManager
            - Calls output_callback with FORWARD or DROP Decision

        FPManager - creates and manages all FP threads, exposes their input queues as raw pointers to LBManager can connect to them

    Key Design:
        Each FP has its OWN connectionTracker (no sharing, no locks)

        Consistent hashing ensures a given FiveTuple always arrives here.
        RuleManager is SHARED and read only from the FP perspective
*/
namespace DPI
{

    // Callback type: FP calls this when it has a forwarding decision.
    // The engine's output thread uses this to write packets to the output file.
    using PacketOutputCallback = std::function<void(const PacketJob &, PacketAction)>;

    // FastPathProcessor — one DPI worker thread
    class FastPathProcessor
    {
    public:
        // fp_id:            which FP this is (0, 1, 2, ...) — for logging
        // rule_manager:     shared read-only rule store
        // output_callback:  called with (job, FORWARD) or (job, DROP)
        FastPathProcessor(int fp_id,
                          RuleManager *rule_manager,
                          PacketOutputCallback output_callback);

        ~FastPathProcessor();

        // Start and stop the FP thread
        void start();
        void stop();

        // LB thread pushes packets here
        ThreadSafeQueue<PacketJob> &getInputQueue() { return input_queue_; }

        // ConnectionTracker is exposed so GlobalConnectionTable can
        // register it for aggregated reporting
        ConnectionTracker &getConnectionTracker() { return conn_tracker_; }

        // Per-FP statistics snapshot
        struct FPStats
        {
            uint64_t packets_processed;
            uint64_t packets_forwarded;
            uint64_t packets_dropped;
            uint64_t connections_tracked;
            uint64_t sni_extractions;     // successful TLS SNI extractions
            uint64_t classification_hits; // flows classified to a known app
        };

        FPStats getStats() const;

        int getId() const { return fp_id_; }
        bool isRunning() const { return running_.load(); }

    private:
        int fp_id_;

        // Input queue — LB thread pushes here, FP thread pops here
        ThreadSafeQueue<PacketJob> input_queue_;

        // Per-FP flow table — no mutex needed (only this thread accesses it)
        ConnectionTracker conn_tracker_;

        // Shared rule store — read-only from FP, written by admin/main thread
        RuleManager *rule_manager_;

        // Called when packet is ready to forward or confirmed dropped
        PacketOutputCallback output_callback_;

        // Atomic performance counters — can be read from stats thread safely
        std::atomic<uint64_t> packets_processed_{0};
        std::atomic<uint64_t> packets_forwarded_{0};
        std::atomic<uint64_t> packets_dropped_{0};
        std::atomic<uint64_t> sni_extractions_{0};
        std::atomic<uint64_t> classification_hits_{0};

        // Thread control
        std::atomic<bool> running_{false};
        std::thread thread_;

        // How many packets to process between stale connection cleanups
        static constexpr uint64_t CLEANUP_INTERVAL = 10000;

        // Internal pipeline stages — called from run() in order

        // Main loop — runs in the FP thread
        void run();

        // Process one packet end-to-end, return FORWARD or DROP
        PacketAction processPacket(PacketJob &job);

        // Try to classify the flow by inspecting payload content
        // Called only when conn->state != CLASSIFIED
        void inspectPayload(PacketJob &job, Connection *conn);

        // Try to extract SNI from TLS Client Hello (port 443)
        // Returns true if SNI was found and flow was classified
        bool tryExtractSNI(const PacketJob &job, Connection *conn);

        // Try to extract Host header from HTTP request (port 80)
        // Returns true if Host was found and flow was classified
        bool tryExtractHTTPHost(const PacketJob &job, Connection *conn);

        // Check all blocking rules for this packet/connection
        // Returns DROP if any rule matches, FORWARD otherwise
        PacketAction checkRules(const PacketJob &job, Connection *conn);

        // Update TCP state machine based on flags in this packet
        // NEW → ESTABLISHED when full handshake is seen
        // → CLOSED when FIN or RST is seen
        void updateTCPState(Connection *conn, uint8_t tcp_flags);
    };

    // FPManager — creates and manages all FP threads
    class FPManager
    {
    public:
        // num_fps:         total number of FP threads to create
        // rule_manager:    shared rule store passed to every FP
        // output_callback: shared output callback passed to every FP
        FPManager(int num_fps,
                  RuleManager *rule_manager,
                  PacketOutputCallback output_callback);

        ~FPManager();

        // Start and stop all FP threads
        void startAll();
        void stopAll();

        // Access individual FP by index
        FastPathProcessor &getFP(int id) { return *fps_[id]; }

        // Get raw pointers to all FP input queues.
        // LBManager uses this to connect LB → FP queues.
        std::vector<ThreadSafeQueue<PacketJob> *> getQueuePtrs();

        int getNumFPs() const { return static_cast<int>(fps_.size()); }

        // Aggregated stats across all FP threads
        struct AggregatedStats
        {
            uint64_t total_processed;
            uint64_t total_forwarded;
            uint64_t total_dropped;
            uint64_t total_connections;
        };

        AggregatedStats getAggregatedStats() const;

        // Generate classification report string for console output
        std::string generateClassificationReport() const;

    private:
        std::vector<std::unique_ptr<FastPathProcessor>> fps_;
    };

} // namespace DPI
#endif // FAST_PATH_H