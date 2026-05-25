/*
                 first packet arrives
                           │
                           ▼
                         NEW
                           │
                    SYN + SYN-ACK + ACK
                    (TCP handshake complete)
                           │
                           ▼
                      ESTABLISHED
                           │
                    SNI / Host extracted
                    app type known
                           │
                           ▼
                       CLASSIFIED
                        /       \
               rule matches    no rule
                   /                \
                  ▼                  ▼
              BLOCKED            (stays CLASSIFIED
            drop all              forward all
           future pkts)          future pkts)
                  \                  /
                   \                /
                    ▼              ▼
                        CLOSED
                   (FIN or RST seen)

*/

#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#include "types.h"
#include <unordered_map>
#include <shared_mutex>
#include <vector>
#include <chrono>
#include <functional>

/*

connection_tracker.h

ConnectionTracker - per-FP-thread flow table

    each FastPath thread owns exactly one ConnectionTracker
    No locking is needed on the dlow table itself because consistent
    hashing gurantees only one FP thread sees a given FiveTuple.

    Responsibilities:
        - create Connection entries on first packet of a flow
        - Update oer-flow counters (packets, bytes, timestamps)
        - Transition connection state (NEW->ESTABLISHED->CLASSIFIED->BLOCKED)
        - Evict oldest entry when table hits capacity (LRU eviction)
        - Remove timed-out connections periodically

GlobalconnectionTable - read only aggregated view for reporting

        - holds eaw pointers to all FP ConnectionTrackers
        - Used only by the reporting thread after processing completes.
        - Protected by shared_mutex for safe concurrent reads.

*/
namespace DPI
{
    // ConnectionTracker
    class ConnectionTracker
    {
    public:
        // fp_id: which FP thread owns this tracker (for logging)
        // max_connections: evict oldest this limit is reached
        explicit ConnectionTracker(int fp_id, size_t max_connections = 100000);

        /*
            getOrCreateConnections()

            the most-called function in the entire engine - called once per packet.

            Looks up 'tuple' in the flow table.
                - 'Found': returns pointer to existing connection
                - 'Not Found': created new Connection, returns pointer to it

            If the table is full , exicts tge least-recently-seenn connection first.

            Returns a raw pointer into the map - valid unntil the entry is evicted.
            The FP thread must not cache this pointer across packets.
        */
        Connection *getOrCreateConnection(const FiveTuple &tuple);

        /*
             getConnection()

             Look up an existing connection. Returns nullptr if not found.
             Also tries the reverse tuple (dst->src) to handle reply packets
             that arrive with flipped src/dst (e.g. server -> client direction)
        */
        Connection *getConnection(const FiveTuple &tuple);

        /*
            updateConnection() 

            Called every packet to update counters and last-seen timestamp.
            is_outbound:: true for client-server packets, false for replied.
        */
        void updateConnection(Connection *conn,
                              size_t packet_size,
                              bool is_outbound);

        /*
            classifyConnection()

            Called when SNI or HTTP Host extraction succeeds.
            Transitions state to CLASSIFIED and stores the app_type + SNI.
            No-op if connection is already classified (first result wins).
        */
        void classifyConnection(Connection *conn, AppType app, const std::string &sni);

        /*
             blockConnection()

             Called when a rule matches. Sets state -> BLOCKED and action -> DROP.
             After this, processPacket() drops all future packets of this flow
             without re-checking rules (cached decision)
        */
        void blockConnection(Connection *conn);

        /*
          closeConnection()

          Called when FIN or RSI is seen. Marks state=CLOSED.
          closed connections are removed on the next cleanupState() call.
        */
        void closeConnection(const FiveTuple &tuple);

        /*
            cleanupStale()

            Remove connections that haven't been seen for longer than 'timeout'
            seconds, and connections already marked CLOSED.

            Called periodically from the FP thread loop (e.g. every 30 seconds
            or whenever popWithTimmeout() retuurns nullopt).

            Returns the number of connections removed.
        */

        size_t cleanupStale(
            std::chrono::seconds timeout = std::chrono::seconds(300));

        // Accessors for reporting

        // Get a snapshot of all connections (copies — safe for reporting thread)
        std::vector<Connection> getAllConnections() const;

        // Current number of active connections in this tracker
        size_t getActiveCount() const;

        // Iterate all connections without copying (callback must not modify map)
        void forEach(std::function<void(const Connection &)> callback) const;

        // Statistics
        struct TrackerStats
        {
            size_t active_connections;     // currently in table
            size_t total_connections_seen; // all time (including evicted)
            size_t classified_connections; // successfully got app type
            size_t blocked_connections;    // matched a block rule
        };

        TrackerStats getStats() const;

        // Remove all entries — used in tests
        void clear();

    private:
        int fp_id_;
        size_t max_connections_;

        // The flow table — FiveTuple → Connection
        // No mutex: only one FP thread ever accesses this map
        std::unordered_map<FiveTuple, Connection, FiveTupleHash> connections_;

        // Lifetime counters (never reset)
        size_t total_seen_ = 0;
        size_t classified_count_ = 0;
        size_t blocked_count_ = 0;

        // Evict the least-recently-seen connection to make room
        void evictOldest();
    };

    /*
        GobalConnectionTable

        Aggregates statistice from ALL FP connectionTrackers into one view.
        Used only for the final report - not on the hot packet path.

        Thread safety:
            - FP threads register their trackers via registerTracker() at startup.
            - after registration, FP threads only write to their OWN tracker
            - the reporting thread calls getGlobalStats() / generateReport() after all FP threads ghave stopped -> no concurrent modification
            - shared_mutex allows multiple conocurrent readers in fitture use cases
    */
    class GlobalConnectionTable
    {
    public:
        explicit GlobalConnectionTable(size_t num_fps);

        // Register an FP's tracker so it's included in global stats.
        // Called once per FP thread at engine startup.
        void registerTracker(int fp_id, ConnectionTracker *tracker);

        // GlobalStats — aggregated view across all FP trackers
        struct GlobalStats
        {
            size_t total_active_connections;
            size_t total_connections_seen;

            // How many connections were classified as each app type
            std::unordered_map<AppType, size_t> app_distribution;

            // Most-seen SNI hostnames: (hostname, count) sorted by count desc
            std::vector<std::pair<std::string, size_t>> top_domains;
        };

        GlobalStats getGlobalStats() const;

        // Format a human-readable report string
        std::string generateReport() const;

    private:
        // Raw pointers — FP threads own their trackers, we just observe them
        std::vector<ConnectionTracker *> trackers_;

        // Protects trackers_ vector during registerTracker() calls
        mutable std::shared_mutex mutex_;
    };
}

#endif