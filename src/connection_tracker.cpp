/*
FP Thread receives packet:
        │
        ▼
getOrCreateConnection(tuple)
        │
        ├── EXISTS in map → return pointer (O(1) hash lookup)
        │
        └── NEW → create Connection{state=NEW, app=UNKNOWN}
                  add to map, total_seen_++
                  return pointer
        │
        ▼
updateConnection(conn, size, outbound)
        │
        └── update last_seen, packets_out++, bytes_out++
        │
        ▼
[if payload contains TLS Client Hello]
classifyConnection(conn, AppType::YOUTUBE, "www.youtube.com")
        │
        └── state = CLASSIFIED
            app_type = YOUTUBE
            sni = "www.youtube.com"
            classified_count_++
        │
        ▼
[if rule says block YOUTUBE]
blockConnection(conn)
        │
        └── state = BLOCKED
            action = DROP
            blocked_count_++
        │
        ▼
[next packet for same FiveTuple]
getOrCreateConnection → returns same conn
conn->state == BLOCKED → return DROP immediately
                         no rule check needed

*/

#include "connection_tracker.h"
#include <algorithm>
#include <sstream>
#include <iomanip>

/*
    connection_tracker.cpp

    implements the per FP flow table and the flobal aggregation table.

    Hot path (called every Packer():
        getOrCreateCinnection() -> updateConnection()

    Classification path (called once per flow, on client Hello packet):
        classifyConnection() -> blockConnection() (if rule matches)

    Mantainance path (called periodically, not on every packet)
        cleanStale -> evictOldest()

*/

namespace DPI
{
    // ConnectionTracker constructor
    ConnectionTracker::ConnectionTracker(int fp_id, size_t max_connections) : fp_id_(fp_id), max_connections_(max_connections)
    {
        // pre-allocate the hash map to avoid refreshing on early insertions.
        // Eeserve 2x expexted to keep load factor low for the o(1) lookups
        connections_.reserve(max_connections / 2);
    }

    /*
        getOrCreateConnection()

        This is on the HOT PATH - called for every single packet.
        Keep it as fast as possible.

        unordered_map::find() is O(1) average - the hash is computed once
        using FiveTupleHash, then the bucket is cheked for an exact match
    */
    Connection *ConnectionTracker::getOrCreateConnection(const FiveTuple &tuple)
    {

        // Fast path: connection already exists (most packets hit this)
        auto it = connections_.find(tuple);
        if (it != connections_.end())
        {
            return &it->second;
        }

        // Slow path: new connection — need to create an entry

        // If we're at capacity, evict the oldest entry first
        if (connections_.size() >= max_connections_)
        {
            evictOldest();
        }

        // Build a new Connection with initial state
        Connection conn;
        conn.tuple = tuple;
        conn.state = ConnectionState::NEW;
        conn.app_type = AppType::UNKNOWN;
        conn.first_seen = std::chrono::steady_clock::now();
        conn.last_seen = conn.first_seen;

        // Insert into map and return pointer to the new entry
        // emplace() returns pair<iterator, bool> — we take the iterator
        auto result = connections_.emplace(tuple, std::move(conn));
        total_seen_++;

        return &result.first->second;
    }

    /*
        getConnection()

        Look up without creating. Also chcks the reverse tuple so we can match server -> client reply packets to the same flow as client->server

        Example:
            Stored key: 192.168.1.1:54321 → 1.2.3.4:443  (client sent)
            Lookup:     1.2.3.4:443 → 192.168.1.1:54321  (server replied)
            reverse()   converts the lookup key → matches stored key
    */
    Connection *ConnectionTracker::getConnection(const FiveTuple &tuple)
    {

        // Try forward direction first (most common)
        auto it = connections_.find(tuple);
        if (it != connections_.end())
        {
            return &it->second;
        }

        // Try reverse direction (server→client replies)
        auto rev = connections_.find(tuple.reverse());
        if (rev != connections_.end())
        {
            return &rev->second;
        }

        return nullptr; // not found in either direction
    }

    /*
        updateConnection()

        Called every packet after getOrCreateConnection()
        updates counters and last[seen timestamp.

        last-seen is used by cleanUpState() to detect idle connections.
    */
    void ConnectionTracker::updateConnection(Connection *conn,
                                             size_t packet_size,
                                             bool is_outbound)
    {
        if (!conn)
            return;

        conn->last_seen = std::chrono::steady_clock::now();

        if (is_outbound)
        {
            conn->packets_out++;
            conn->bytes_out += packet_size;
        }
        else
        {
            conn->packets_in++;
            conn->bytes_in += packet_size;
        }
    }

    /*
        classifyConnection()

        Called once when the SNI extractor or HTTP jost extractor succeeds.
        Transitions state NEW/ESTABLISHED -> CLASSIFIED

        "First result wins" - if somehow two packets both contain SNI
        (shouldn't happen with TLS but defensive mode), we keep the first
    */
    void ConnectionTracker::classifyConnection(Connection *conn,
                                               AppType app,
                                               const std::string &sni)
    {
        if (!conn)
            return;

        // Only classify once — don't overwrite a good classification
        if (conn->state == ConnectionState::CLASSIFIED ||
            conn->state == ConnectionState::BLOCKED)
        {
            return;
        }

        conn->app_type = app;
        conn->sni = sni;
        conn->state = ConnectionState::CLASSIFIED;
        classified_count_++;
    }

    /*
        blockConnection()

        Called when rule checking finds a match.
        Sets action = DROP so future optimisation for blocked connection:
            Packet 1: check rules -> match + blockConnection -> DROP
            Packet 2: conn->state = BLOCKED -> DROP immediately (no rule check)
            PACKET 3: conn->state = BLOCKED -> DROP immediately
    */
    void ConnectionTracker::blockConnection(Connection *conn)
    {
        if (!conn)
            return;

        conn->state = ConnectionState::BLOCKED;
        conn->action = PacketAction::DROP;
        blocked_count_++;
    }

    /*
        closeConnection()

        Called when a TCP FIN or RST flag is open.
        Marks the connection CLOSED - it will be removed by the next
        cleanupStale() call rather than immediately, so any in-flight
        packets for this flow are stii;; handled correctly
    */
    void ConnectionTracker::closeConnection(const FiveTuple &tuple)
    {
        auto it = connections_.find(tuple);
        if (it != connections_.end())
        {
            it->second.state = ConnectionState::CLOSED;
        }
    }

    /*
        cleanupStale()

        Removes connections that are:
            1. Already CLOSED (FIN / RST seen)
            2.. Haven't been seen for longer than 'timeout' seconds

        Called periodically from the FP thread (not on every packet - that would be too expensive)

        iterates the entire app once. Entries to remove are identified and erased safely using the erase by iterator pattern
    */
    size_t ConnectionTracker::cleanupStale(std::chrono::seconds timeout)
    {
        auto now = std::chrono::steady_clock::now();
        size_t removed = 0;

        for (auto it = connections_.begin(); it != connections_.end();)
        {
            const Connection &conn = it->second;

            // Calculate how long since we last saw a packet for this flow
            auto idle_time = std::chrono::duration_cast<std::chrono::seconds>(
                now - conn.last_seen);

            bool should_remove =
                conn.state == ConnectionState::CLOSED || // already finished
                idle_time > timeout;                     // been idle too long

            if (should_remove)
            {
                it = connections_.erase(it); // erase() returns next valid iterator
                removed++;
            }
            else
            {
                ++it;
            }
        }

        return removed;
    }

    /*
        evictOldest()

        Called when the table is full and we need to make room for a new entry.

        Strategy: find the connection with the oldest last seen timestamp and remove it. This is LRU (Least Recently Used) eviction.

        O(n) => we scan the whole table to find the oldest.
        This is acceptable because it's called rarely (only when the table is full)
    */
    void ConnectionTracker::evictOldest()
    {
        if (connections_.empty())
            return;

        // Find the iterator pointing to the entry with the smallest last_seen
        auto oldest = connections_.begin();
        for (auto it = connections_.begin(); it != connections_.end(); ++it)
        {
            if (it->second.last_seen < oldest->second.last_seen)
            {
                oldest = it;
            }
        }

        connections_.erase(oldest);
    }

    // getActiveCount() / getState() / clear() / forEach()
    size_t ConnectionTracker::getActiveCount() const
    {
        return connections_.size();
    }

    ConnectionTracker::TrackerStats ConnectionTracker::getStats() const
    {
        TrackerStats stats;
        stats.active_connections = connections_.size();
        stats.total_connections_seen = total_seen_;
        stats.classified_connections = classified_count_;
        stats.blocked_connections = blocked_count_;
        return stats;
    }

    void ConnectionTracker::clear()
    {
        connections_.clear();
    }

    // forEach: iterate all connections and call callback for each.
    // callback must NOT modify the map (no insert/erase during iteration).
    void ConnectionTracker::forEach(
        std::function<void(const Connection &)> callback) const
    {

        for (const auto &pair : connections_)
        {
            callback(pair.second);
        }
    }

    // GlobalConnectionTable implementation
    GlobalConnectionTable::GlobalConnectionTable(size_t num_fps)
    {
        // Pre-size the vector for registerTracker() can index directly
        trackers_.resize(num_fps, nullptr);
    }

    /*
        registerTracker()

        Called once per FP thread at engine starting.
        Stores a raw pointer - the FP thread owns "the tracker's" lifetime
    */
    void GlobalConnectionTable::registerTracker(int fp_id,
                                                ConnectionTracker *tracker)
    {
        std::unique_lock<std::shared_mutex> lock(mutex_);

        if (fp_id >= 0 && fp_id < static_cast<int>(trackers_.size()))
        {
            trackers_[fp_id] = tracker;
        }
    }

    /*
        getGlobalStats()

        Aggregates data from all FP trackers into onoe GlobalStats struct.

        Called after all FP threads have stopped - no concurrent modification.
        Shared_lock allows multiple concurrent readers if called from a monitoring/stats thread in a future live-capture version.
    */
    GlobalConnectionTable::GlobalStats
    GlobalConnectionTable::getGlobalStats() const
    {

        std::shared_lock<std::shared_mutex> lock(mutex_);

        GlobalStats stats;
        stats.total_active_connections = 0;
        stats.total_connections_seen = 0;

        // Temporary map to count SNI occurrences across all FPs
        std::unordered_map<std::string, size_t> domain_counts;

        for (const ConnectionTracker *tracker : trackers_)
        {
            if (!tracker)
                continue;

            // Add this tracker's counters to global totals
            auto tracker_stats = tracker->getStats();
            stats.total_active_connections += tracker_stats.active_connections;
            stats.total_connections_seen += tracker_stats.total_connections_seen;

            // Walk every connection to build app distribution + domain counts
            tracker->forEach([&](const Connection &conn)
                             {
            stats.app_distribution[conn.app_type]++;

            if (!conn.sni.empty()) {
                domain_counts[conn.sni]++;
            } });
        }

        // Sort domains by count descending and take the top 20
        std::vector<std::pair<std::string, size_t>> domain_vec(
            domain_counts.begin(), domain_counts.end());

        std::sort(domain_vec.begin(), domain_vec.end(),
                  [](const auto &a, const auto &b)
                  {
                      return a.second > b.second;
                  });

        size_t top_n = std::min(domain_vec.size(), static_cast<size_t>(20));
        stats.top_domains.assign(domain_vec.begin(),
                                 domain_vec.begin() + top_n);

        return stats;
    }

    // generateReport()
    // Formats the global stats into a pretty box for console output.
    std::string GlobalConnectionTable::generateReport() const
    {
        auto stats = getGlobalStats();

        std::ostringstream ss;

        ss << "\n╔══════════════════════════════════════════════════════════════╗\n"
           << "║              GLOBAL CONNECTION STATISTICS                     ║\n"
           << "╠══════════════════════════════════════════════════════════════╣\n"
           << "║ Active Connections:     "
           << std::setw(10) << stats.total_active_connections
           << "                          ║\n"
           << "║ Total Connections Seen: "
           << std::setw(10) << stats.total_connections_seen
           << "                          ║\n";

        // App distribution
        ss << "╠══════════════════════════════════════════════════════════════╣\n"
           << "║                   APPLICATION BREAKDOWN                       ║\n"
           << "╠══════════════════════════════════════════════════════════════╣\n";

        size_t total = 0;
        for (const auto &pair : stats.app_distribution)
            total += pair.second;

        // Sort by count descending
        std::vector<std::pair<AppType, size_t>> sorted_apps(
            stats.app_distribution.begin(), stats.app_distribution.end());
        std::sort(sorted_apps.begin(), sorted_apps.end(),
                  [](const auto &a, const auto &b)
                  {
                      return a.second > b.second;
                  });

        for (const auto &pair : sorted_apps)
        {
            double pct = total > 0 ? (100.0 * pair.second / total) : 0.0;
            ss << "║ " << std::setw(20) << std::left << appTypeToString(pair.first)
               << std::setw(8) << std::right << pair.second
               << "  (" << std::fixed << std::setprecision(1)
               << std::setw(5) << pct << "%)                    ║\n";
        }

        // Top domains
        if (!stats.top_domains.empty())
        {
            ss << "╠══════════════════════════════════════════════════════════════╣\n"
               << "║                       TOP DOMAINS                            ║\n"
               << "╠══════════════════════════════════════════════════════════════╣\n";

            for (const auto &pair : stats.top_domains)
            {
                // Truncate long domain names so they fit in the box
                std::string domain = pair.first;
                if (domain.size() > 38)
                {
                    domain = domain.substr(0, 35) + "...";
                }
                ss << "║  " << std::setw(40) << std::left << domain
                   << std::setw(8) << std::right << pair.second
                   << "               ║\n";
            }
        }

        ss << "╚══════════════════════════════════════════════════════════════╝\n";

        return ss.str();
    }
}