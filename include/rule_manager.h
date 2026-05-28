#ifndef RULE_MANAGER_H
#define RULE_MANAGER_H

#include "types.h"
#include <string>
#include <unordered_set>
#include <vector>
#include <shared_mutex>
#include <optional>
#include <fstream>

/*
   rule_manager.h

   RuleManager — thread-safe store for all blocking/filtering rules.

   Used by every FP thread simultaneously for rule checking (reads),
   and by the main thread for rule management (writes).

   Thread safety model:
     - Each rule category has its OWN shared_mutex
     - This means blocking an IP does not block FP threads checking apps
     - Fine-grained locking = maximum read parallelism

   Four rule categories:
     IP rules:     block all traffic from a specific source IP
     App rules:    block all connections to a detected application
     Domain rules: block connections whose SNI matches a pattern
     Port rules:   block all traffic to a destination port

   Rule persistence:
     saveRules() / loadRules() write/read a simple text format
     so rules survive engine restarts
*/

namespace DPI
{

    class RuleManager
    {
    public:
        RuleManager() = default;

        // IP Blocking

        // Block all traffic where source IP matches.
        // String form: "192.168.1.50"
        void blockIP(const std::string &ip);
        void blockIP(uint32_t ip);

        void unblockIP(const std::string &ip);
        void unblockIP(uint32_t ip);

        // Returns true if src_ip is on the block list
        bool isIPBlocked(uint32_t ip) const;

        // Returns all blocked IPs as dotted-decimal strings (for display)
        std::vector<std::string> getBlockedIPs() const;

        // Application Blocking

        // Block all connections classified as this application type.
        // e.g. blockApp(AppType::YOUTUBE) drops all YouTube connections.
        void blockApp(AppType app);
        void unblockApp(AppType app);

        bool isAppBlocked(AppType app) const;

        std::vector<AppType> getBlockedApps() const;

        // Domain Blocking
        //
        // Two matching modes:
        //   Exact:    "www.tiktok.com"    matches only that exact SNI
        //   Wildcard: "*.tiktok.com"      matches any subdomain of tiktok.com
        //
        // Exact matches use an unordered_set for O(1) lookup.
        // Wildcard patterns are stored in a vector and checked with
        // domainMatchesPattern() which handles the *.domain.com form.
        void blockDomain(const std::string &domain);
        void unblockDomain(const std::string &domain);

        // Returns true if 'domain' matches any blocked domain or pattern
        bool isDomainBlocked(const std::string &domain) const;

        std::vector<std::string> getBlockedDomains() const;

        // Port Blocking

        // Block all traffic to a destination port.
        // e.g. blockPort(6881) blocks BitTorrent default port.
        void blockPort(uint16_t port);
        void unblockPort(uint16_t port);

        bool isPortBlocked(uint16_t port) const;

        // Combined check — called by FP thread for every packet
        //
        // Checks all four rule categories in priority order:
        //   IP → Port → App → Domain
        //
        // Returns BlockReason describing WHY the packet was blocked,
        // or std::nullopt if no rule matched (packet should be forwarded).
        //
        // The BlockReason lets the engine log exactly which rule triggered.
        struct BlockReason
        {
            enum Type
            {
                IP_RULE,
                PORT_RULE,
                APP_RULE,
                DOMAIN_RULE
            } type;

            std::string detail; // e.g. "192.168.1.50" or "YouTube" or "tiktok.com"
        };

        std::optional<BlockReason> shouldBlock(uint32_t src_ip,
                                               uint16_t dst_port,
                                               AppType app,
                                               const std::string &domain) const;

        // Rule Persistence
        //
        // File format (plain text, one rule per line):
        //   [BLOCKED_IPS]
        //   192.168.1.50
        //   10.0.0.5
        //
        //   [BLOCKED_APPS]
        //   YouTube
        //   TikTok
        //
        //   [BLOCKED_DOMAINS]
        //   *.facebook.com
        //   ads.google.com
        //
        //   [BLOCKED_PORTS]
        //   6881
        bool saveRules(const std::string &filename) const;
        bool loadRules(const std::string &filename);

        // Remove all rules from all categories
        void clearAll();

        // Statistics
        struct RuleStats
        {
            size_t blocked_ips;
            size_t blocked_apps;
            size_t blocked_domains;
            size_t blocked_ports;
        };

        RuleStats getStats() const;

    private:
        // Storage — one container per rule category, each with its own mutex
        //
        // Using separate mutexes means:
        //   - FP threads checking IP rules don't block threads checking app rules
        //   - Maximum read parallelism across categories

        mutable std::shared_mutex ip_mutex_;
        std::unordered_set<uint32_t> blocked_ips_;

        mutable std::shared_mutex app_mutex_;
        std::unordered_set<AppType> blocked_apps_;

        mutable std::shared_mutex domain_mutex_;
        std::unordered_set<std::string> blocked_domains_; // exact matches
        std::vector<std::string> domain_patterns_;        // wildcard patterns

        mutable std::shared_mutex port_mutex_;
        std::unordered_set<uint16_t> blocked_ports_;

        // Helper functions
        // Convert "192.168.1.50" → uint32_t (network byte order)
        static uint32_t parseIP(const std::string &ip);

        // Convert uint32_t → "192.168.1.50"
        static std::string ipToString(uint32_t ip);

        // Check if 'domain' matches a wildcard pattern like "*.facebook.com"
        // Pattern "*.facebook.com" matches:
        //   "www.facebook.com"    ✓
        //   "cdn.facebook.com"    ✓
        //   "facebook.com"        ✓  (bare domain also matches)
        //   "notfacebook.com"     ✗
        static bool domainMatchesPattern(const std::string &domain,
                                         const std::string &pattern);
    };

}

#endif