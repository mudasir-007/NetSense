#include "rule_manager.h"

#include <sstream>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <mutex>
#include <shared_mutex>

/*
     rule_manager.cpp

     All public methods follow the same locking pattern:

       Reads  → std::shared_lock  (multiple threads can hold simultaneously)
       Writes → std::unique_lock  (exclusive — blocks all readers and writers)

     The four rule categories have separate mutexes so FP threads
     checking different categories never block each other.
*/

namespace DPI
{
    /*
         Helper: parseIP

         Convert "192.168.1.50" to uint32_t stored in the same byte order
         that PacketParser produces from raw packet bytes (network order).

         We store byte 0 (192) in bits 0-7, byte 1 (168) in bits 8-15, etc.
         This matches ipToString() in types.cpp and packet_parser.cpp.
    */
    uint32_t RuleManager::parseIP(const std::string &ip)
    {
        uint32_t result = 0;
        int octet = 0;
        int shift = 0; // current byte position in bits

        for (char c : ip)
        {
            if (c == '.')
            {
                result |= (octet << shift); // pack octet into result
                shift += 8;                 // move to next byte
                octet = 0;
            }
            else if (c >= '0' && c <= '9')
            {
                octet = octet * 10 + (c - '0');
            }
        }

        result |= (octet << shift); // pack the last octet
        return result;
    }

    /*
        Helper: ipToString

        reverse of parseIP => produces "192.168.1.50" from uint32_t
    */
    std::string RuleManager::ipToString(uint32_t ip)
    {
        std::ostringstream ss;

        ss << ((ip >> 0) & 0xFF) << "."
           << ((ip >> 8) & 0xFF) << "."
           << ((ip >> 16) & 0xFF) << "."
           << ((ip >> 24) & 0xFF);

        return ss.str();
    }

    /*
         Helper: domainMatchesPattern

         Supports wildcard pattern "*.example.com":
           matches "www.example.com"   ✓
           matches "cdn.example.com"   ✓
           matches "example.com"       ✓  (bare domain)
           rejects "notexample.com"    ✗

         Both domain and pattern are converted to lowercase before comparison
         so matching is always case-insensitive.
    */

    bool RuleManager::domainMatchesPattern(const std::string &domain,
                                           const std::string &pattern)
    {
        // Only handle "*.something" patterns
        if (pattern.size() < 2 ||
            pattern[0] != '*' ||
            pattern[1] != '.')
        {
            return false;
        }

        // The suffix is everything after the '*'
        // e.g. pattern="*.facebook.com" → suffix=".facebook.com"
        std::string suffix = pattern.substr(1);

        // Check 1: does domain end with ".facebook.com"?
        // e.g. "cdn.facebook.com" ends with ".facebook.com" ✓
        if (domain.size() >= suffix.size())
        {
            std::string domain_end =
                domain.substr(domain.size() - suffix.size());

            if (domain_end == suffix)
                return true;
        }

        // Check 2: does domain equal the bare domain without the dot?
        // e.g. pattern "*.facebook.com" → bare = "facebook.com"
        // domain "facebook.com" should match
        std::string bare = pattern.substr(2); // skip "*."

        if (domain == bare)
            return true;

        return false;
    }

    // IP Blocking
    void RuleManager::blockIP(const std::string &ip)
    {
        blockIP(parseIP(ip));
    }

    void RuleManager::blockIP(uint32_t ip)
    {
        std::unique_lock<std::shared_mutex> lock(ip_mutex_);

        blocked_ips_.insert(ip);

        std::cout << "[RuleManager] Blocked IP: "
                  << ipToString(ip) << "\n";
    }

    void RuleManager::unblockIP(const std::string &ip)
    {
        unblockIP(parseIP(ip));
    }

    void RuleManager::unblockIP(uint32_t ip)
    {
        std::unique_lock<std::shared_mutex> lock(ip_mutex_);

        blocked_ips_.erase(ip);

        std::cout << "[RuleManager] Unblocked IP: "
                  << ipToString(ip) << "\n";
    }

    // shared_lock: multiple FP threads can call isIPBlocked() simultaneously
    bool RuleManager::isIPBlocked(uint32_t ip) const
    {
        std::shared_lock<std::shared_mutex> lock(ip_mutex_);
        return blocked_ips_.count(ip) > 0;
    }

    std::vector<std::string> RuleManager::getBlockedIPs() const
    {
        std::shared_lock<std::shared_mutex> lock(ip_mutex_);

        std::vector<std::string> result;
        result.reserve(blocked_ips_.size());

        for (uint32_t ip : blocked_ips_)
        {
            result.push_back(ipToString(ip));
        }

        return result;
    }

    // Application Blocking

    void RuleManager::blockApp(AppType app)
    {
        std::unique_lock<std::shared_mutex> lock(app_mutex_);

        blocked_apps_.insert(app);

        std::cout << "[RuleManager] Blocked app: "
                  << appTypeToString(app) << "\n";
    }
    void RuleManager::unblockApp(AppType app)
    {
        std::unique_lock<std::shared_mutex> lock(app_mutex_);

        blocked_apps_.erase(app);

        std::cout << "[RuleManager] Unblocked app: "
                  << appTypeToString(app) << "\n";
    }

    bool RuleManager::isAppBlocked(AppType app) const
    {
        std::shared_lock<std::shared_mutex> lock(app_mutex_);
        return blocked_apps_.count(app) > 0;
    }

    std::vector<AppType> RuleManager::getBlockedApps() const
    {
        std::shared_lock<std::shared_mutex> lock(app_mutex_);

        return std::vector<AppType>(blocked_apps_.begin(),
                                    blocked_apps_.end());
    }

    // Domain Blocking

    void RuleManager::blockDomain(const std::string &domain)
    {
        std::unique_lock<std::shared_mutex> lock(domain_mutex_);

        // Wildcard patterns go in the vector, exact domains in the set
        if (domain.size() >= 2 &&
            domain[0] == '*' &&
            domain[1] == '.')
        {
            domain_patterns_.push_back(domain);
        }
        else
        {
            blocked_domains_.insert(domain);
        }

        std::cout << "[RuleManager] Blocked domain: "
                  << domain << "\n";
    }

    void RuleManager::unblockDomain(const std::string &domain)
    {
        std::unique_lock<std::shared_mutex> lock(domain_mutex_);

        if (domain.size() >= 2 &&
            domain[0] == '*' &&
            domain[1] == '.')
        {
            // Remove from patterns vector
            auto it = std::find(domain_patterns_.begin(),
                                domain_patterns_.end(),
                                domain);

            if (it != domain_patterns_.end())
            {
                domain_patterns_.erase(it);
            }
        }
        else
        {
            blocked_domains_.erase(domain);
        }
    }

    bool RuleManager::isDomainBlocked(const std::string &domain) const
    {
        std::shared_lock<std::shared_mutex> lock(domain_mutex_);

        // Lowercase the incoming domain for case-insensitive comparison
        std::string lower = domain;

        std::transform(lower.begin(),
                       lower.end(),
                       lower.begin(),
                       [](unsigned char c)
                       { return std::tolower(c); });

        // Fast path: exact match in hash set
        if (blocked_domains_.count(lower) > 0)
            return true;

        // Slow path: check wildcard patterns one by one
        for (const auto &pattern : domain_patterns_)
        {
            std::string lower_pattern = pattern;

            std::transform(lower_pattern.begin(),
                           lower_pattern.end(),
                           lower_pattern.begin(),
                           [](unsigned char c)
                           { return std::tolower(c); });

            if (domainMatchesPattern(lower, lower_pattern))
                return true;
        }

        return false;
    }

    std::vector<std::string> RuleManager::getBlockedDomains() const
    {
        std::shared_lock<std::shared_mutex> lock(domain_mutex_);

        std::vector<std::string> result(blocked_domains_.begin(),
                                        blocked_domains_.end());

        // Append wildcard patterns too
        result.insert(result.end(),
                      domain_patterns_.begin(),
                      domain_patterns_.end());

        return result;
    }

    // Port Blocking

    void RuleManager::blockPort(uint16_t port)
    {
        std::unique_lock<std::shared_mutex> lock(port_mutex_);

        blocked_ports_.insert(port);

        std::cout << "[RuleManager] Blocked port: "
                  << port << "\n";
    }

    void RuleManager::unblockPort(uint16_t port)
    {
        std::unique_lock<std::shared_mutex> lock(port_mutex_);
        blocked_ports_.erase(port);
    }

    bool RuleManager::isPortBlocked(uint16_t port) const
    {
        std::shared_lock<std::shared_mutex> lock(port_mutex_);
        return blocked_ports_.count(port) > 0;
    }

    // shouldBlock() — the combined check called by every FP thread
    //
    // Checks all four categories in priority order.
    // Returns on the FIRST match so we don't do unnecessary work.
    //
    // Priority order rationale:
    //   IP   first — most specific, fastest check, strongest signal
    //   Port second — catches protocol-level blocks before app detection
    //   App  third  — requires SNI extraction to have succeeded first
    //   Domain last — most expensive (vector scan for wildcards)

    std::optional<RuleManager::BlockReason>
    RuleManager::shouldBlock(uint32_t src_ip,
                             uint16_t dst_port,
                             AppType app,
                             const std::string &domain) const
    {
        // Check 1: source IP
        if (isIPBlocked(src_ip))
        {
            return BlockReason{
                BlockReason::IP_RULE,
                ipToString(src_ip)};
        }

        // Check 2: destination port
        if (isPortBlocked(dst_port))
        {
            return BlockReason{
                BlockReason::PORT_RULE,
                std::to_string(dst_port)};
        }

        // Check 3: application type
        if (isAppBlocked(app))
        {
            return BlockReason{
                BlockReason::APP_RULE,
                appTypeToString(app)};
        }

        // Check 4: domain pattern
        if (!domain.empty() &&
            isDomainBlocked(domain))
        {
            return BlockReason{
                BlockReason::DOMAIN_RULE,
                domain};
        }

        return std::nullopt; // no rule matched — forward the packet
    }

    // Rule Persistence - saveRules()

    bool RuleManager::saveRules(const std::string &filename) const
    {
        std::ofstream file(filename);

        if (!file.is_open())
        {
            std::cerr << "[RuleManager] Cannot save rules to: "
                      << filename << "\n";

            return false;
        }

        file << "[BLOCKED_IPS]\n";

        for (const auto &ip : getBlockedIPs())
        {
            file << ip << "\n";
        }

        file << "\n[BLOCKED_APPS]\n";

        for (AppType app : getBlockedApps())
        {
            file << appTypeToString(app) << "\n";
        }

        file << "\n[BLOCKED_DOMAINS]\n";

        for (const auto &domain : getBlockedDomains())
        {
            file << domain << "\n";
        }

        {
            std::shared_lock<std::shared_mutex> lock(port_mutex_);

            file << "\n[BLOCKED_PORTS]\n";

            for (uint16_t port : blocked_ports_)
            {
                file << port << "\n";
            }
        }

        std::cout << "[RuleManager] Rules saved to: "
                  << filename << "\n";

        return true;
    }

    // Rule Persistence — loadRules()
    //
    // Reads the section-based file format written by saveRules().
    // Lines starting with '[' are section headers.
    // All other non-empty lines are rule values for the current section.

    bool RuleManager::loadRules(const std::string &filename)
    {
        std::ifstream file(filename);

        if (!file.is_open())
        {
            std::cerr << "[RuleManager] Cannot load rules from: "
                      << filename << "\n";

            return false;
        }

        std::string line;
        std::string current_section;

        while (std::getline(file, line))
        {
            // Skip empty lines
            if (line.empty())
                continue;

            // Section header
            if (line[0] == '[')
            {
                current_section = line;
                continue;
            }

            // Process rule based on current section
            if (current_section == "[BLOCKED_IPS]")
            {
                blockIP(line);
            }
            else if (current_section == "[BLOCKED_APPS]")
            {
                // Convert string back to AppType by searching all values
                for (int i = 0;
                     i < static_cast<int>(AppType::APP_COUNT);
                     i++)
                {
                    AppType app = static_cast<AppType>(i);

                    if (appTypeToString(app) == line)
                    {
                        blockApp(app);
                        break;
                    }
                }
            }
            else if (current_section == "[BLOCKED_DOMAINS]")
            {
                blockDomain(line);
            }
            else if (current_section == "[BLOCKED_PORTS]")
            {
                blockPort(static_cast<uint16_t>(std::stoi(line)));
            }
        }

        std::cout << "[RuleManager] Rules loaded from: "
                  << filename << "\n";

        return true;
    }

    // clearAll() — remove every rule from every category

    void RuleManager::clearAll()
    {
        {
            std::unique_lock<std::shared_mutex> lock(ip_mutex_);
            blocked_ips_.clear();
        }

        {
            std::unique_lock<std::shared_mutex> lock(app_mutex_);
            blocked_apps_.clear();
        }

        {
            std::unique_lock<std::shared_mutex> lock(domain_mutex_);
            blocked_domains_.clear();
            domain_patterns_.clear();
        }

        {
            std::unique_lock<std::shared_mutex> lock(port_mutex_);
            blocked_ports_.clear();
        }

        std::cout << "[RuleManager] All rules cleared\n";
    }

    // getStats()

    RuleManager::RuleStats RuleManager::getStats() const
    {
        RuleStats stats;

        {
            std::shared_lock<std::shared_mutex> lock(ip_mutex_);
            stats.blocked_ips = blocked_ips_.size();
        }

        {
            std::shared_lock<std::shared_mutex> lock(app_mutex_);
            stats.blocked_apps = blocked_apps_.size();
        }

        {
            std::shared_lock<std::shared_mutex> lock(domain_mutex_);

            stats.blocked_domains =
                blocked_domains_.size() +
                domain_patterns_.size();
        }

        {
            std::shared_lock<std::shared_mutex> lock(port_mutex_);
            stats.blocked_ports = blocked_ports_.size();
        }

        return stats;
    }

}