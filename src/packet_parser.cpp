#include "packet_parser.h"
#include "platform.h"
#include <sstream>
#include <iomanip>
#include <cstring>

// *short macros to convert network byte order to host byte order
#define ntohs(x) PortableNet::netToHost16(x)
#define ntohl(x) PortableNet::netToHost32(x)

namespace PacketAnalyzer
{
    /*
     * PacketParser::parse()
     *
     * Main entry point for the parsing pipeline.
     * Drives the packet through each layer in order:
     *
     *   raw bytes -> Ethernet -> IPv4 -> TCP or UDP -> payload
     *
     * 'offset' tracks our current position in the byte buffer.
     * Each sub-parser reads its header at 'offset' and advances it forward.
     *
     * Returns true if parsing succeeded, false if packet is malformed.
     *
     * Raw bytes in data[]
     *        |
     *        v
     * offset = 0
     *        |
     *        v
     * ┌─────────────────────┐
     * │   parseEthernet()   │  reads 14 bytes
     * │   offset → 14       │  extracts: src_mac, dst_mac, ether_type
     * └─────────────────────┘
     *        |
     *        v
     * ┌─────────────────────┐
     * │    parseIPv4()      │  reads 20+ bytes (IHL × 4)
     * │   offset → 34+      │  extracts: src_ip, dst_ip, protocol, ttl
     * └─────────────────────┘
     *        |
     *        ├──── protocol == TCP?
     *        |            |
     *        |            v
     *        |     ┌─────────────────────┐
     *        |     │    parseTCP()       │  reads 20+ bytes
     *        |     │   offset → payload  │  extracts: ports, seq, flags
     *        |     └─────────────────────┘
     *        |
     *        └──── protocol == UDP?
     *                     |
     *                     v
     *              ┌─────────────────────┐
     *              │    parseUDP()       │  reads exactly 8 bytes
     *              │   offset → payload  │  extracts: ports
     *              └─────────────────────┘
     *                     |
     *                     v
     *              remaining bytes = payload
     *              payload_data = &data[offset]
     *              payload_length = len - offset
     */
    bool PacketParser::parse(const RawPacket &raw, ParsedPacket &parsed)
    {
        // reset output struct to a clean state before filling it
        parsed = ParsedPacket();
        parsed.timestamp_sec  = raw.header.ts_sec;
        parsed.timestamp_usec = raw.header.ts_usec;

        const uint8_t *data = raw.data.data();
        size_t len    = raw.data.size();
        size_t offset = 0;

        // Step 1: Ethernet header is always the first layer
        if (!parseEthernet(data, len, parsed, offset))
            return false;

        // Step 2: only continue if EtherType is IPv4
        if (parsed.ether_type == EtherType::IPv4)
        {
            if (!parseIPv4(data, len, parsed, offset))
                return false;

            // Step 3: transport layer depends on the IP protocol field
            if (parsed.protocol == Protocol::TCP)
            {
                if (!parseTCP(data, len, parsed, offset))
                    return false;
            }
            else if (parsed.protocol == Protocol::UDP)
            {
                if (!parseUDP(data, len, parsed, offset))
                    return false;
            }
            // ICMP and other protocols: we stop here, that is fine
        }

        // everything remaining after the headers is the payload
        if (offset < len)
        {
            parsed.payload_length = len - offset;
            parsed.payload_data   = data + offset;
        }
        else
        {
            parsed.payload_length = 0;
            parsed.payload_data   = nullptr;
        }

        return true;
    }

    /*
     * parseEthernet()
     *
     * Ethernet header layout (always exactly 14 bytes):
     *
     *   Byte  0-5  : Destination MAC address
     *   Byte  6-11 : Source MAC address
     *   Byte 12-13 : EtherType — tells us what layer comes next
     *                  0x0800 = IPv4
     *                  0x0806 = ARP
     *                  0x86DD = IPv6
     *
     * After this function, offset = 14.
     */
    bool PacketParser::parseEthernet(const uint8_t *data, size_t len,
                                     ParsedPacket &parsed, size_t &offset)
    {
        constexpr size_t ETH_LEN = 14;

        if (len < ETH_LEN)
            return false; // packet too short to hold an Ethernet header

        // bytes 0-5: destination MAC
        parsed.dest_mac = macToString(data + 0);

        // bytes 6-11: source MAC
        parsed.src_mac = macToString(data + 6);

        // bytes 12-13: EtherType stored big-endian — swap to host order
        parsed.ether_type = ntohs(*reinterpret_cast<const uint16_t *>(data + 12));

        offset = ETH_LEN; // advance past the Ethernet header
        return true;
    }

    /*
     * parseIPv4()
     *
     * IPv4 header layout (minimum 20 bytes):
     *
     *   Byte  0    : Version (top 4 bits) + IHL (bottom 4 bits)
     *                IHL = Internet Header Length in 32-bit words
     *                IHL=5 → 5×4=20 bytes (no options)
     *                IHL=6 → 6×4=24 bytes (4 bytes of options)
     *   Byte  8    : TTL — decremented at each router; packet dies at 0
     *   Byte  9    : Protocol — 6=TCP, 17=UDP, 1=ICMP
     *   Byte 12-15 : Source IP address
     *   Byte 16-19 : Destination IP address
     *
     * After this function, offset has advanced past the full IP header.
     */
    bool PacketParser::parseIPv4(const uint8_t *data, size_t len,
                                 ParsedPacket &parsed, size_t &offset)
    {
        constexpr size_t MIN_IP_LEN = 20;

        if (len < offset + MIN_IP_LEN)
            return false;

        const uint8_t *ip = data + offset; // pointer to start of IP header

        // byte 0: upper 4 bits = version, lower 4 bits = IHL
        uint8_t version_ihl  = ip[0];
        parsed.ip_version    = (version_ihl >> 4) & 0x0F;
        uint8_t ihl          = (version_ihl >> 0) & 0x0F;
        size_t  ip_hdr_len   = ihl * 4; // convert 32-bit words to bytes

        if (parsed.ip_version != 4)   return false;
        if (ip_hdr_len < MIN_IP_LEN)  return false;
        if (len < offset + ip_hdr_len) return false;

        // byte 8: TTL
        parsed.ttl = ip[8];

        // byte 9: transport protocol
        parsed.protocol = ip[9];

        // bytes 12-15: source IP (big-endian — use memcpy to avoid alignment issues)
        uint32_t src_ip_raw = 0;
        std::memcpy(&src_ip_raw, ip + 12, 4);
        parsed.src_ip = ipToString(src_ip_raw);

        // bytes 16-19: destination IP
        uint32_t dst_ip_raw = 0;
        std::memcpy(&dst_ip_raw, ip + 16, 4);
        parsed.dest_ip = ipToString(dst_ip_raw);

        parsed.has_ip  = true;
        offset        += ip_hdr_len; // advance past IP header including any options
        return true;
    }

    /*
     * parseTCP()
     *
     * TCP header layout (minimum 20 bytes):
     *
     *   Byte  0-1  : Source port
     *   Byte  2-3  : Destination port
     *   Byte  4-7  : Sequence number
     *   Byte  8-11 : Acknowledgment number
     *   Byte 12    : Data offset (upper 4 bits) — header length in 32-bit words
     *   Byte 13    : Flags: URG ACK PSH RST SYN FIN
     *   Byte 14-15 : Window size
     *   Byte 16-17 : Checksum
     *   Byte 18-19 : Urgent pointer
     *   Byte 20+   : Options (present if data_offset > 5)
     *
     * After this function, offset points at the start of TCP payload.
     */
    bool PacketParser::parseTCP(const uint8_t *data, size_t len,
                                ParsedPacket &parsed, size_t &offset)
    {
        constexpr size_t MIN_TCP_LEN = 20;

        if (len < offset + MIN_TCP_LEN)
            return false;

        const uint8_t *tcp = data + offset; // pointer to start of TCP header

        // bytes 0-1: source port (big-endian — swap to host order)
        parsed.src_port = ntohs(*reinterpret_cast<const uint16_t *>(tcp + 0));

        // bytes 2-3: destination port
        parsed.dest_port = ntohs(*reinterpret_cast<const uint16_t *>(tcp + 2));

        // bytes 4-7: sequence number
        parsed.seq_number = ntohl(*reinterpret_cast<const uint32_t *>(tcp + 4));

        // bytes 8-11: acknowledgment number
        parsed.ack_number = ntohl(*reinterpret_cast<const uint32_t *>(tcp + 8));

        // byte 12: upper 4 bits = data offset (header length in 32-bit words)
        uint8_t data_offset = (tcp[12] >> 4) & 0x0F;
        size_t  tcp_hdr_len = data_offset * 4;

        // byte 13: TCP flags bitmask (SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04)
        parsed.tcp_flags = tcp[13];

        if (tcp_hdr_len < MIN_TCP_LEN)      return false;
        if (len < offset + tcp_hdr_len)     return false;

        parsed.has_tcp  = true;
        offset         += tcp_hdr_len; // advance past TCP header including options
        return true;
    }

    /*
     * parseUDP()
     *
     * UDP header layout (always exactly 8 bytes — no options):
     *
     *   Byte 0-1 : Source port
     *   Byte 2-3 : Destination port
     *   Byte 4-5 : Length (header + data)
     *   Byte 6-7 : Checksum
     *
     * After this function, offset points at the start of UDP payload.
     */
    bool PacketParser::parseUDP(const uint8_t *data, size_t len,
                                ParsedPacket &parsed, size_t &offset)
    {
        constexpr size_t UDP_LEN = 8;

        if (len < offset + UDP_LEN)
            return false;

        const uint8_t *udp = data + offset; // pointer to start of UDP header

        // bytes 0-1: source port
        parsed.src_port = ntohs(*reinterpret_cast<const uint16_t *>(udp + 0));

        // bytes 2-3: destination port
        parsed.dest_port = ntohs(*reinterpret_cast<const uint16_t *>(udp + 2));

        // UDP has no sequence numbers, flags, or variable-length options
        parsed.has_udp  = true;
        offset         += UDP_LEN; // UDP header is always exactly 8 bytes
        return true;
    }

    // -------------------------------------------------------------------------
    // UTILITY FUNCTIONS — convert raw bytes into human-readable strings
    // -------------------------------------------------------------------------

    // Convert 6 raw MAC bytes into "aa:bb:cc:dd:ee:ff" string format
    std::string PacketParser::macToString(const uint8_t *mac)
    {
        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < 6; i++)
        {
            if (i > 0) ss << ":";
            ss << std::setw(2) << static_cast<int>(mac[i]);
        }
        return ss.str();
    }

    // Convert a 32-bit IP address (network byte order) to "192.168.1.1" format
    // IP bytes arrive big-endian: byte 0 of the uint32 is the first octet
    std::string PacketParser::ipToString(uint32_t ip)
    {
        std::ostringstream ss;
        ss << ((ip >>  0) & 0xFF) << "."   // first octet  (e.g. 192)
           << ((ip >>  8) & 0xFF) << "."   // second octet (e.g. 168)
           << ((ip >> 16) & 0xFF) << "."   // third octet  (e.g. 1)
           << ((ip >> 24) & 0xFF);         // fourth octet (e.g. 1)
        return ss.str();
    }

    // Convert IP protocol number to a readable name string
    std::string PacketParser::protocolToString(uint8_t protocol)
    {
        switch (protocol)
        {
            case Protocol::ICMP: return "ICMP";
            case Protocol::TCP:  return "TCP";
            case Protocol::UDP:  return "UDP";
            default:             return "Unknown(" + std::to_string(protocol) + ")";
        }
    }

    // Convert TCP flags bitmask to a readable string like "SYN ACK"
    std::string PacketParser::tcpFlagsToString(uint8_t flags)
    {
        std::string result;
        if (flags & TCPFlags::SYN) result += "SYN ";
        if (flags & TCPFlags::ACK) result += "ACK ";
        if (flags & TCPFlags::FIN) result += "FIN ";
        if (flags & TCPFlags::RST) result += "RST ";
        if (flags & TCPFlags::PSH) result += "PSH ";
        if (flags & TCPFlags::URG) result += "URG ";

        if (!result.empty()) result.pop_back(); // remove trailing space
        return result.empty() ? "none" : result;
    }

} // namespace PacketAnalyzer