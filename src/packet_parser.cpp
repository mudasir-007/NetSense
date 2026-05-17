#include "packet_parser.h"
#include "platform.h"
#include <sstream>
#include <iomanip>
#include <cstring>

// we define short macros so the coee below looks like standard C
#define ntohs(x) PortableNet::netToHost16(x);
#define ntohl(x) PortableNet::netToHost32(x);

namespace PacketAnalyzer
{
    /*
        PacketParser::parse()

        this is the main entry point. It drives the parsing pipeline:
            raw bytes -> Ethernet -> IPV4 -> TCP or UDP -> payload

        the 'offset' variable tdacks where are in the byte buuffer
        each sub-parser reads its header at 'offset' then advances it.

    */
    bool PacketParser::parse(const RawPacket &raw, ParsedPacket &parsed)
    {
        // Reset the output struct to a clean state
        parsed = ParsedPacket();
        parsed.timestamp_sec = raw.header.ts_sec;
        parsed.timestamp_usec = raw.header.ts_usec;

        const uint8_t *data = raw.data.data();
        size_t len = raw.data.size();
        size_t offset = 0;

        // Step 1: parse the ethernet header (always first => we're on ethernet)
        if (!parseEthernet(data, len, parsed, offset))
        {
            return false;
        }

        // // Step 2: parse IP layer (only if EtherType says IPv4)
        if (parsed.ether_type == EtherType::IPv4)
        {
            if (!parseIPv4(data, len, parsed, offset))
            {
                return false;
            }

            // Step 3: parse transport layer based on IP protocol field
            if (parsed.protocol == Protocol::TCP)
            {
                if (!parseTCP(data, len, parsed, offset))
                {
                    return false;
                }
            }
            else if (parsed.protocol == Protocol::UDP)
            {
                if (!parseUDP(data, len, parsed, offset))
                {
                    return false;
                }
            }
            // TCMP and others: we dont parse further, but thats fine
        }

        // whatever remains after the headers is the payload
        if (offset < len)
        {
            parsed.payload_length = len - offset;
            parsed.payload_data = data + offset;
        }
        else
        {
            parsed.payload_length - 0;
            parsed.payload_data = nullptr;
        }
        return true;
    }

    /*
        parseEthernet()

        Ethernet header layout (always exactly 14 bytes)

        Byte 0-5: Destination MAC address
        Byte 6-11: Source MAC address
        Byte 12-13: EtherType (tells us what comes next)
             0x0800 = IPv4
             0x0806 = ARP
             0x86DD = IPv6

        after this function , offset => 14
    */
    bool PacketParser::parseEthernet(const uint8_t *data, size_t len,
                                     ParsedPacket &parsed, size_t &offset)
    {
        constexpr size_t ETH_LEN = 14;

        if (len < ETH_LEN)
        {
            return false; // packet too short to contain Ethernet header
        }

        // bytes 0-5: destination MAC
        parsed.dest_mac = macToString(data + 0);

        // bytes 6-11: source MAC
        parsed.src_mac = macToString(data + 6);

        // bytes 12-13: EtherType — stored big-endian, so we swap
        // We use reinterpret_cast to read 2 bytes at once as a uint16_t
        parsed.ether_type = ntohs(*reinterpret_cast<const uint16_t *>(data + 12));

        offset = ETH_LEN; // advance past Ethernet header
        return true;
    }

    /*
        parseIPv4()

        IPv4 header layout (minimum 20 bytes):

        Byte 0:     Version (top 4 bits) + IHL (bottom 4 bits)
                    IHL = "Internet Header Length" in 32-bit words
                    IHL=5 means 5*4=20 bytes (minimum, no options)
                    IHL=6 means 6*4=24 bytes (4 bytes of options)

        Byte 8:     TTL  — decremented at each router; packet dies at 0
        Byte 9:     Protocol — 6=TCP, 17=UDP, 1=ICMP
        Byte 12-15: Source IP
        Byte 16-19: Destination IP

        After this function, offset has advanced past the IP header
        (which may be more than 20 bytes if options are present).
    */
    bool PacketParser::parseIPv4(const uint8_t *data, size_t len,
                                 ParsedPacket &parsed, size_t &offset)
    {
        constexpr size_t MIN_IP_LEN = 20;

        // Make sure there are at least 20 bytes after current offset
        if (len < offset + MIN_IP_LEN)
        {
            return false;
        }

        const uint8_t *ip = data + offset; // pointer to start of IP header

        // Byte 0: version (upper 4 bits) and IHL (lower 4 bits)
        uint8_t version_ihl = ip[0];
        parsed.ip_version = (version_ihl >> 4) & 0x0F; // shift right 4, keep lower 4
        uint8_t ihl = (version_ihl >> 0) & 0x0F;       // just keep lower 4 bits
        size_t ip_hdr_len = ihl * 4;                   // convert words to bytes

        // Reject non-IPv4 or unreasonably short headers
        if (parsed.ip_version != 4)
            return false;
        if (ip_hdr_len < MIN_IP_LEN)
            return false;
        if (len < offset + ip_hdr_len)
            return false;

        // Byte 8: TTL
        parsed.ttl = ip[8];

        // Byte 9: Protocol (what transport layer follows)
        parsed.protocol = ip[9];

        // Bytes 12-15: Source IP (4 bytes, big-endian)
        // We read it as a uint32_t using memcpy (safe — avoids alignment issues)
        uint32_t src_ip_raw = 0;
        std::memcpy(&src_ip_raw, ip + 12, 4);
        parsed.src_ip = ipToString(src_ip_raw); // stored in network order

        // Bytes 16-19: Destination IP
        uint32_t dst_ip_raw = 0;
        std::memcpy(&dst_ip_raw, ip + 16, 4);
        parsed.dest_ip = ipToString(dst_ip_raw);

        parsed.has_ip = true;
        offset += ip_hdr_len; // advance past IP header (including any options)
        return true;
    }
    /*
         parseTCP()

         TCP header layout (minimum 20 bytes):

           Byte 0-1:   Source port
           Byte 2-3:   Destination port
           Byte 4-7:   Sequence number
           Byte 8-11:  Acknowledgment number
           Byte 12:    Data offset (upper 4 bits) — header length in 32-bit words
           Byte 13:    Flags: URG ACK PSH RST SYN FIN
           Byte 14-15: Window size
           Byte 16-17: Checksum
           Byte 18-19: Urgent pointer
           Byte 20+:   Options (if data_offset > 5)

         After this function, offset points at the TCP payload.

     */
    bool PacketParser::parseTCP(const uint8_t *data, size_t len, ParsedPacket &parsed, size_t &offset)
    {
        constexpr size_t MIN_TCP_LEN = 20;

        if (len < offset + MIN_TCP_LEN)
        {
            return false;
        }

        const uint8_t *tcp = data + offset; // pointer to the start of TCP
                                            // Bytes 0-1: source port — stored big-endian, swap to host order
        parsed.src_port = ntohs(*reinterpret_cast<const uint16_t *>(tcp + 0));

        // Bytes 2-3: destination port
        parsed.dest_port = ntohs(*reinterpret_cast<const uint16_t *>(tcp + 2));

        // Bytes 4-7: sequence number
        parsed.seq_number = ntohl(*reinterpret_cast<const uint32_t *>(tcp + 4));

        // Bytes 8-11: acknowledgment number
        parsed.ack_number = ntohl(*reinterpret_cast<const uint32_t *>(tcp + 8));

        // Byte 12: data offset in upper 4 bits
        // This tells us how long the TCP header is (including options)
        uint8_t data_offset = (tcp[12] >> 4) & 0x0F; // upper 4 bits
        size_t tcp_hdr_len = data_offset * 4;        // convert words to bytes

        // Byte 13: flags bitmask
        // Each bit is a flag: 0x02=SYN, 0x10=ACK, 0x01=FIN, 0x04=RST, etc.
        parsed.tcp_flags = tcp[13];

        // Validate TCP header length
        if (tcp_hdr_len < MIN_TCP_LEN)
            return false;
        if (len < offset + tcp_hdr_len)
            return false;

        parsed.has_tcp = true;
        offset += tcp_hdr_len; // advance past TCP header (including any options)
        return true;
    }
    /*

        parseUDP()

        UDP header layout (always exactly 8 bytes — no options):

        Byte 0-1: Source port
        Byte 2-3: Destination port
        Byte 4-5: Length (header + data)
        Byte 6-7: Checksum

        After this function, offset points at the UDP payload.


    */
    bool PacketParser::parseUDP(const uint8_t *data, size_t len,
                                ParsedPacket &parsed, size_t &offset)
    {
        constexpr size_t UDP_LEN = 8;

        if (len < offset + UDP_LEN)
        {
            return false;
        }

        const uint8_t *udp = data + offset; // pointer to start of UDP header

        // Bytes 0-1: source port
        parsed.src_port = ntohs(*reinterpret_cast<const uint16_t *>(udp + 0));

        // Bytes 2-3: destination port
        parsed.dest_port = ntohs(*reinterpret_cast<const uint16_t *>(udp + 2));

        // UDP has no sequence numbers, flags, or options — just ports and length

        parsed.has_udp = true;
        offset += UDP_LEN; // UDP header is always exactly 8 bytes
        return true;
    }
    // UTILITY FUNCTIONS => to convert raw bytes into human - readable strings

    // Convert 6 raw MAC bytes to "aa:bb:cc:dd:ee:ff" format
    std::string PacketParser::macToString(const uint8_t *mac)
    {
        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < 6; i++)
        {
            if (i > 0)
                ss << ":";
            ss << std::setw(2) << static_cast<int>(mac[i]);
        }
        return ss.str();
    }

    // Convert a 32-bit IP (in network byte order) to "192.168.1.1" format
    // Note: IP bytes arrive in network order (big-endian).
    // On a little-endian machine, byte 0 of the uint32 is the FIRST octet.
    std::string PacketParser::ipToString(uint32_t ip)
    {
        std::ostringstream ss;
        // Extract each byte using shifts
        // ip stored as network order: byte0=first octet, byte3=last octet
        ss << ((ip >> 0) & 0xFF) << "."  // first octet (e.g. 192)
           << ((ip >> 8) & 0xFF) << "."  // second octet (e.g. 168)
           << ((ip >> 16) & 0xFF) << "." // third octet (e.g. 1)
           << ((ip >> 24) & 0xFF);       // fourth octet (e.g. 100)
        return ss.str();
    }

    // Convert protocol number to name
    std::string PacketParser::protocolToString(uint8_t protocol)
    {
        switch (protocol)
        {
        case Protocol::ICMP:
            return "ICMP";
        case Protocol::TCP:
            return "TCP";
        case Protocol::UDP:
            return "UDP";
        default:
            return "Unknown(" + std::to_string(protocol) + ")";
        }
    }

    // ConvertTCP flags bitmask to readbale string like "SYN ACK"
    std::string PacketParser::tcpFlagsToString(uint8_t flags)
    {
        std::string result;
        // Check each bit individually using the named constants from the header
        if (flags & TCPFlags::SYN)
            result += "SYN ";
        if (flags & TCPFlags::ACK)
            result += "ACK ";
        if (flags & TCPFlags::FIN)
            result += "FIN ";
        if (flags & TCPFlags::RST)
            result += "RST ";
        if (flags & TCPFlags::PSH)
            result += "PSH ";
        if (flags & TCPFlags::URG)
            result += "URG ";

        if (!result.empty())
            result.pop_back(); // remove trailing space
        return result.empty() ? "none" : result;
    }
}