#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <cstdint>
#include <string>
#include <array>
#include "pcap_reader.h"

/*
    this header file defines the structures and parser for peeling apart a raw network packet


    Parsing order:
        rawpacket (just bytes)

        parseEthernet() => fills the src_mac, dest_mac, ether_type

        parseipV4() => fills src_ip, dest_ip, protocol, ttl

        parseTCP() => fills src_port, set_port, flags, seq
        or parseUDP() => fills src_-port, dest_port

        parsedPacket() => (human readable fields and a pointer to the payload)

*/

namespace PacketAnalyzer
{
    /*
        raw header structs => these map directlyy into bytes in the memory

        we use these as overlays to read thr fields from the packet buffer

        all multi-byte fields arrive big endian format
    */

    // Ethernet header => exactly 14 bytes
    struct EthernetHeader
    {
        std::array<uint8_t, 6> dest_mac; // bytes 0-5 => destination MAC
        std::array<uint8_t, 6> dest_src; // bytes 6-11 => source MAC
        uint16_t ether_type;             // bytes 12-13: 0x0800=IPv4, 0x86DD=IPv6
    };

    // IPV4 heade => minimum 20 bytes and can go tup 60 with options
    struct IPV4Header
    {
        uint8_t version_ihl; // byte 0 => upper 4 bits = version
        // lower 4 bits =>> header length 9n the 32 bit words
        uint8_t tos;             // byte 1 => type os services (usually ignored)
        uint16_t total_length;   // bytes 2-3 : total packet length
        uint16_t identification; // bytes 4-5 => fragment ID
        uint16_t flags_fragment; // bytes 6-7 : flags => flags fragment
        uint8_t ttl;             // byte 8: time to live (hops remaining)
        uint8_t protocol;        // byte 9: 6 => TCP, 17 => UDP, 1 => TCMP
        uint16_t checksum;       // byte 10-11  => header checksum
        uint32_t src_ip;         // byte 12-15 => source IP address
        uint32_t dest_ip;        // bytes 16-19 => destination IP address
        // optional: bytes 20+ (if iihl > 5)
    };

    // TCP header — minimum 20 bytes (can be up to 60 with options)
    struct TCPHeader
    {
        uint16_t src_port;       // bytes 0-1:   source port
        uint16_t dest_port;      // bytes 2-3:   destination port
        uint32_t seq_number;     // bytes 4-7:   sequence number
        uint32_t ack_number;     // bytes 8-11:  acknowledgment number
        uint8_t data_offset;     // byte 12:     upper 4 bits = header length in 32-bit words
        uint8_t flags;           // byte 13:     SYN, ACK, FIN, RST, PSH, URG
        uint16_t window;         // bytes 14-15: receive window size
        uint16_t checksum;       // bytes 16-17: checksum
        uint16_t urgent_pointer; // bytes 18-19: urgent pointer (rarely used)
        // optional: bytes 20+  (if data_offset > 5)
    };

    // UDP header — always exactly 8 bytes, no options
    struct UDPHeader
    {
        uint16_t src_port;  // bytes 0-1: source port
        uint16_t dest_port; // bytes 2-3: destination port
        uint16_t length;    // bytes 4-5: length of UDP header + data
        uint16_t checksum;  // bytes 6-7: checksum
    };

    /*

        ParsedPacket => the result of parsing a raw packet.
        contains human readable strings and convenient booleans.
        payload_data points INTOO the original RawPacket's data buffer
            => so the RawPacket must stay alive as long as you can use the payload_data
    */
    struct ParsedPacket
    {
        // --- Timestamps (copied from pcap packet header) ---
        uint32_t timestamp_sec = 0;
        uint32_t timestamp_usec = 0;

        // --- Ethernet layer ---
        std::string src_mac;
        std::string dest_mac;
        uint16_t ether_type = 0; // 0x0800=IPv4, 0x86DD=IPv6, 0x0806=ARP

        // --- IP layer ---
        bool has_ip = false;
        uint8_t ip_version = 0;
        std::string src_ip;
        std::string dest_ip;
        uint8_t protocol = 0; // 6=TCP, 17=UDP, 1=ICMP
        uint8_t ttl = 0;

        // --- Transport layer ---
        bool has_tcp = false;
        bool has_udp = false;
        uint16_t src_port = 0;
        uint16_t dest_port = 0;

        // --- TCP-specific ---
        uint8_t tcp_flags = 0; // bitmask: SYN=0x02, ACK=0x10, FIN=0x01, etc.
        uint32_t seq_number = 0;
        uint32_t ack_number = 0;

        // --- Payload (the data after all headers) ---
        size_t payload_length = 0;
        const uint8_t *payload_data = nullptr; // points into original RawPacket buffer
    };

    /*
        PacletParser => static methods only, no state
        call parse() with a RawPacket andd it fills in a ParsedPacket

    */

    class PacketParser
    {
    public:
        // main entry point - parse raw bytes into the structured fields
        // returns false if the packet is too short or malformed
        static bool parse(const RawPacket &raw, ParsedPacket &parsed);

        // Utility: convert raw bytes to human-readable strings
        static std::string macToString(const uint8_t *mac);    // e.g. "aa:bb:cc:dd:ee:ff"
        static std::string ipToString(uint32_t ip);            // e.g. "192.168.1.1"
        static std::string protocolToString(uint8_t protocol); // e.g. "TCP"
        static std::string tcpFlagsToString(uint8_t flags);    // e.g. "SYN ACK"

    private:
        // Each sub-parser advances 'offset' past the header it parsed.
        // Returns false if there aren't enough bytes remaining.
        static bool parseEthernet(const uint8_t *data, size_t len,
                                  ParsedPacket &parsed, size_t &offset);
        static bool parseIPv4(const uint8_t *data, size_t len,
                              ParsedPacket &parsed, size_t &offset);
        static bool parseTCP(const uint8_t *data, size_t len,
                             ParsedPacket &parsed, size_t &offset);
        static bool parseUDP(const uint8_t *data, size_t len,
                             ParsedPacket &parsed, size_t &offset);
    };

    // Named Constants => we will use these instead of magic numbers in our code
    namespace TCPFlags
    {
        constexpr uint8_t FIN = 0x01; // connection finish
        constexpr uint8_t SYN = 0x02; // synchronize / connection open
        constexpr uint8_t RST = 0x04; // reset / connection abort
        constexpr uint8_t PSH = 0x08; // push data immediately
        constexpr uint8_t ACK = 0x10; // acknowledgment field is valid
        constexpr uint8_t URG = 0x20; // urgent pointer is valid
    }

    namespace Protocol
    {
        constexpr uint8_t ICMP = 1;
        constexpr uint8_t TCP = 6;
        constexpr uint8_t UDP = 17;
    }

    namespace EtherType
    {
        constexpr uint16_t IPv4 = 0x0800;
        constexpr uint16_t ARP = 0x0806;
        constexpr uint16_t IPv6 = 0x86DD;
    }
}

#endif