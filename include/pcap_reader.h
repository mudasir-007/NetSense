/*

a .pcap file is like a recording of network trafffic - wireshark saves it. The format is simple:


┌─────────────────────────┐
│  Global Header (24 B)   │  ← "this is a pcap file, ethernet, version 2.4"
├─────────────────────────┤
│  Packet Header (16 B)   │  ← timestamp, how many bytes follow
│  Packet Data  (N bytes) │  ← the actual network bytes
├─────────────────────────┤
│  Packet Header (16 B)   │
│  Packet Data  (N bytes) │
├─────────────────────────┤
│  ... repeat ...         │
└─────────────────────────┘


PcapReader is just a wrapper around fread() - open the file, read 24 bytes header, then loop reading 16-byte packets followed by the packet data

*/

#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <cstdint>
#include <string>
#include <vector>
#include <fstream>

namespace PacketAnalyzer
{
    // the 24 byte global header at the start of every .pcap file
    struct PcapGlobalHeader
    {
        uint32_t magic_number;  // 0xa1b2c3d4 identifies this as pcap

        /*
            The magic_number tells you byte order.
                If magic number equals:
                    0xa1b2c3d4 → same endianness as machine
                    0xd4c3b2a1 → opposite endianness
        */
        uint16_t version_major; // usually 2
        uint16_t version_minor; // usually 4
        int32_t thiszone;       // timezone offset, almost always 0
        uint32_t sigfigs;       // timestamp precision, almost always 0
        uint32_t snaplen;       // max bytes captured per packet (e.g. 65535)
        uint32_t network;       // link layer type: 1 = Ethernet
    };

    // this 16-byte header pakcet before each packet in the file
    struct PcapPacketHeader
    {
        uint32_t ts_sec;   // timestamp: seconds since epoch
        uint32_t ts_usec;  // timestamp: microseconds part
        uint32_t incl_len; // bytes actually saved in this file
        uint32_t orig_len; // original packet length (may differ if truncated)
    };

    // one complete raw packet (header + bytes)
    struct RawPacket
    {
        PcapPacketHeader header;
        std::vector<uint8_t> data; // the raw network bytes
    };

    // PcapReader -> opens a .pcap file and hands out packets one at a time
    class PcapReader
    {
    public:
        PcapReader() = default;
        ~PcapReader();

        // Open a .pcap file. Returns false if file not found or not valid pcap
        bool open(const std::string &filename);

        // close the file
        void close();

        // Read the next packet into 'packet'. Returns false when file is done.
        bool readNextPacket(RawPacket &packet);

        // Access the global header (e.g. to copy to output file)
        const PcapGlobalHeader &getGlobalHeader() const { return global_header_; }

        bool isOpen() const { return file_.is_open(); }

    private:
        std::ifstream file_;
        PcapGlobalHeader global_header_;
        bool needs_byte_swap_ = false; // true if file was written on big-endian machine

        uint16_t maybeSwap16(uint16_t value);
        uint32_t maybeSwap32(uint32_t value);
    };

} // namespace PacketAnalyzer
#endif
