#ifndef PCAP_READER_H
#define PCAP_READER_H

#include <cstdint>   // uint32_t, uint16_t, int32_t
#include <string>    // std::string
#include <vector>    // std::vector
#include <fstream>   // std::ifstream — for reading files

namespace PacketAnalyzer
{
    /*
     * PCAP Global Header layout (24 bytes — appears once at start of file):
     *
     *   Byte  0-3  : Magic number  → 0xA1B2C3D4  identifies this as a pcap file
     *   Byte  4-5  : Major version → always 2
     *   Byte  6-7  : Minor version → always 4
     *   Byte  8-11 : GMT offset    → usually 0
     *   Byte 12-15 : Accuracy      → usually 0
     *   Byte 16-19 : Snaplen       → max bytes captured per packet (usually 65535)
     *   Byte 20-23 : Link type     → 1 = Ethernet
     */

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

    /*
     * PCAP Per-Packet Record layout (repeated for every packet in the file):
     *
     * ┌─────────────────────────────┐
     * │      Packet Header          │  16 bytes
     * │   ts_sec   (4 bytes)        │  timestamp — seconds
     * │   ts_usec  (4 bytes)        │  timestamp — microseconds
     * │   incl_len (4 bytes)        │  bytes actually saved in file
     * │   orig_len (4 bytes)        │  original packet size on wire
     * ├─────────────────────────────┤
     * │      Raw Packet Data        │  incl_len bytes
     * │   (Ethernet+IP+TCP+payload) │
     * └─────────────────────────────┘
     */

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
    /*
 * PcapReader workflow:
 *
 * open("capture.pcap")
 *        |
 *        v
 * read PcapGlobalHeader (24 bytes)
 *        |
 *        v
 * check magic_number → valid?
 *        |
 *        v
 * loop:
 *    read PcapPacketHeader (16 bytes)
 *        |
 *        v
 *    read incl_len bytes → raw data
 *        |
 *        v
 *    wrap into RawPacket
 *        |
 *        v
 *    hand to PacketParser
 *        |
 *        v
 *    repeat until file ends
 */

} // namespace PacketAnalyzer
#endif