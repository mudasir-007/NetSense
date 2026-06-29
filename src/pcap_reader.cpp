/*
 * PcapReader complete workflow:
 *
 * PcapReader reader
 *        |
 *        v
 * reader.open("file.pcap")
 *        |
 *        v
 * read 24 bytes → global_header_
 *        |
 *        v
 * check magic_number
 *    NATIVE  → needs_byte_swap_ = false
 *    SWAPPED → needs_byte_swap_ = true → swap header fields
 *    INVALID → return false
 *        |
 *        v
 * loop: reader.readNextPacket(packet)
 *        |
 *        v
 * read 16 bytes → packet.header
 *        |
 *        v
 * swap if needed
 *        |
 *        v
 * sanity check incl_len
 *        |
 *        v
 * read incl_len bytes → packet.data
 *        |
 *        v
 * return true → repeat
 *        |
 *        v
 * file_.good() == false → return false → loop ends
 *        |
 *        v
 * reader.close()
 */


#include "pcap_reader.h"
#include <iostream>


namespace PacketAnalyzer
{

    // Magic numbers — the first 4 bytes of every valid .pcap file
    // If we see the "swapped" version, the file was written on a big-endian machine
    constexpr uint32_t PCAP_MAGIC_NATIVE = 0xa1b2c3d4;  // our machine order
    constexpr uint32_t PCAP_MAGIC_SWAPPED = 0xd4c3b2a1; // opposite order
    /*
    *NATIVE:  A1 B2 C3 D4
    *SWAPPED: D4 C3 B2 A1  ← exact reverse
    */

    PcapReader::~PcapReader()
    {
        close();
    }

    bool PcapReader::open(const std::string &filename)
    {
        close(); // close any previously opened file first

        // Open in binary mode — critical, otherwise Windows messes with line endings
        file_.open(filename, std::ios::binary);
        if (!file_.is_open())
        {
            std::cerr << "[PcapReader] Cannot open: " << filename << "\n";
            return false;
        }

        // Read the 24-byte global header
        file_.read(reinterpret_cast<char *>(&global_header_), sizeof(PcapGlobalHeader));
        if (!file_.good())
        {
            std::cerr << "[PcapReader] Failed to read global header\n";
            close();
            return false;
        }

        // Check the magic number to confirm this is really a pcap file
        // and to detect if byte-swapping is needed
        if (global_header_.magic_number == PCAP_MAGIC_NATIVE)
        {
            needs_byte_swap_ = false;
        }
        else if (global_header_.magic_number == PCAP_MAGIC_SWAPPED)
        {
            needs_byte_swap_ = true;
            // Swap the header fields we already read
            global_header_.version_major = maybeSwap16(global_header_.version_major);
            global_header_.version_minor = maybeSwap16(global_header_.version_minor);
            global_header_.snaplen = maybeSwap32(global_header_.snaplen);
            global_header_.network = maybeSwap32(global_header_.network);
        }
        else
        {
            std::cerr << "[PcapReader] Invalid magic number — not a pcap file\n";
            close();
            return false;
        }

        std::cout << "[PcapReader] Opened: " << filename << "\n";
        std::cout << "  Version:   " << global_header_.version_major
                  << "." << global_header_.version_minor << "\n";
        std::cout << "  Link type: " << global_header_.network
                  << (global_header_.network == 1 ? " (Ethernet)" : "") << "\n";
        std::cout << "  Snaplen:   " << global_header_.snaplen << " bytes\n";

        return true;
    }

    void PcapReader::close()
    {
        if (file_.is_open())
        {
            file_.close();
        }
        needs_byte_swap_ = false;
    }

    bool PcapReader::readNextPacket(RawPacket &packet)
    {
        if (!file_.is_open())
            return false;

        // Read the 16-byte packet header
        file_.read(reinterpret_cast<char *>(&packet.header), sizeof(PcapPacketHeader));
        if (!file_.good())
        {
            return false; // end of file or read error — normal exit condition
        }

        // Swap bytes if the file came from a different-endian machine
        if (needs_byte_swap_)
        {
            packet.header.ts_sec = maybeSwap32(packet.header.ts_sec);
            packet.header.ts_usec = maybeSwap32(packet.header.ts_usec);
            packet.header.incl_len = maybeSwap32(packet.header.incl_len);
            packet.header.orig_len = maybeSwap32(packet.header.orig_len);
        }

        // Sanity check: incl_len should never exceed snaplen or 65535
        if (packet.header.incl_len > 65535)
        {
            std::cerr << "[PcapReader] Bogus packet length: " << packet.header.incl_len << "\n";
            return false;
        }

        // Read exactly incl_len bytes of packet data
        packet.data.resize(packet.header.incl_len);
        file_.read(reinterpret_cast<char *>(packet.data.data()), packet.header.incl_len);
        if (!file_.good())
        {
            std::cerr << "[PcapReader] Truncated packet data\n";
            return false;
        }

        return true;
    }

    uint16_t PcapReader::maybeSwap16(uint16_t value)
    {
        if (!needs_byte_swap_)
            return value;
        return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
    }

    uint32_t PcapReader::maybeSwap32(uint32_t value)
    {
        if (!needs_byte_swap_)
            return value;
        return ((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) |
               ((value & 0x0000FF00) << 8) | ((value & 0x000000FF) << 24);
    }
}