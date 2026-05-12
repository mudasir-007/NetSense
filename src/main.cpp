#include <iostream>
#include "pcap_reader.h"

using namespace PacketAnalyzer;

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage: flowshield <file.pcap>\n";
        return 1;
    }

    std::string filename = argv[1];

    PcapReader reader;

    if (!reader.open(filename))
    {
        std::cerr << "Failed to open pcap file.\n";
        return 1;
    }

    RawPacket packet;
    size_t packetCount = 0;
    size_t totalBytes = 0;

    while (reader.readNextPacket(packet))
    {
        packetCount++;
        totalBytes += packet.header.incl_len;

        std::cout << "Packet #" << packetCount
                  << " | Size: " << packet.header.incl_len
                  << " bytes"
                  << " | Timestamp: "
                  << packet.header.ts_sec << "."
                  << packet.header.ts_usec
                  << "\n";
    }

    std::cout << "\nFinished reading file.\n";
    std::cout << "Total packets: " << packetCount << "\n";
    std::cout << "Total captured bytes: " << totalBytes << "\n";

    reader.close();

    return 0;
}