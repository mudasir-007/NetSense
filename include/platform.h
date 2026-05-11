#ifndef PLATFORM_H
#define PLATFORM_H

#include <cstdint>

// platform.h => oirtable byte-order conversion

/*
    Network protocols send data in big endian order
    x86 wndows uses little-endian order
    these functions flip bytes when needed

*/

namespace PortableNet
{
    // Swap the two bytes in a 16-bit value
    // Example: 0x01BB -> 0xBB01
    inline uint16_t swapBytes16(uint16_t value)
    {
        return ((value & 0xFF00) >> 8) | // move high byte to low
               ((value & 0x00FF) << 8);  // move low byte to high
    }

    // Swap all four bytes in a 32-bit value
    // Example: 0x01020304 -> 0x04030201

    inline uint32_t swapBytes32(uint32_t value)
    {
        return ((value & 0xFF000000) >> 24) | // byte 3 -> byte 0
               ((value & 0x00FF0000) >> 8) |  // byte 2 -> byte 1
               ((value & 0x0000FF00) << 8) |  // byte 1 -> byte 2
               ((value & 0x000000FF) << 24);  // byte 0 -> byte 3
    }

    // Detect at runtime whether this CPU is little-endian
    // We store 0x0001 and check which byte is at address 0
    // Little-endian: address 0 holds 0x01 (low byte first)
    inline bool isLittleEndian()
    {
        uint16_t test = 0x0001;
        return *reinterpret_cast<const uint8_t *>(&test) == 0x01;
    }

    // Convert a 16-bit value from network byte order to host byte order
    // if we are little-endian (windows x86): swap
    // if we are big-endian (rare) : no op
    inline uint16_t netToHost16(uint16_t netValue)
    {
        return isLittleEndian() ? swapBytes16(netValue) : netValue;
    }

    // Convert a 32 bit value from network byte order to host byte order
    inline uint32_t netToHost32(uint32_t netValue)
    {
        return isLittleEndian() ? swapBytes32(netValue) : netValue;
    }

    // Host to network is the same operation(swapping is its own inverse)
    inline uint16_t hostToNet16(uint16_t hostValue)
    {
        return netToHost16(hostValue);
    }
    inline uint32_t hostToNet32(uint32_t hostValue)
    {
        return netToHost32(hostValue);
    }
}

#endif
