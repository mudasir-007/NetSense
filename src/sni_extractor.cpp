#include "sni_extractor.h"
#include <cstring>   // memcmp
#include <algorithm> // std::min

/*
    sni_extractor.cpp

    Implements byte-level parsing of TLS, HTTP, DNS, and QUIC payloads
    to extract hostnames/domain names.

    Key principle: NEVER read past the end of the buffer.
    Every array access is bounds-checked before it happens.
    If anything is out of bounds, return std::nullopt immediately.
*/

namespace DPI
{
    /*
        Helper: readUint16BE

        Read two bytes as big-endian 16-bit integer.
    */
    uint16_t SNIExtractor::readUint16BE(const uint8_t *data)
    {
        return (static_cast<uint16_t>(data[0]) << 8) |
               static_cast<uint16_t>(data[1]);
    }

    /*
        Helper: readUint24BE

        Read three bytes as big-endian 24-bit integer.
        Used for TLS handshake lengths.
    */
    uint32_t SNIExtractor::readUint24BE(const uint8_t *data)
    {
        return (static_cast<uint32_t>(data[0]) << 16) |
               (static_cast<uint32_t>(data[1]) << 8) |
               static_cast<uint32_t>(data[2]);
    }

    /*
        SNIExtractor::isTLSClientHello()

        Performs quick validation of a TLS Client Hello packet.
        Checks record header and handshake type.
    */
    bool SNIExtractor::isTLSClientHello(const uint8_t *payload, size_t length)
    {
        if (length < 6)
        {
            return false;
        }

        if (payload[0] != CONTENT_TYPE_HANDSHAKE)
        {
            return false;
        }

        if (payload[1] != 0x03)
        {
            return false;
        }
        if (payload[2] > 0x04)
        {
            return false;
        }

        uint16_t record_len = readUint16BE(payload + 3);
        if (record_len > length - 5)
        {
            return false;
        }

        if (payload[5] != HANDSHAKE_CLIENT_HELLO)
        {
            return false;
        }

        return true;
    }

    /*
        SNIExtractor::extract()

        Parses TLS Client Hello and extracts SNI hostname
        from the extensions section.
    */
    std::optional<std::string>
    SNIExtractor::extract(const uint8_t *payload, size_t length)
    {
        if (!isTLSClientHello(payload, length))
        {
            return std::nullopt;
        }

        size_t offset = 5; // Skip record header

        if (offset + 4 > length)
        {
            return std::nullopt;
        }
        offset += 4; // Skip handshake header

        if (offset + 34 > length)
        {
            return std::nullopt;
        }
        offset += 34; // Skip version + random

        if (offset + 1 > length)
        {
            return std::nullopt;
        }
        uint8_t session_len = payload[offset];
        offset += 1 + session_len;
        if (offset > length)
        {
            return std::nullopt;
        }

        if (offset + 2 > length)
        {
            return std::nullopt;
        }
        uint16_t cipher_len = readUint16BE(payload + offset);
        offset += 2 + cipher_len;
        if (offset > length)
        {
            return std::nullopt;
        }

        if (offset + 1 > length)
        {
            return std::nullopt;
        }
        uint8_t comp_len = payload[offset];
        offset += 1 + comp_len;
        if (offset > length)
        {
            return std::nullopt;
        }

        if (offset + 2 > length)
        {
            return std::nullopt;
        }
        uint16_t ext_total = readUint16BE(payload + offset);
        offset += 2;

        size_t ext_end = std::min(offset + ext_total, length);

        while (offset + 4 <= ext_end)
        {
            uint16_t ext_type = readUint16BE(payload + offset);
            uint16_t ext_len = readUint16BE(payload + offset + 2);
            offset += 4;

            if (offset + ext_len > ext_end)
            {
                break;
            }

            if (ext_type == EXTENSION_SNI)
            {
                if (ext_len < 5)
                    break;

                uint8_t sni_type = payload[offset + 2];
                if (sni_type != SNI_TYPE_HOSTNAME)
                {
                    break;
                }

                uint16_t host_len = readUint16BE(payload + offset + 3);
                if (host_len == 0)
                {
                    break;
                }
                if (5 + host_len > ext_len)
                {
                    break;
                }

                std::string hostname(
                    reinterpret_cast<const char *>(payload + offset + 5),
                    host_len);

                return hostname;
            }

            offset += ext_len;
        }

        return std::nullopt;
    }

    /*
        SNIExtractor::extractExtensions()

        Returns all TLS extensions as (type, raw_data) pairs.
        Useful for debugging.
    */
    std::vector<std::pair<uint16_t, std::string>>
    SNIExtractor::extractExtensions(const uint8_t *payload, size_t length)
    {
        std::vector<std::pair<uint16_t, std::string>> result;

        if (!isTLSClientHello(payload, length))
        {
            return result;
        }

        size_t offset = 5 + 4 + 34;

        if (offset + 1 > length)
        {
            return result;
        }
        uint8_t session_len = payload[offset];
        offset += 1 + session_len;

        if (offset + 2 > length)
        {
            return result;
        }
        uint16_t cipher_len = readUint16BE(payload + offset);
        offset += 2 + cipher_len;

        if (offset + 1 > length)
        {
            return result;
        }
        uint8_t comp_len = payload[offset];
        offset += 1 + comp_len;

        if (offset + 2 > length)
        {
            return result;
        }
        uint16_t ext_total = readUint16BE(payload + offset);
        offset += 2;

        size_t ext_end = std::min(offset + ext_total, length);

        while (offset + 4 <= ext_end)
        {
            uint16_t ext_type = readUint16BE(payload + offset);
            uint16_t ext_len = readUint16BE(payload + offset + 2);
            offset += 4;

            if (offset + ext_len > ext_end)
            {
                break;
            }

            std::string data(
                reinterpret_cast<const char *>(payload + offset),
                ext_len);

            result.emplace_back(ext_type, data);
            offset += ext_len;
        }

        return result;
    }

    /*
        HTTPHostExtractor::isHTTPRequest()

        Checks if payload begins with a known HTTP method.
    */
    bool HTTPHostExtractor::isHTTPRequest(const uint8_t *payload, size_t length)
    {
        if (length < 4)
        {
            return false;
        }

        const char *methods[] = {
            "GET ", "POST", "PUT ",
            "HEAD", "DELE", "PATC", "OPTI"};

        for (const char *method : methods)
        {
            if (std::memcmp(payload, method, 4) == 0)
            {
                return true;
            }
        }

        return false;
    }

    /*
        HTTPHostExtractor::extract()

        Scans HTTP headers for "Host:" field
        and returns hostname without port.
    */
    std::optional<std::string>
    HTTPHostExtractor::extract(const uint8_t *payload, size_t length)
    {
        if (!isHTTPRequest(payload, length))
        {
            return std::nullopt;
        }

        for (size_t i = 0; i + 6 < length; i++)
        {
            if ((payload[i] == 'H' || payload[i] == 'h') &&
                (payload[i + 1] == 'O' || payload[i + 1] == 'o') &&
                (payload[i + 2] == 'S' || payload[i + 2] == 's') &&
                (payload[i + 3] == 'T' || payload[i + 3] == 't') &&
                payload[i + 4] == ':')
            {
                size_t start = i + 5;

                while (start < length &&
                       (payload[start] == ' ' || payload[start] == '\t'))
                    start++;

                size_t end = start;
                while (end < length &&
                       payload[end] != '\r' &&
                       payload[end] != '\n')
                    end++;

                if (end <= start)
                {
                    return std::nullopt;
                }

                std::string host(
                    reinterpret_cast<const char *>(payload + start),
                    end - start);

                size_t colon = host.find(':');
                if (colon != std::string::npos)
                {
                    host = host.substr(0, colon);
                }

                return host;
            }
        }

        return std::nullopt;
    }

    /*
        DNSExtractor::isDNSQuery()

        Checks basic DNS header fields to confirm
        packet is a DNS query.
    */
    bool DNSExtractor::isDNSQuery(const uint8_t *payload, size_t length)
    {
        if (length < 12)
        {
            return false;
        }

        if (payload[2] & 0x80)
        {
            return false;
        }

        uint16_t qdcount =
            (static_cast<uint16_t>(payload[4]) << 8) |
            static_cast<uint16_t>(payload[5]);

        if (qdcount == 0)
        {
            return false;
        }

        return true;
    }

    /*
        DNSExtractor::extractQuery()

        Parses DNS question section and reconstructs
        domain name from length-prefixed labels.
    */
    std::optional<std::string>
    DNSExtractor::extractQuery(const uint8_t *payload, size_t length)
    {
        if (!isDNSQuery(payload, length))
            return std::nullopt;

        size_t offset = 12;
        std::string domain;

        while (offset < length)
        {
            uint8_t label_len = payload[offset++];
            if (label_len == 0)
                break;

            if (label_len > 63)
                break;

            if (offset + label_len > length)
                break;

            if (!domain.empty())
                domain += '.';

            domain += std::string(
                reinterpret_cast<const char *>(payload + offset),
                label_len);

            offset += label_len;
        }

        return domain.empty() ? std::nullopt
                              : std::optional<std::string>(domain);
    }

    /*
        QUICSNIExtractor::isQUICInitial()

        Basic heuristic check for QUIC long header.
    */
    bool QUICSNIExtractor::isQUICInitial(const uint8_t *payload, size_t length)
    {
        if (length < 5)
        {
            return false;
        }

        return (payload[0] & 0x80) != 0;
    }

    /*
        QUICSNIExtractor::extract()

        Scans QUIC packet for embedded TLS Client Hello
        and delegates extraction to SNIExtractor.
    */
    std::optional<std::string>
    QUICSNIExtractor::extract(const uint8_t *payload, size_t length)
    {
        if (!isQUICInitial(payload, length))
        {
            return std::nullopt;
        }

        for (size_t i = 0; i + 10 < length; i++)
        {
            if (payload[i] == 0x16 && payload[i + 1] == 0x03)
            {
                auto result =
                    SNIExtractor::extract(payload + i, length - i);

                if (result)
                {
                    return result;
                }
            }
        }

        return std::nullopt;
    }

} // namespace DPI