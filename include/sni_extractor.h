/*

The TLS Client Hello byte layout

BYTE 0:       0x16          ← Content Type: Handshake
BYTES 1-2:    0x03 0x01     ← TLS version (1.0 on record layer)
BYTES 3-4:    [length]      ← how many bytes follow

BYTE 5:       0x01          ← Handshake Type: Client Hello
BYTES 6-8:    [length]      ← 3-byte length of Client Hello body

BYTES 9-10:   [version]     ← client's max TLS version
BYTES 11-42:  [random]      ← 32 random bytes (used in key exchange)
BYTE 43:      [N]           ← session ID length
BYTES 44+N:   [session ID]  ← N bytes of session ID (skip)

BYTES ...:    [cipher len]  ← 2 bytes: how many cipher suites
BYTES ...:    [ciphers]     ← skip all of them
BYTE  ...:    [comp len]    ← 1 byte: compression methods length
BYTES ...:    [comp]        ← skip

BYTES ...:    [ext len]     ← 2 bytes: total extensions length
─── EXTENSIONS (loop through these) ───────────────────────
  BYTES: [ext type]         ← 2 bytes: which extension
  BYTES: [ext len]          ← 2 bytes: this extension's data length
  BYTES: [ext data]         ← variable

  When ext type == 0x0000 (SNI extension):
    BYTES: [list len]       ← 2 bytes
    BYTE:  0x00             ← entry type: hostname
    BYTES: [name len]       ← 2 bytes
    BYTES: [hostname]       ← THIS IS WHAT WE WANT

*/

#ifndef SNI_EXTRACTOR_H
#define SNI_EXTRACTOR_H

#include <string>
#include <cstdint>
#include <optional> // std::optional - returns value OR nothing
#include <vector>

/*
    sni_extractor.h

    Four Extractors, each targeting a different protocol:

    SNIExtractor - TLS client Hello (HTTPS, port 443)
    HTTPHostExtractor - HTTP Host header (plain HTTP, port 80)
    DNSExtractor - DNS query name (UDP port 53)
    QUICSNIExtractor - QUIC Initial packet (UDP port 443, HTTP/3)

    All extractoRs follow the same pattern:
        1. check if payload looks like the target protocol.
        2. Navigate the byte structure to find the hostname.
        3. Return std::optional<std::string>
            - std::nullopt if not found / wrong protocol
            - the hostname if successfully extracted
*/

namespace DPI
{
    /*

        SNI Extractor - extracts hostname from TLS client hello

        input: pointer to TCP payload bytes + length
        Output: the SNI hostname string, e.g, "www.youtube.com" or std::nullopt if this isn't a TLS client hello

        This only works on the FIRST packet of a TLS connection.
        Subsequent packets are encrypted and yield nothing.

    */
    class SNIExtractor
    {
    public:
        // Main extraction function.
        // 'payload' should point to the first byte AFTER the TCP header.
        // Returns the SNI hostname or std::nullopt.
        static std::optional<std::string> extract(const uint8_t *payload,
                                                  size_t length);

        // Quick check: does this payload look like a TLS Client Hello?
        // Used to avoid running the full parser on every packet.
        static bool isTLSClientHello(const uint8_t *payload, size_t length);

        // Debug helper: extract all TLS extensions as (type, data) pairs
        static std::vector<std::pair<uint16_t, std::string>>
        extractExtensions(const uint8_t *payload, size_t length);

    private:
        // --- TLS protocol constants ---

        // Content type byte (byte 0 of TLS record)
        static constexpr uint8_t CONTENT_TYPE_HANDSHAKE = 0x16;

        // Handshake type byte (byte 5, first byte of handshake layer)
        static constexpr uint8_t HANDSHAKE_CLIENT_HELLO = 0x01;

        // Extension type for SNI (the two-byte type field in extensions)
        static constexpr uint16_t EXTENSION_SNI = 0x0000;

        // SNI entry type: 0x00 means "hostname" (the only defined type)
        static constexpr uint8_t SNI_TYPE_HOSTNAME = 0x00;

        // --- Helper functions to read big-endian values from raw bytes ---

        // Read 2 bytes at 'data' as a big-endian uint16
        // e.g. bytes {0x01, 0xBB} -> 443
        static uint16_t readUint16BE(const uint8_t *data);

        // Read 3 bytes at 'data' as a big-endian uint24 (used in handshake length)
        // TLS handshake lengths are 3 bytes, not 2 or 4
        static uint32_t readUint24BE(const uint8_t *data);
    };

    /*
        HTTPHostExtractor - extracts hostname from HTTP/1.x Host header

        plain HTTP (port 80) sends headers in clearText.
        Every HTTP request includes a "Host: www.example.com" header.
        We search the payload for this header and extract the value.

        Example HTTP request payload:
            GET / HTTP / 1.1\r\n
            Host: www.example.com\r\n <- we extract: "www.example.com"
            User Agent: ////\f\n
            \f\n
    */
    class HTTPHostExtractor
    {
    public:
        // Extract the Host header value from an HTTP request payload.
        // Returns std::nullopt if this isn't an HTTP request.

        static std::optional<std::string> extract(const uint8_t *payload, size_t length);

        // Quick check: does this start with an HTTP method?
        // (GET, POST, PUT, HEAD, DELETE, PATCH OPTIONS)
        static bool isHTTPRequest(const uint8_t *payload, size_t length);
    };

    /*
        DNSExtractor - extracts queried domain from 0 DNS request.

        DNS packets have a fixed 12-byte header followed y question records.
        Each question contains a domain name encoded as length-prefixed labels:

            Example: "www.google.com"
            Encoded: 03 'w' 'w' 'w'   ← label: 3 bytes "www"
                     06 'g' 'o' 'o' 'g' 'l' 'e'  ← label: 6 bytes "google"
                     03 'c' 'o' 'm'   ← label: 3 bytes "com"
                     00               ← null terminator
    */
    class DNSExtractor
    {
    public:
        // Extracts the queried domain name from a DNS request.
        // Returns std::nullopt if this isn't a DNS query
        static std::optional<std::string> extractQuery(const uint8_t *payload, size_t length);

        // Quick check: is this a DNS query (not a response)?
        static bool isDNSQuery(const uint8_t *payload, size_t length);
    };

    /*
        QUICSNIExtractor -  extracts SNI from QUIC initial packets

        QUIC (used by HTTP/3) runs over UDP Port 443
        QUIC Initial packets contain a TLS client hello inside CRYPTO Frames.
        This is complex in parse properly, so we use a simplified heuristic.
        scan for a TLS client Hello pattern inside the QUIC payload.
    */
    class QUICSNIExtractor
    {
    public:
        // Attempt to extract SNI from a QUIC initial packet.
        static std::optional<std::string> extract(const uint8_t *payload, size_t length);

        // Quick check: does this look like a QUIC packet?
        static bool isQUICInitial(const uint8_t *payload, size_t length);
    };
}

#endif