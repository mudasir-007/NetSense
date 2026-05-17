#include "types.h"
#include <sstream>
#include <iomanip>
#include <algorithm> // for std::transform
#include <cctype>    // for std::toLower

/*
    types.cpp - implements the two key functions declared in types.h

    appTypeToString() - enum -> human readable form
    sniToAppType - domain name -> enum

    also implements FiveTuple::toString() for debug output.

*/

namespace DPI
{
    /*
        FiveTuple::toString()

        produces a human readable description of the connection
        used in debug output and log messages

        Example output: "192.168.1.100:54321 -> 142.250.185.206:443 (TCP)"

    */
    std::string FiveTuple::toString() const
    {
        // Helper lambda: convert a uint32_t IP to "a.b.c.d" string
        // IP is stored in network byte order (same as in the packet)
        auto formatIP = [](uint32_t ip) -> std::string
        {
            std::ostringstream s;
            s << ((ip >> 0) & 0xFF) << "."
              << ((ip >> 8) & 0xFF) << "."
              << ((ip >> 16) & 0xFF) << "."
              << ((ip >> 24) & 0xFF);
            return s.str();
        };

        std::ostringstream ss;
        ss << formatIP(src_ip) << ":" << src_port
           << " -> "
           << formatIP(dst_ip) << ":" << dst_port
           << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP"
                                                              : "?")
           << ")";
        return ss.str();
    }

    /*
        appTypeToString()

        converts an AppType enum value to a prinitable name
        used in reports , blocking logs, and the finnal statistics table
    */
    std::string appTypeToString(AppType type)
    {
        switch (type)
        {
        case AppType::UNKNOWN:
            return "Unknown";
        case AppType::HTTP:
            return "HTTP";
        case AppType::HTTPS:
            return "HTTPS";
        case AppType::DNS:
            return "DNS";
        case AppType::TLS:
            return "TLS";
        case AppType::QUIC:
            return "QUIC";
        case AppType::GOOGLE:
            return "Google";
        case AppType::FACEBOOK:
            return "Facebook";
        case AppType::YOUTUBE:
            return "YouTube";
        case AppType::TWITTER:
            return "Twitter/X";
        case AppType::INSTAGRAM:
            return "Instagram";
        case AppType::NETFLIX:
            return "Netflix";
        case AppType::AMAZON:
            return "Amazon";
        case AppType::MICROSOFT:
            return "Microsoft";
        case AppType::APPLE:
            return "Apple";
        case AppType::WHATSAPP:
            return "WhatsApp";
        case AppType::TELEGRAM:
            return "Telegram";
        case AppType::TIKTOK:
            return "TikTok";
        case AppType::SPOTIFY:
            return "Spotify";
        case AppType::ZOOM:
            return "Zoom";
        case AppType::DISCORD:
            return "Discord";
        case AppType::GITHUB:
            return "GitHub";
        case AppType::CLOUDFLARE:
            return "Cloudflare";
        default:
            return "Unknown";
        }
    }

    /*
        sniToAppType()

        this is the core classification function

        Jow it works:

        1. Convert the SNI string to lowercase (so "YouTube.com" => "youtube.com")

        2. check if it contains the known SUBSTRINGS using std::string::find()
        3. return the matching AppType


        Why substring matching (find) instead of exact matching?
        Because the same service uses many subdomains:
            "www.youtube.com"        ← all contain "youtube"
            "music.youtube.com"
            "i.ytimg.com"            ← YouTube's image CDN

        Order matters — check more specific patterns before general ones.
        Example: check "youtube" before "google" because YouTube IS Google,
        so we want to classify it as YOUTUBE not GOOGLE.

    */
    AppType sniToAppType(const std::string &sni)
    {
        if (sni.empty())
            return AppType::UNKNOWN;

        // Convert to lowercase for case-insensitive matching
        std::string s = sni;
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c)
                       { return std::tolower(c); });

        // YouTube — check BEFORE Google because ytimg/youtube would also match
        // Google patterns (YouTube is owned by Google)
        if (s.find("youtube") != std::string::npos ||
            s.find("ytimg") != std::string::npos || // YouTube image CDN
            s.find("youtu.be") != std::string::npos)
        { // YouTube short URLs
            return AppType::YOUTUBE;
        }

        // Google — after YouTube so we don't misclassify YouTube as Google
        if (s.find("google") != std::string::npos ||
            s.find("gstatic") != std::string::npos ||    // Google static assets
            s.find("googleapis") != std::string::npos || // Google APIs
            s.find("gvt1") != std::string::npos)
        { // Google video
            return AppType::GOOGLE;
        }

        // Instagram — check BEFORE Facebook because both use fbcdn
        if (s.find("instagram") != std::string::npos ||
            s.find("cdninstagram") != std::string::npos)
        { // Instagram CDN
            return AppType::INSTAGRAM;
        }

        // WhatsApp — check BEFORE Facebook (both owned by Meta)
        if (s.find("whatsapp") != std::string::npos ||
            s.find("wa.me") != std::string::npos)
        {
            return AppType::WHATSAPP;
        }

        // Facebook / Meta
        if (s.find("facebook") != std::string::npos ||
            s.find("fbcdn") != std::string::npos || // Facebook CDN
            s.find("fb.com") != std::string::npos ||
            s.find("fbsbx") != std::string::npos || // Facebook sandbox
            s.find("meta.com") != std::string::npos)
        {
            return AppType::FACEBOOK;
        }

        // Twitter / X
        if (s.find("twitter") != std::string::npos ||
            s.find("twimg") != std::string::npos || // Twitter image CDN
            s.find("x.com") != std::string::npos ||
            s.find("t.co") != std::string::npos)
        { // Twitter short URLs
            return AppType::TWITTER;
        }

        // Netflix
        if (s.find("netflix") != std::string::npos ||
            s.find("nflxvideo") != std::string::npos || // Netflix video CDN
            s.find("nflximg") != std::string::npos)
        { // Netflix image CDN
            return AppType::NETFLIX;
        }

        // Amazon / AWS — broad match because Amazon has many services
        if (s.find("amazon") != std::string::npos ||
            s.find("amazonaws") != std::string::npos || // AWS services
            s.find("cloudfront") != std::string::npos)
        { // Amazon CDN
            return AppType::AMAZON;
        }

        // Microsoft
        if (s.find("microsoft") != std::string::npos ||
            s.find("office") != std::string::npos ||
            s.find("azure") != std::string::npos ||
            s.find("outlook") != std::string::npos ||
            s.find("live.com") != std::string::npos ||
            s.find("bing") != std::string::npos)
        {
            return AppType::MICROSOFT;
        }

        // Apple
        if (s.find("apple") != std::string::npos ||
            s.find("icloud") != std::string::npos ||
            s.find("itunes") != std::string::npos ||
            s.find("mzstatic") != std::string::npos)
        { // Apple CDN
            return AppType::APPLE;
        }

        // Telegram
        if (s.find("telegram") != std::string::npos ||
            s.find("t.me") != std::string::npos)
        {
            return AppType::TELEGRAM;
        }

        // TikTok / ByteDance
        if (s.find("tiktok") != std::string::npos ||
            s.find("tiktokcdn") != std::string::npos ||
            s.find("musical.ly") != std::string::npos || // TikTok's old name
            s.find("bytedance") != std::string::npos)
        {
            return AppType::TIKTOK;
        }

        // Spotify
        if (s.find("spotify") != std::string::npos ||
            s.find("scdn.co") != std::string::npos)
        { // Spotify CDN
            return AppType::SPOTIFY;
        }

        // Zoom
        if (s.find("zoom") != std::string::npos)
        {
            return AppType::ZOOM;
        }

        // Discord
        if (s.find("discord") != std::string::npos ||
            s.find("discordapp") != std::string::npos)
        {
            return AppType::DISCORD;
        }

        // GitHub
        if (s.find("github") != std::string::npos ||
            s.find("githubusercontent") != std::string::npos)
        { // raw file CDN
            return AppType::GITHUB;
        }

        // Cloudflare
        if (s.find("cloudflare") != std::string::npos)
        {
            return AppType::CLOUDFLARE;
        }

        // Fallback — we found an SNI but didn't recognise the domain.
        // Mark as HTTPS (better than UNKNOWN — we know it's encrypted web traffic).
        return AppType::HTTPS;
    }
}
