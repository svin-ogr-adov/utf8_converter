#include "utf8_converter_api.h"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <stdexcept>
#include <filesystem>

namespace enc {

// -------------------- IO --------------------
/**
 * Reads an entire file as raw bytes.
 *
 * @param path Path to the file.
 * @return Vector of bytes containing the full file contents.
 * @throws std::runtime_error if the file cannot be opened.
 */
static std::vector<unsigned char> read_file_bytes(const std::string &path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open file: " + path);
    in.seekg(0, std::ios::end);
    auto len = in.tellg();
    in.seekg(0, std::ios::beg);
    std::vector<unsigned char> data;
    data.resize(static_cast<size_t>(len));
    if (len > 0) in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(len));
    return data;
}

// -------------------- UTF-8 helpers --------------------
/**
 * Validates that a byte span is well‑formed UTF‑8.
 *
 * Implements boundary checks for overlong sequences and surrogate ranges.
 *
 * @param s Pointer to the first byte.
 * @param n Number of bytes to validate.
 * @return true if the span is valid UTF‑8.
 */
static bool is_valid_utf8(const unsigned char* s, size_t n) {
    size_t i = 0;
    while (i < n) {
        unsigned char c = s[i];
        if (c <= 0x7F) { i++; continue; }
        size_t extra = 0;
        if ((c & 0xE0) == 0xC0) { extra = 1; if (c < 0xC2) return false; }
        else if ((c & 0xF0) == 0xE0) { extra = 2; }
        else if ((c & 0xF8) == 0xF0) { extra = 3; if (c > 0xF4) return false; }
        else return false;
        if (i + extra >= n) return false;
        for (size_t j = 1; j <= extra; ++j) if ((s[i+j] & 0xC0) != 0x80) return false;
        if (extra == 2) {
            unsigned char c1 = s[i+1];
            if (c == 0xE0 && (c1 < 0xA0)) return false;
            if (c == 0xED && (c1 >= 0xA0)) return false;
        } else if (extra == 3) {
            unsigned char c1 = s[i+1];
            if (c == 0xF0 && (c1 < 0x90)) return false;
            if (c == 0xF4 && (c1 >= 0x90)) return false;
        }
        i += extra + 1;
    }
    return true;
}

/**
 * Appends a Unicode code point to a UTF‑8 string buffer.
 *
 * @param out Destination UTF‑8 string.
 * @param cp  Unicode scalar value (0..0x10FFFF), no validation here.
 */
static void append_utf8(std::string &out, uint32_t cp) {
    if (cp <= 0x7F) out.push_back(static_cast<char>(cp));
    else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

// -------------------- BOM detection --------------------
/**
 * Minimal BOM detector for UTF families.
 */
struct BomInfo { const char* name; size_t size; };
static std::optional<BomInfo> detect_bom(const std::vector<unsigned char>& b) {
    if (b.size() >= 3 && b[0]==0xEF && b[1]==0xBB && b[2]==0xBF) return BomInfo{"UTF-8", 3};
    if (b.size() >= 2 && b[0]==0xFF && b[1]==0xFE) return BomInfo{"UTF-16LE", 2};
    if (b.size() >= 2 && b[0]==0xFE && b[1]==0xFF) return BomInfo{"UTF-16BE", 2};
    if (b.size() >= 4 && b[0]==0xFF && b[1]==0xFE && b[2]==0x00 && b[3]==0x00) return BomInfo{"UTF-32LE", 4};
    if (b.size() >= 4 && b[0]==0x00 && b[1]==0x00 && b[2]==0xFE && b[3]==0xFF) return BomInfo{"UTF-32BE", 4};
    return std::nullopt;
}

// -------------------- Heuristics for UTF-16/32 without BOM --------------------
/**
 * Heuristic: UTF‑16LE text often has many zero bytes in the high byte of each 16‑bit unit.
 */
static bool looks_like_utf16_le(const std::vector<unsigned char>& b) {
    if (b.size() < 6) return false;
    size_t zeros_even = 0, zeros_odd = 0;
    for (size_t i = 0; i + 1 < b.size(); i += 2) zeros_odd  += (b[i+1] == 0);
    for (size_t i = 0; i + 1 < b.size(); i += 2) zeros_even += (b[i] == 0);
    return zeros_odd > zeros_even * 3 && zeros_odd > b.size() / 8;
}
/**
 * Heuristic: UTF‑16BE text often has many zero bytes in the low byte of each 16‑bit unit.
 */
static bool looks_like_utf16_be(const std::vector<unsigned char>& b) {
    if (b.size() < 6) return false;
    size_t zeros_even = 0, zeros_odd = 0;
    for (size_t i = 0; i + 1 < b.size(); i += 2) zeros_even += (b[i] == 0);
    for (size_t i = 0; i + 1 < b.size(); i += 2) zeros_odd  += (b[i+1] == 0);
    return zeros_even > zeros_odd * 3 && zeros_even > b.size() / 8;
}
/**
 * Heuristic: UTF‑32LE text has three zero bytes for many ASCII code points.
 */
static bool looks_like_utf32_le(const std::vector<unsigned char>& b) {
    if (b.size() < 8) return false;
    size_t zero_cnt = 0;
    for (size_t i = 0; i + 3 < b.size(); i += 4) zero_cnt += (b[i+1]==0 && b[i+2]==0 && b[i+3]==0);
    return zero_cnt > b.size() / 16;
}
/**
 * Heuristic: UTF‑32BE text has three leading zero bytes for many ASCII code points.
 */
static bool looks_like_utf32_be(const std::vector<unsigned char>& b) {
    if (b.size() < 8) return false;
    size_t zero_cnt = 0;
    for (size_t i = 0; i + 3 < b.size(); i += 4) zero_cnt += (b[i]==0 && b[i+1]==0 && b[i+2]==0);
    return zero_cnt > b.size() / 16;
}

// -------------------- Single-byte decoding tables --------------------
// Each table maps 0..255 -> Unicode code point.
// For 0..127 use ASCII; rest per encoding.

static const uint16_t CP1251_TABLE[128] = {
// 0x80..0xFF
0x0402,0x0403,0x201A,0x0453,0x201E,0x2026,0x2020,0x2021,0x20AC,0x2030,0x0409,0x2039,0x040A,0x040C,0x040B,0x040F,
0x0452,0x2018,0x2019,0x201C,0x201D,0x2022,0x2013,0x2014,0x0000,0x2122,0x0459,0x203A,0x045A,0x045C,0x045B,0x045F,
0x00A0,0x040E,0x045E,0x0408,0x00A4,0x0490,0x00A6,0x00A7,0x0401,0x00A9,0x0404,0x00AB,0x00AC,0x00AD,0x00AE,0x0407,
0x00B0,0x00B1,0x0406,0x0456,0x0491,0x00B5,0x00B6,0x00B7,0x0451,0x2116,0x0454,0x00BB,0x0458,0x0405,0x0455,0x0457,
0x0410,0x0411,0x0412,0x0413,0x0414,0x0415,0x0416,0x0417,0x0418,0x0419,0x041A,0x041B,0x041C,0x041D,0x041E,0x041F,
0x0420,0x0421,0x0422,0x0423,0x0424,0x0425,0x0426,0x0427,0x0428,0x0429,0x042A,0x042B,0x042C,0x042D,0x042E,0x042F,
0x0430,0x0431,0x0432,0x0433,0x0434,0x0435,0x0436,0x0437,0x0438,0x0439,0x043A,0x043B,0x043C,0x043D,0x043E,0x043F,
0x0440,0x0441,0x0442,0x0443,0x0444,0x0445,0x0446,0x0447,0x0448,0x0449,0x044A,0x044B,0x044C,0x044D,0x044E,0x044F
};

static const uint16_t KOI8R_TABLE[128] = {
0x2500,0x2502,0x250C,0x2510,0x2514,0x2518,0x251C,0x2524,0x252C,0x2534,0x253C,0x2580,0x2584,0x2588,0x258C,0x2590,
0x2591,0x2592,0x2593,0x2320,0x25A0,0x2219,0x221A,0x2248,0x2264,0x2265,0x00A0,0x2321,0x00B0,0x00B2,0x00B7,0x00F7,
0x2550,0x2551,0x2552,0x0451,0x2553,0x2554,0x2555,0x2556,0x2557,0x2558,0x2559,0x255A,0x255B,0x255C,0x255D,0x255E,
0x255F,0x2560,0x2561,0x0401,0x2562,0x2563,0x2564,0x2565,0x2566,0x2567,0x2568,0x2569,0x256A,0x256B,0x256C,0x00A9,
0x044E,0x0430,0x0431,0x0446,0x0434,0x0435,0x0444,0x0433,0x0445,0x0438,0x0439,0x043A,0x043B,0x043C,0x043D,0x043E,
0x043F,0x044F,0x0440,0x0441,0x0442,0x0443,0x0436,0x0432,0x044C,0x044B,0x0437,0x0448,0x044D,0x0449,0x0447,0x044A,
0x042E,0x0410,0x0411,0x0426,0x0414,0x0415,0x0424,0x0413,0x0425,0x0418,0x0419,0x041A,0x041B,0x041C,0x041D,0x041E,
0x041F,0x042F,0x0420,0x0421,0x0422,0x0423,0x0416,0x0412,0x042C,0x042B,0x0417,0x0428,0x042D,0x0429,0x0427,0x042A
};

static const uint16_t ISO8859_5_TABLE[128] = {
0x0080,0x0081,0x0082,0x0083,0x0084,0x0085,0x0086,0x0087,0x0088,0x0089,0x008A,0x008B,0x008C,0x008D,0x008E,0x008F,
0x0090,0x0091,0x0092,0x0093,0x0094,0x0095,0x0096,0x0097,0x0098,0x0099,0x009A,0x009B,0x009C,0x009D,0x009E,0x009F,
0x00A0,0x0401,0x0402,0x0403,0x0404,0x0405,0x0406,0x0407,0x0408,0x0409,0x040A,0x040B,0x040C,0x00AD,0x040E,0x040F,
0x0410,0x0411,0x0412,0x0413,0x0414,0x0415,0x0416,0x0417,0x0418,0x0419,0x041A,0x041B,0x041C,0x041D,0x041E,0x041F,
0x0420,0x0421,0x0422,0x0423,0x0424,0x0425,0x0426,0x0427,0x0428,0x0429,0x042A,0x042B,0x042C,0x042D,0x042E,0x042F,
0x0430,0x0431,0x0432,0x0433,0x0434,0x0435,0x0436,0x0437,0x0438,0x0439,0x043A,0x043B,0x043C,0x043D,0x043E,0x043F,
0x0440,0x0441,0x0442,0x0443,0x0444,0x0445,0x0446,0x0447,0x0448,0x0449,0x044A,0x044B,0x044C,0x044D,0x044E,0x044F,
0x2116,0x0451,0x0452,0x0453,0x0454,0x0455,0x0456,0x0457,0x0458,0x0459,0x045A,0x045B,0x045C,0x00A7,0x045E,0x045F
};

static const uint16_t MACCYR_TABLE[128] = {
0x0410,0x0411,0x0412,0x0413,0x0414,0x0415,0x0416,0x0417,0x0418,0x0419,0x041A,0x041B,0x041C,0x041D,0x041E,0x041F,
0x0420,0x0421,0x0422,0x0423,0x0424,0x0425,0x0426,0x0427,0x0428,0x0429,0x042A,0x042B,0x042C,0x042D,0x042E,0x042F,
0x2020,0x00B0,0x0490,0x00A3,0x00A7,0x2022,0x00B6,0x0406,0x00AE,0x00A9,0x2122,0x0402,0x0452,0x2260,0x0403,0x0453,
0x221E,0x00B1,0x2264,0x2265,0x00A5,0x0491,0x0408,0x0404,0x0407,0x0409,0x040A,0x040C,0x0459,0x045A,0x045C,0x045B,
0x045F,0x00A4,0x00AB,0x00BB,0x2591,0x2592,0x2593,0x2502,0x2524,0x00A0,0x044E,0x0430,0x0431,0x0446,0x0434,0x0435,
0x0444,0x0433,0x0445,0x0438,0x0439,0x043A,0x043B,0x043C,0x043D,0x043E,0x043F,0x044F,0x0440,0x0441,0x0442,0x0443,
0x0436,0x0432,0x044C,0x044B,0x0437,0x0448,0x044D,0x0449,0x0447,0x044A,0x042E,0x0410,0x0411,0x0426,0x0414,0x0415,
0x0424,0x0413,0x0425,0x0418,0x0419,0x041A,0x041B,0x041C,0x041D,0x041E,0x041F,0x042F,0x0420,0x0421,0x0422,0x0423
};

// -------------------- Decoders --------------------
/**
 * Enum discriminator for supported single‑byte Cyrillic encodings.
 */
enum class SingleByte { CP1251, KOI8R, ISO8859_5, MACCYR };

/**
 * Decodes UTF‑16LE/BE into a sequence of Unicode code points (char32_t).
 *
 * Handles surrogate pairs and emits U+FFFD for malformed pairs or trailing high
 * surrogates.
 *
 * @param p Pointer to first byte.
 * @param n Number of bytes.
 * @param be True for big‑endian input; false for little‑endian.
 * @return UTF‑32 code‑point sequence.
 */
static std::u32string decode_utf16(const unsigned char* p, size_t n, bool be) {
    std::u32string out;
    if (n % 2) n--; // drop trailing odd byte
    for (size_t i = 0; i + 1 < n; i += 2) {
        uint16_t u = be ? (static_cast<uint16_t>(p[i]) << 8 | static_cast<uint16_t>(p[i+1]))
                        : (static_cast<uint16_t>(p[i+1]) << 8 | static_cast<uint16_t>(p[i]));
        if (u >= 0xD800 && u <= 0xDBFF) {
            if (i + 3 >= n) { out.push_back(0xFFFD); break; }
            uint16_t v = be ? (static_cast<uint16_t>(p[i+2]) << 8 | static_cast<uint16_t>(p[i+3]))
                            : (static_cast<uint16_t>(p[i+3]) << 8 | static_cast<uint16_t>(p[i+2]));
            if (v < 0xDC00 || v > 0xDFFF) { out.push_back(0xFFFD); i += 2; continue; }
            uint32_t cp = 0x10000 + (((u - 0xD800) << 10) | (v - 0xDC00));
            out.push_back(cp); i += 2;
        } else if (u >= 0xDC00 && u <= 0xDFFF) {
            out.push_back(0xFFFD);
        } else {
            out.push_back(u);
        }
    }
    return out;
}

/**
 * Decodes UTF‑32LE/BE into Unicode code points; invalid scalars become U+FFFD.
 */
static std::u32string decode_utf32(const unsigned char* p, size_t n, bool be) {
    std::u32string out;
    if (n % 4) n -= n % 4;
    for (size_t i = 0; i + 3 < n; i += 4) {
        uint32_t cp = be ? (static_cast<uint32_t>(p[i])   << 24 |
                            static_cast<uint32_t>(p[i+1]) << 16 |
                            static_cast<uint32_t>(p[i+2]) << 8  |
                            static_cast<uint32_t>(p[i+3]))
                         : (static_cast<uint32_t>(p[i+3]) << 24 |
                            static_cast<uint32_t>(p[i+2]) << 16 |
                            static_cast<uint32_t>(p[i+1]) << 8  |
                            static_cast<uint32_t>(p[i]));
        if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) cp = 0xFFFD;
        out.push_back(cp);
    }
    return out;
}

/**
 * Decodes a single‑byte text using the specified mapping table.
 */
static std::u32string decode_single_byte(const unsigned char* p, size_t n, SingleByte t) {
    std::u32string out; out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        unsigned char b = p[i];
        if (b < 0x80) out.push_back(b);
        else {
            uint16_t cp = 0xFFFD;
            switch (t) {
                case SingleByte::CP1251:    cp = CP1251_TABLE[b-0x80]; break;
                case SingleByte::KOI8R:     cp = KOI8R_TABLE[b-0x80]; break;
                case SingleByte::ISO8859_5: cp = ISO8859_5_TABLE[b-0x80]; break;
                case SingleByte::MACCYR:    cp = MACCYR_TABLE[b-0x80]; break;
            }
            if (cp == 0x0000) cp = 0xFFFD; // undefined -> replacement
            out.push_back(cp);
        }
    }
    return out;
}

/**
 * Encodes a UTF‑32 (code‑point) sequence into UTF‑8.
 */
static std::string u32_to_utf8(const std::u32string &u32) {
    std::string out; out.reserve(u32.size()*2);
    for (uint32_t cp : u32) append_utf8(out, cp);
    return out;
}

// -------------------- Scoring --------------------
/**
 * Heuristic scorer to prefer plausible human text: rewards ASCII, punctuation,
 * and Cyrillic letters; penalizes control chars and replacement characters.
 *
 * @return Average per‑code‑point score (higher is better).
 */
static double score_u32_text(const std::u32string &u) {
    if (u.empty()) return 0.0;
    size_t total = u.size();
    size_t cyr = 0, good = 0, bad = 0;
    for (uint32_t cp : u) {
        if (cp == 0x0000) { bad += 3; continue; }
        if (cp < 0x20 && cp != 0x09 && cp != 0x0A && cp != 0x0D) { bad += 2; continue; }
        if (cp >= 0x0400 && cp <= 0x04FF) { cyr++; good++; continue; }
        if ((cp >= 0x0020 && cp <= 0x007E) || cp==0x00A0 || cp==0x2116) { good++; continue; }
        if (cp == 0xFFFD) { bad += 2; continue; }
        if ((cp >= 0x2000 && cp <= 0x206F) || (cp >= 0x20 && cp <= 0x7E)) good++;
    }
    double score = static_cast<double>(good) - static_cast<double>(bad) + 1.5 * static_cast<double>(cyr);
    return score / static_cast<double>(total);
}

// -------------------- Internal buffer-based detection --------------------
/**
 * Determines the best guess for the encoding of a byte buffer.
 */
static std::string DetectEncodingFromBuffer(const std::vector<unsigned char>& bytes) {
    if (bytes.empty()) return "UTF-8";

    if (auto bom = detect_bom(bytes)) return bom->name;

    if (looks_like_utf32_le(bytes)) return "UTF-32LE";
    if (looks_like_utf32_be(bytes)) return "UTF-32BE";
    if (looks_like_utf16_le(bytes)) return "UTF-16LE";
    if (looks_like_utf16_be(bytes)) return "UTF-16BE";

    if (is_valid_utf8(bytes.data(), bytes.size())) return "UTF-8";

    struct Cand { const char* name; SingleByte t; } cands[] = {
        {"WINDOWS-1251", SingleByte::CP1251},
        {"KOI8-R",       SingleByte::KOI8R},
        {"ISO-8859-5",   SingleByte::ISO8859_5},
        {"MACCYRILLIC",  SingleByte::MACCYR}
    };
    double bestScore = -1e9; const char* bestName = "WINDOWS-1251";
    for (auto &c : cands) {
        auto u = decode_single_byte(bytes.data(), bytes.size(), c.t);
        double s = score_u32_text(u);
        if (s > bestScore) { bestScore = s; bestName = c.name; }
    }
    return bestName;
}

// -------------------- Public API --------------------
std::string DetectEncoding(const std::string &path) {
    auto bytes = read_file_bytes(path);
    return DetectEncodingFromBuffer(bytes);
}

std::string ConvertBufferToUtf8(const std::vector<unsigned char>& bytes, std::string* detected_out) {
    if (bytes.empty()) { if (detected_out) *detected_out = "UTF-8"; return std::string(); }

    auto bom = detect_bom(bytes);
    std::string encname;
    size_t off = 0;
    if (bom) { encname = bom->name; off = bom->size; }
    else encname = DetectEncodingFromBuffer(bytes);

    const unsigned char* p = bytes.data() + off;
    size_t n = bytes.size() - off;

    std::string out;
    if (encname == "UTF-8") {
        if (!is_valid_utf8(p, n)) {
            auto u = decode_single_byte(p, n, SingleByte::CP1251);
            out = u32_to_utf8(u);
            encname = "WINDOWS-1251";
        } else {
            out.assign(reinterpret_cast<const char*>(p), n);
        }
    } else if (encname == "UTF-16LE") {
        auto u = decode_utf16(p, n, /*be=*/false); out = u32_to_utf8(u);
    } else if (encname == "UTF-16BE") {
        auto u = decode_utf16(p, n, /*be=*/true);  out = u32_to_utf8(u);
    } else if (encname == "UTF-32LE") {
        auto u = decode_utf32(p, n, /*be=*/false); out = u32_to_utf8(u);
    } else if (encname == "UTF-32BE") {
        auto u = decode_utf32(p, n, /*be=*/true);  out = u32_to_utf8(u);
    } else if (encname == "WINDOWS-1251") {
        auto u = decode_single_byte(p, n, SingleByte::CP1251); out = u32_to_utf8(u);
    } else if (encname == "KOI8-R") {
        auto u = decode_single_byte(p, n, SingleByte::KOI8R); out = u32_to_utf8(u);
    } else if (encname == "ISO-8859-5") {
        auto u = decode_single_byte(p, n, SingleByte::ISO8859_5); out = u32_to_utf8(u);
    } else if (encname == "MACCYRILLIC") {
        auto u = decode_single_byte(p, n, SingleByte::MACCYR); out = u32_to_utf8(u);
    } else {
        auto u = decode_single_byte(p, n, SingleByte::CP1251); out = u32_to_utf8(u);
        encname = "WINDOWS-1251";
    }

    if (detected_out) *detected_out = encname;
    return out;
}

std::string ConvertFileToUtf8(const std::string &path, std::string* detected_out) {
    auto bytes = read_file_bytes(path);
    return ConvertBufferToUtf8(bytes, detected_out);
}

void ConvertFileToUtf8To(const std::string& input_path, const std::string& output_path, std::string* detected_out) {
    std::string utf8 = ConvertFileToUtf8(input_path, detected_out);
    std::ofstream out(output_path, std::ios::binary);
    if (!out) throw std::runtime_error("Cannot open output file: " + output_path);
    out.write(utf8.data(), static_cast<std::streamsize>(utf8.size()));
}

void ConvertFileToUtf8Inplace(const std::string& path, std::string* detected_out) {
    namespace fs = std::filesystem;
    fs::path p(path);
    fs::path tmp = p;
    tmp += ".utf8.tmp";

    // 1) Convert
    std::string utf8 = ConvertFileToUtf8(path, detected_out);

    // 2) Write into a temp file in the same directory
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("Cannot open temp file: " + tmp.string());
        out.write(utf8.data(), static_cast<std::streamsize>(utf8.size()));
        out.flush();
        if (!out) throw std::runtime_error("Write failed for temp file: " + tmp.string());
    }

    // 3) Atomic-ish replacement: try rename; if it fails, remove original then retry.
    std::error_code ec;
    fs::rename(tmp, p, ec);
    if (ec) {
        // Try removing original and renaming again
        fs::remove(p, ec);
        fs::rename(tmp, p, ec);
        if (ec) {
            // Clean temp and report error
            std::error_code ec2; fs::remove(tmp, ec2);
            throw std::runtime_error(std::string("Failed to replace file: ") + p.string() + ", reason: " + ec.message());
        }
    }
}

} // namespace enc

