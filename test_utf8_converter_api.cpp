#include <cassert>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <vector>
#include "utf8_converter_api.h"

using enc::DetectEncoding;
using enc::ConvertFileToUtf8;
using enc::ConvertBufferToUtf8;
using enc::ConvertFileToUtf8To;
using enc::ConvertFileToUtf8Inplace;

// Utility: write raw bytes to a file (overwrites if exists).
static void write_bytes(const std::string& path, const std::vector<unsigned char>& bytes) {
    std::ofstream out(path, std::ios::binary);
    if (!out) throw std::runtime_error("cannot create file: " + path);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

int main() {
    try {
        // ---- 1) UTF‑8 without BOM ----
        const std::string utf8_text = "Hello, мир!\n"; // UTF‑8 text
        write_bytes("t_utf8.txt", std::vector<unsigned char>(utf8_text.begin(), utf8_text.end()));
        std::string e1 = DetectEncoding("t_utf8.txt");
        assert(e1 == "UTF-8");

        // ---- 2) UTF‑8 with BOM ----
        std::vector<unsigned char> bom_utf8 = {0xEF,0xBB,0xBF};
        bom_utf8.insert(bom_utf8.end(), utf8_text.begin(), utf8_text.end());
        write_bytes("t_utf8_bom.txt", bom_utf8);
        std::string e2 = DetectEncoding("t_utf8_bom.txt");
        assert(e2 == "UTF-8");
        std::string det2; std::string c2 = ConvertFileToUtf8("t_utf8_bom.txt", &det2);
        assert(det2 == "UTF-8");
        assert(c2 == utf8_text.substr(0)); // content without BOM

        // ---- 3) UTF‑16LE with BOM ----
        // Write BOM FF FE and "AB" in UTF‑16LE: 41 00 42 00
        std::vector<unsigned char> u16le = {0xFF,0xFE, 0x41,0x00, 0x42,0x00};
        write_bytes("t_utf16le.txt", u16le);
        std::string e3 = DetectEncoding("t_utf16le.txt");
        assert(e3 == "UTF-16LE");
        std::string det3; std::string c3 = ConvertFileToUtf8("t_utf16le.txt", &det3);
        assert(det3 == "UTF-16LE");
        assert(c3 == std::string("AB"));

        // ---- 4) WINDOWS‑1251 example: word "Привет" ----
        // CP1251 bytes: П(0xCF) р(0xF0) и(0xE8) в(0xE2) е(0xE5) т(0xF2)
        std::vector<unsigned char> cp1251 = {0xCF,0xF0,0xE8,0xE2,0xE5,0xF2};
        write_bytes("t_cp1251.txt", cp1251);
        std::string e4 = DetectEncoding("t_cp1251.txt");
        // The detector should choose a single‑byte Cyrillic; expect WINDOWS‑1251
        assert(e4 == "WINDOWS-1251");
        std::string det4; std::string c4 = ConvertFileToUtf8("t_cp1251.txt", &det4);
        assert(det4 == "WINDOWS-1251");
        assert(c4 == std::string("Привет"));

        // ---- 5) ConvertBufferToUtf8 ----
        std::string det5; std::string c5 = ConvertBufferToUtf8(cp1251, &det5);
        assert(det5 == "WINDOWS-1251");
        assert(c5 == std::string("Привет"));

        // ---- 6) ConvertFileToUtf8To (new file) ----
        ConvertFileToUtf8To("t_cp1251.txt", "t_out_utf8.txt", nullptr);
        std::ifstream check_out("t_out_utf8.txt", std::ios::binary);
        std::string out_str((std::istreambuf_iterator<char>(check_out)), {});
        assert(out_str == std::string("Привет"));

        // ---- 7) ConvertFileToUtf8Inplace (overwrite) ----
        write_bytes("t_inplace_cp1251.txt", cp1251);
        ConvertFileToUtf8Inplace("t_inplace_cp1251.txt", nullptr);
        std::ifstream check_inplace("t_inplace_cp1251.txt", std::ios::binary);
        std::string inpl_str((std::istreambuf_iterator<char>(check_inplace)), {});
        assert(inpl_str == std::string("Привет"));

        // Cleanup (optional)
        std::remove("t_utf8.txt");
        std::remove("t_utf8_bom.txt");
        std::remove("t_utf16le.txt");
        std::remove("t_cp1251.txt");
        std::remove("t_out_utf8.txt");
        std::remove("t_inplace_cp1251.txt");

        std::cout << "All tests passed.\n";
    } catch (const std::exception& e) {
        std::cerr << "Test failed: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

