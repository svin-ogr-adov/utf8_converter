#pragma once
#include <string>
#include <vector>

namespace enc {

/**
 * Detects the character encoding of a file by inspecting its bytes.
 *
 * Heuristics:
 *  - Respects BOMs for UTF‑8/16/32 when present.
 *  - Attempts to identify UTF‑16/32 without BOM via byte-pattern analysis.
 *  - Validates UTF‑8 sequences; if valid, assumes UTF‑8.
 *  - Otherwise, scores several single‑byte Cyrillic encodings (Windows‑1251,
 *    KOI8‑R, ISO‑8859‑5, MacCyrillic) and returns the best candidate.
 *
 * @param path Path to the file to inspect.
 * @return A canonical encoding name (e.g., "UTF-8", "UTF-16LE", "KOI8-R").
 */
std::string DetectEncoding(const std::string &path);

/**
 * Converts a file to UTF‑8.
 *
 * Behavior mirrors DetectEncoding plus decoding into UTF‑8. If the file has a
 * UTF BOM, it is honored and skipped in output. If no BOM exists, the same
 * heuristics as DetectEncoding are applied. On decoding failure inside an
 * otherwise chosen single‑byte path, replacement characters (U+FFFD) may be
 * produced for undefined code points.
 *
 * @param path Path to the input file.
 * @param detected_out Optional pointer to receive the detected/source encoding name.
 * @return The file contents re‑encoded as UTF‑8.
 */
std::string ConvertFileToUtf8(const std::string &path, std::string* detected_out = nullptr);

/**
 * Converts an in‑memory byte buffer to UTF‑8 using the same logic as
 * ConvertFileToUtf8.
 *
 * @param data Raw bytes of the source text.
 * @param detected_out Optional pointer to receive the detected/source encoding name.
 * @return The buffer content re‑encoded as UTF‑8.
 */
std::string ConvertBufferToUtf8(const std::vector<unsigned char>& data, std::string* detected_out = nullptr);

/**
 * Converts a file to UTF‑8 and atomically replaces the original file on disk.
 *
 * Implementation detail: writes to a temporary file in the same directory and
 * then attempts a rename. If a simple rename fails (e.g., on Windows when
 * replacing an existing file), it deletes the original and retries. Any
 * remaining failure cleans up the temp file and throws.
 *
 * @param path Path to the file to convert in place.
 * @param detected_out Optional pointer to receive the detected/source encoding name.
 * @throws std::runtime_error on I/O failures.
 */
void ConvertFileToUtf8Inplace(const std::string& path, std::string* detected_out = nullptr);

/**
 * Converts a file to UTF‑8 and writes the result to a new file, leaving the
 * source file untouched.
 *
 * @param input_path Path to the source file.
 * @param output_path Path to write the UTF‑8 output.
 * @param detected_out Optional pointer to receive the detected/source encoding name.
 * @throws std::runtime_error if the output file cannot be created.
 */
void ConvertFileToUtf8To(const std::string& input_path, const std::string& output_path, std::string* detected_out = nullptr);

} // namespace enc


