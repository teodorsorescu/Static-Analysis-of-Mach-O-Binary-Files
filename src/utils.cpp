#include "utils.h"

#include <LIEF/MachO.hpp>
#include <stdexcept>
#include <unordered_set>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>

namespace Utils {
    void ensureMachoFile(const std::filesystem::path &path) {
        if (!LIEF::MachO::is_macho(path.string()))
            throw std::runtime_error(path.string() + " is not a Mach-O file");
    }

    bool isFat(const std::filesystem::path &path) {
        return LIEF::MachO::is_fat(path.string());
    }

    std::unique_ptr<LIEF::MachO::FatBinary> getFatFromFile(const std::filesystem::path &path) {
        auto fat = LIEF::MachO::Parser::parse(path.string()); // TODO: Check parse config
        if (!fat) {
            throw std::runtime_error("Failed to parse Mach-O: " + path.string());
        }
        return fat;
    }

    std::unordered_set<LIEF::Header::ARCHITECTURES> getArches(const LIEF::MachO::FatBinary &fat) {
        std::unordered_set<LIEF::Header::ARCHITECTURES> arches;
        for (const LIEF::MachO::Binary &bin: fat) {
            arches.emplace(LIEF::Header::from(bin).architecture());
        }
        return arches;
    }

    std::unordered_set<std::string> getArchesAsStrings(const LIEF::MachO::FatBinary &fat) {
        std::unordered_set<std::string> archStrings;
        for (const auto &arch: getArches(fat)) {
            archStrings.emplace(to_string(arch));
        }
        return archStrings;
    }

    std::unique_ptr<LIEF::MachO::Binary> getSliceFromArch(std::unique_ptr<LIEF::MachO::FatBinary> fat,
                                                          const std::string &arch) {
        for (size_t i = 0; i < fat->size(); ++i) {
            const LIEF::MachO::Binary *bin = fat->at(i);
            if (bin && to_string(LIEF::Header::from(*bin).architecture()) == arch) {
                return fat->take(i);
            }
        }
        return nullptr;
    }

    bool stringToU64Base16(const std::string& s, uint64_t& out) {
        try {
            size_t u64 = 0;
            out = std::stoull(s, &u64, 16);
            return (u64 == s.size());
        }
        catch (const std::invalid_argument&) {
            return false;
        }
        catch (const std::out_of_range&) {
            return false;
        }
    }

    void ensureIpswFile(const std::filesystem::path& file) {
        if (file.extension() != ".ipsw") {
            throw std::runtime_error("Error: '" + file.string() + "' does not have a .ipsw extension.");
        }

        std::ifstream in{ file, std::ios::binary };
        if (!in.is_open()) {
            in.open(file.string(), std::ios::binary);
        }
        if (!in.is_open()) {
            throw std::runtime_error("Error: failed to open '" + file.string() + "' for reading.");
        }

        std::array<char, 4> magic{};
        in.read(magic.data(), magic.size());
        if (in.gcount() < static_cast<std::streamsize>(magic.size()) ||
            magic[0] != 'P' ||
            magic[1] != 'K' ||
            static_cast<unsigned char>(magic[2]) != 0x03 ||
            static_cast<unsigned char>(magic[3]) != 0x04)
        {
            throw std::runtime_error("Error: '" + file.string() +
                                     "' is not a valid IPSW/ZIP file (invalid magic bytes).");
        }
    }

    void printAsString(std::span<const uint8_t> data) {
        size_t i = 0;
        for (const auto& byte : data) {
            if (byte >= 32 && byte <= 126) {
                std::cout << static_cast<char>(byte);
                if (i++ % 100 == 0) {
                    std::cout << '\n';
                }
            } else {
                // std::cout << std::format("\\x{:02x}", byte);
            }
        }
        std::cout << '\n';
    }

    void findDarwinVersion(std::span<const uint8_t> data) {
        std::string currentString;

        for (const auto& byte : data) {
            if (byte == 0) {
                if (!currentString.empty()) {
                    if (currentString.find("Darwin Kernel Version") != std::string::npos) {
                        std::cout << std::format("\"{}\"", currentString) << '\n';
                        return;
                    }
                    currentString.clear();
                }
            } else if (byte >= 32 && byte <= 126) {
                currentString += static_cast<char>(byte);
            } else {
                if (!currentString.empty()) {
                    if (currentString.find("Darwin Kernel Version") != std::string::npos) {
                        std::cout << std::format("\"{}\"", currentString) << '\n';
                        return;
                    }
                    currentString.clear();
                }
            }
        }
        if (!currentString.empty() && currentString.find("Darwin Kernel Version") != std::string::npos) {
            std::cout << std::format("\"{}\"", currentString) << '\n';
        }
    }
}
