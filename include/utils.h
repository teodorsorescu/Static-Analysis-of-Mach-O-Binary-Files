#ifndef UTILS_H
#define UTILS_H

#include <filesystem>
#include <unordered_set>
#include <LIEF/MachO.hpp>
#include <span>

namespace Utils {
    void ensureMachoFile(const std::filesystem::path& filePath);

    bool isFat(const std::filesystem::path& filePath);

    std::unique_ptr<LIEF::MachO::FatBinary> getFatFromFile(const std::filesystem::path& filePath);

    std::unordered_set<LIEF::Header::ARCHITECTURES> getArches(const LIEF::MachO::FatBinary &fat);

    std::unordered_set<std::string> getArchesAsStrings(const LIEF::MachO::FatBinary &fat);

    std::unique_ptr<LIEF::MachO::Binary> getSliceFromArch(std::unique_ptr<LIEF::MachO::FatBinary> fat, const std::string &arch);

    bool stringToU64Base16(const std::string& hexString, uint64_t& outputValue);

    void ensureIpswFile(const std::filesystem::path& filePath);

    void printAsString(std::span<const uint8_t> data);

    void findDarwinVersion(std::span<const uint8_t> data);
}

#endif //UTILS_H
