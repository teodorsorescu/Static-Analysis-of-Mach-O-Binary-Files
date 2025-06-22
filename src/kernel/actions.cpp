#include "kernel/actions.h"
#include <iostream>
#include <fstream>
#include "mz.h"
#include "mz_strm_os.h"
#include "mz_zip.h"
#include "utils.h"
#include <lzfse.h>


void listKernelCachesInIpsw(std::filesystem::path zipPath) {
    std::vector<std::string> entries;

    void *stream = mz_stream_os_create();
    if (!stream) {
        throw std::runtime_error("Failed to create OS stream");
    }

    int32_t errorCode = mz_stream_os_open(stream, zipPath.string().c_str(), MZ_OPEN_MODE_READ);
    if (errorCode != MZ_OK) {
        mz_stream_os_delete(&stream);
        throw std::runtime_error("Failed to open zip file: " + zipPath.string());
    }

    void *zipHandle = mz_zip_create();
    if (!zipHandle) {
        mz_stream_os_close(stream);
        mz_stream_os_delete(&stream);
        throw std::runtime_error("Failed to create zip handle");
    }

    errorCode = mz_zip_open(zipHandle, stream, MZ_OPEN_MODE_READ);
    if (errorCode != MZ_OK) {
        mz_zip_delete(&zipHandle);
        mz_stream_os_close(stream);
        mz_stream_os_delete(&stream);
        throw std::runtime_error("Failed to open zip archive");
    }

    errorCode = mz_zip_goto_first_entry(zipHandle);
    while (errorCode == MZ_OK) {
        mz_zip_file *fileInfo = nullptr;
        if (mz_zip_entry_get_info(zipHandle, &fileInfo) != MZ_OK) {
            break;
        }
        // Collect filename (UTF-8)
        if (fileInfo && fileInfo->filename) {
            entries.emplace_back(fileInfo->filename);
        }

        errorCode = mz_zip_goto_next_entry(zipHandle);
    }

    std::erase_if(entries, [](const std::string &entry) -> bool {
        return !entry.starts_with("kernelcache.");
    });

    for (auto entry: entries) {
        std::cout << entry << std::endl;
    }

    mz_zip_close(zipHandle);
    mz_zip_delete(&zipHandle);
    mz_stream_os_close(stream);
    mz_stream_os_delete(&stream);
}

void extractKernelCacheFromIpsw(std::filesystem::path zipPath, std::string kcToExtract) {
    std::filesystem::path outPath = std::filesystem::current_path() / kcToExtract;
    if (outPath.has_parent_path()) {
        std::filesystem::create_directories(outPath.parent_path());
    }

    void *stream = mz_stream_os_create();
    if (!stream) throw std::runtime_error("Failed to create OS stream");
    if (mz_stream_os_open(stream, zipPath.string().c_str(), MZ_OPEN_MODE_READ) != MZ_OK) {
        mz_stream_os_delete(&stream);
        throw std::runtime_error("Cannot open ZIP file: " + zipPath.string());
    }

    void *zipHandle = mz_zip_create();
    if (!zipHandle) {
        mz_stream_os_close(stream);
        mz_stream_os_delete(&stream);
        throw std::runtime_error("Failed to create ZIP handle");
    }
    if (mz_zip_open(zipHandle, stream, MZ_OPEN_MODE_READ) != MZ_OK) {
        mz_zip_delete(&zipHandle);
        mz_stream_os_close(stream);
        mz_stream_os_delete(&stream);
        throw std::runtime_error("Cannot open archive for reading");
    }

    int32_t errorCode = mz_zip_locate_entry(zipHandle, kcToExtract.c_str(), 0);
    if (errorCode != MZ_OK) {
        mz_zip_close(zipHandle);
        mz_zip_delete(&zipHandle);
        mz_stream_os_close(stream);
        mz_stream_os_delete(&stream);
        throw std::runtime_error("Entry not found: " + kcToExtract);
    }

    if (mz_zip_entry_read_open(zipHandle, 0, nullptr) != MZ_OK) {
        mz_zip_close(zipHandle);
        mz_zip_delete(&zipHandle);
        mz_stream_os_close(stream);
        mz_stream_os_delete(&stream);
        throw std::runtime_error("Failed to open entry for reading");
    }

    if (std::filesystem::exists(outPath)) {
        mz_zip_entry_close(zipHandle);
        mz_zip_close(zipHandle);
        mz_zip_delete(&zipHandle);
        mz_stream_os_close(stream);
        mz_stream_os_delete(&stream);
        throw std::runtime_error("Refusing to overwrite existing file: " + outPath.string());
    }

    std::ofstream out(outPath, std::ios::binary);
    if (!out.is_open()) {
        mz_zip_entry_close(zipHandle);
        mz_zip_close(zipHandle);
        mz_zip_delete(&zipHandle);
        mz_stream_os_close(stream);
        mz_stream_os_delete(&stream);
        throw std::runtime_error("Cannot open output file: " + outPath.string());
    }

    // 6) Read and write
    constexpr size_t BUF_SIZE = 4096;
    std::vector<char> buffer(BUF_SIZE);
    int32_t bytesRead;
    while ((bytesRead = mz_zip_entry_read(zipHandle, buffer.data(), static_cast<int32_t>(buffer.size()))) > 0) {
        out.write(buffer.data(), bytesRead);
        if (!out) {
            throw std::runtime_error("Write error to: " + outPath.string());
        }
    }
    if (bytesRead < 0) {
        throw std::runtime_error("Error reading entry: " + kcToExtract);
    }

    out.close();
    mz_zip_entry_close(zipHandle);
    mz_zip_close(zipHandle);
    mz_zip_delete(&zipHandle);
    mz_stream_os_close(stream);
    mz_stream_os_delete(&stream);

    std::cout << "Extracted '" << kcToExtract << "' to '" << outPath.string() << "'\n";
}

void unwrapKernelCache(std::filesystem::path kernelCachePath, std::string whereTo) {
    const std::string im4pMagicString = "IM4P";
    const std::vector<char> bvx2MagicSequence = {'b', 'v', 'x', '2'};

    auto outPath = std::filesystem::path(whereTo);

    if (std::filesystem::exists(outPath)) {
        throw std::runtime_error("Output file already exists. Will not overwrite: " + outPath.string());
    }

    std::ifstream inputStream(kernelCachePath, std::ios::binary | std::ios::ate);
    if (!inputStream.is_open()) {
        throw std::runtime_error("Could not open input file: " + kernelCachePath.string());
    }

    std::streamsize fileSize = inputStream.tellg();
    if (fileSize == 0) {
        inputStream.close();
        throw std::runtime_error("Input file is empty: " + kernelCachePath.string());
    }
    inputStream.seekg(0, std::ios::beg);

    std::vector<char> buffer(static_cast<size_t>(fileSize));
    if (!inputStream.read(buffer.data(), fileSize)) {
        inputStream.close();
        throw std::runtime_error("Could not read input file content: " + kernelCachePath.string());
    }
    inputStream.close();

    auto im4pStartIterator = std::ranges::search(buffer, im4pMagicString).begin();

    if (im4pStartIterator == buffer.end()) {
        throw std::runtime_error("'IM4P' magic sequence not found in the file.");
    }

    auto bvx2SearchStartIterator = im4pStartIterator + im4pMagicString.length();
    if (bvx2SearchStartIterator >= buffer.end()) {
        throw std::runtime_error("No data found after 'IM4P' magic sequence to search for 'bvx2'.");
    }

    auto bvx2StartIterator = std::search(bvx2SearchStartIterator,
                                   buffer.end(),
                                   bvx2MagicSequence.begin(),
                                   bvx2MagicSequence.end());

    if (bvx2StartIterator == buffer.end()) {
        throw std::runtime_error("'bvx2' magic sequence not found after 'IM4P' magic sequence in the file.");
    }

    std::ofstream outputFileStream(outPath, std::ios::binary);

    if (!outputFileStream.is_open()) {
        throw std::runtime_error("Could not open output file for writing: " + outPath.string());
    }

    size_t bytesToWrite = static_cast<size_t>(std::distance(bvx2StartIterator, buffer.end()));
    outputFileStream.write(&(*bvx2StartIterator), static_cast<std::streamsize>(bytesToWrite));

    if (!outputFileStream) {
        outputFileStream.close();
        std::filesystem::remove(outPath);
        throw std::runtime_error("Could not write all data to output file: " + outPath.string());
    }

    outputFileStream.close();
    if (outputFileStream.fail()) {
        std::filesystem::remove(outPath);
        throw std::runtime_error("Failed to properly close the output file: " + outPath.string());
    }

    std::cout << "Unwrapped '" << kernelCachePath << "' to '" << outPath.string() << "'\n";
}

void decompressKernelCache(std::filesystem::path kernelCachePath, std::string whereTo) {
    auto outPath = std::filesystem::path(whereTo);

    if (std::filesystem::exists(outPath)) {
        throw std::runtime_error("Output file already exists. Will not overwrite: " + outPath.string());
    }

    std::ifstream inputFile(kernelCachePath, std::ios::binary | std::ios::ate);
    if (!inputFile) {
        throw std::runtime_error("failed: cannot open input file: " + kernelCachePath.string());
    }

    auto compressedSize = inputFile.tellg();
    if (compressedSize <= 0) {
        throw std::runtime_error("failed: input file is empty or invalid: " + kernelCachePath.string());
    }

    inputFile.seekg(0, std::ios::beg);
    std::vector<uint8_t> compressedData(compressedSize);

    if (!inputFile.read(reinterpret_cast<char *>(compressedData.data()), compressedSize)) {
        throw std::runtime_error("failed: cannot read input file: " + kernelCachePath.string());
    }
    inputFile.close();

    size_t scratchSize = lzfse_decode_scratch_size();
    std::unique_ptr<uint8_t[]> scratchBuffer;
    if (scratchSize > 0) {
        scratchBuffer = std::make_unique<uint8_t[]>(scratchSize);
    }

    size_t decompressedSize = static_cast<size_t>(compressedSize) * 4;
    std::vector<uint8_t> decompressedData;
    size_t actualSize = 0;

    constexpr size_t maxAttempts = 5;
    for (size_t attempt = 0; attempt < maxAttempts; ++attempt) {
        decompressedData.resize(decompressedSize);

        actualSize = lzfse_decode_buffer(
            decompressedData.data(),
            decompressedSize,
            compressedData.data(),
            static_cast<size_t>(compressedSize),
            scratchBuffer.get()
        );

        if (actualSize == 0) {
            throw std::runtime_error("failed: decompression failed - invalid or corrupted LZFSE data");
        }

        if (actualSize < decompressedSize) {
            break;
        }

        if (attempt == maxAttempts - 1) {
            throw std::runtime_error("failed: decompressed data too large, exceeded maximum buffer size");
        }

        decompressedSize *= 2;
    }

    decompressedData.resize(actualSize);

    std::ofstream outputFile(outPath, std::ios::binary);
    if (!outputFile) {
        throw std::runtime_error("failed: cannot create output file: " + outPath.string());
    }

    if (!outputFile.write(reinterpret_cast<const char *>(decompressedData.data()),
                          static_cast<std::streamsize>(actualSize))) {
        throw std::runtime_error("failed: cannot write to output file: " + outPath.string());
    }

    outputFile.close();

    if (!std::filesystem::exists(outPath)) {
        throw std::runtime_error("failed: output file was not created: " + outPath.string());
    }

    auto outputSize = std::filesystem::file_size(outPath);
    if (outputSize != actualSize) {
        throw std::runtime_error(
            "failed: output file size mismatch - expected " + std::to_string(actualSize) + " bytes, got " +
            std::to_string(outputSize) + " bytes");
    }

    std::cout << "Decompressed '" << kernelCachePath << "' to '" << outPath.string() << "'\n";
}

void extractKextsFromKernelCache(std::unique_ptr<LIEF::MachO::Binary> kernelCacheBinary) {
    auto fileSets = kernelCacheBinary->filesets();
    if (fileSets.empty()) {
        throw std::runtime_error("no filesets present");
    }

    for (auto &fc: fileSets) {
        std::cout << std::format("  Will extract: {}\n", fc.fileset_name());
        std::filesystem::path outPath = std::filesystem::current_path() / "extracted/";
        if (!std::filesystem::exists(outPath)) {
            std::filesystem::create_directories(outPath);
            std::cout << "Created directory: " << outPath << "\n";
        }
        fc.write(outPath.string() + fc.fileset_name());
        std::cout << std::format("  Extracted: {} to {}\n", fc.fileset_name(), outPath.string());
    }
}

void getDarwinVersionFromKernelCache(std::unique_ptr<LIEF::MachO::Binary> kernelCacheBinary) {
    for (auto &fileset: kernelCacheBinary->filesets()) {
        if (fileset.fileset_name() == "com.apple.kernel") {
            auto constSection = fileset.get_section("__TEXT", "__const");
            Utils::findDarwinVersion(constSection->content());
        }
    }
}

void dumpMachTrapsFromKernelCache(std::unique_ptr<LIEF::MachO::Binary> kernelCacheBinary) {
    struct MachTrapT {
        uint8_t argCount;
        uint8_t u32Words;
        uint8_t returnsPort;
        uint8_t padding[5];
        uint64_t function;
        uint64_t argMunge32;
    };
   constexpr size_t MACH_TRAP_TABLE_COUNT = 128;

    auto dataConstSection = kernelCacheBinary->get_section("__DATA_CONST", "__const");

    if (!dataConstSection) {
        throw std::runtime_error("Failed to find __DATA_CONST __const section");
    }
    auto x = dataConstSection->alignment();
    auto y = dataConstSection->virtual_address();

    std::cout << std::endl << std::hex << y << std::endl;

    auto sectionData = dataConstSection->content();

    uint64_t kernelInvalidAddress = 0;
    size_t pos = 0;
    while (pos + 5 * sizeof(uint64_t) <= sectionData.size()) {
        const uint64_t* ptr = reinterpret_cast<const uint64_t*>(sectionData.data() + pos);

        uint64_t zero1 = ptr[0];
        uint64_t kernel_invalid = ptr[1];
        uint64_t zero2 = ptr[2];
        uint64_t zero3 = ptr[3];
        uint64_t match = ptr[4];

        if (zero1 == 0 && kernel_invalid != 0 && zero2 == 0 && zero3 == 0 && match == kernel_invalid) {
            kernelInvalidAddress = kernel_invalid;
            break;
        }
        pos += sizeof(uint64_t);
    }

    if (kernelInvalidAddress == 0) {
        throw std::runtime_error("Failed to find kernel_invalid address using pattern matching");
    }


    size_t tableOffset = 0;
    pos = 0;
    while (pos + sizeof(uint64_t) <= sectionData.size()) {
        const uint64_t* ptr = reinterpret_cast<const uint64_t*>(sectionData.data() + pos);

        if (*ptr == kernelInvalidAddress) {
            if (pos >= 8) {
                tableOffset = pos - 8;
                break;
            }
        }
        pos += sizeof(uint64_t);
    }

    if (tableOffset == 0) {
        throw std::runtime_error("Failed to find mach trap table location");
    }

    uint64_t machTrapTableAddress = dataConstSection->virtual_address() + tableOffset;

    std::cout << "Found mach_trap_table=0x" << std::hex << machTrapTableAddress << std::endl;

    for (size_t i = 0; i < MACH_TRAP_TABLE_COUNT; ++i) {
        size_t entryOffset = tableOffset + i * sizeof(MachTrapT);
        const MachTrapT* trapPointer = reinterpret_cast<const MachTrapT*>(sectionData.data() + entryOffset);

        MachTrapT trapData = *trapPointer;

        std::cout << std::dec << i << "  ";
        std::cout << "0x" << std::hex << std::setfill('0') << std::setw(16) << trapData.function << ": ";

        if (trapData.function == kernelInvalidAddress) {
            std::cout << "kern_invalid";
        } else if (trapData.function == 0) {
            std::cout << "<unused>";
        } else {
            std::cout << "<unknown>";

            if (trapData.argMunge32 != 0 || trapData.argCount != 0 || trapData.returnsPort != 0) {
                std::cout << std::setfill(' ') << std::setw(30 - 9) << " "; // Adjust spacing for "<unknown>"
                std::cout << "munge=0x" << std::hex << std::setfill('0') << std::setw(16) << trapData.argMunge32;
                std::cout << " nargs=" << std::dec << static_cast<int>(trapData.argCount);
                std::cout << " ret_port=" << static_cast<int>(trapData.returnsPort);
                std::cout << " <unknown>(...)";
            }
        }
        std::cout << std::endl;
    }
}

void dumpSyscallsFromKernelCache(std::unique_ptr<LIEF::MachO::Binary> kernelCacheBinary) {
    constexpr std::array<uint8_t, 20> SIG1 = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00
    };

    constexpr std::array<uint8_t, 16> SIG1_SUF = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00
    };

    constexpr std::array<uint8_t, 8> SIG1_IOS8X = {
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00
    };

    bool is64Bit = true;

    std::cout << "Searching for syscall table and names in kernelcache...\n";

    auto readMemoryAtAddress = [&](uint64_t addr, size_t size) -> std::vector<uint8_t> {
        std::vector<uint8_t> result;
        for (const auto& segment : kernelCacheBinary->segments()) {
            if (addr >= segment.virtual_address() &&
                addr < segment.virtual_address() + segment.virtual_size()) {
                uint64_t offsetInSegment = addr - segment.virtual_address();
                auto segmentContent = segment.content();
                if (offsetInSegment + size <= segmentContent.size()) {
                    result.assign(segmentContent.begin() + offsetInSegment,
                                segmentContent.begin() + offsetInSegment + size);
                }
                break;
            }
        }
        return result;
    };

    std::vector<std::string> syscallNames;

    auto cStringSection = kernelCacheBinary->get_section("__TEXT", "__cstring");
    if (cStringSection) {
        auto content = cStringSection->content();

        const char syscallPattern[] = "syscall\0exit";
        auto it = std::search(content.begin(), content.end(),
                             std::begin(syscallPattern), std::end(syscallPattern) - 1);

        if (it != content.end()) {
            size_t offset = std::distance(content.begin(), it);
            std::cout << std::format("Found syscall names at offset: 0x{:x}\n", offset);

            const char* stringData = reinterpret_cast<const char*>(content.data() + offset);
            size_t remaining = content.size() - offset;

            for (size_t i = 0; i < 600 && i * 20 < remaining; ) { // reasonable limit
                size_t stringLength = strnlen(stringData, remaining);
                if (stringLength == 0 || stringLength >= remaining) break;

                syscallNames.emplace_back(stringData);
                stringData += stringLength + 1;
                remaining -= stringLength + 1;

                if (syscallNames.back().length() > 2 &&
                    syscallNames.back().find_first_not_of("abcdefghijklmnopqrstuvwxyz_0123456789") == std::string::npos) {
                    i++;
                }
            }
        }
    }

    auto section = kernelCacheBinary->get_section("__DATA_CONST", "__const");
    if (!section) {
        section = kernelCacheBinary->get_section("__DATA", "__const");
    }
    if (!section) {
        std::cerr << "Could not find __DATA_CONST.__const or __DATA.__const section\n";
        return;
    }

    auto content = section->content();
    if (content.empty()) {
        std::cerr << "Section content is empty\n";
        return;
    }

    std::optional<uint64_t> sysentAddress;
    const size_t dataSize = content.size();

    // heuristic from https://github.com/davidrhodus/misc/blob/master/iOS-internals/jocker.c
    for (size_t i = 0; i < dataSize - 40; ++i) {
        if (i + 40 <= dataSize &&
            memcmp(content.data() + i, SIG1.data(), SIG1.size()) == 0 &&
            memcmp(content.data() + i + 24, SIG1_SUF.data(), SIG1_SUF.size()) == 0) {
            sysentAddress = section->virtual_address() + i - 24;
            break;
        }

        if (i + 24 <= dataSize &&
            memcmp(content.data() + i, SIG1_IOS8X.data(), SIG1_IOS8X.size()) == 0) {
            sysentAddress = section->virtual_address() + i - 16;
            break;
        }
    }

    if (!sysentAddress) {
        std::cerr << "Could not locate syscall table\n";
        return;
    }

    std::cout << std::format("Found syscall table at virtual address: 0x{:x}\n", *sysentAddress);
    std::cout << std::format("Extracted {} syscall names dynamically\n", syscallNames.size());


    constexpr size_t MAX_SYSCALLS = 600;
    size_t entrySize = is64Bit ? 24 : 20;
    size_t totalSize = MAX_SYSCALLS * entrySize;

    auto sysentData = readMemoryAtAddress(*sysentAddress, totalSize);
    if (sysentData.empty()) {
        std::cerr << "Failed to read syscall table data\n";
        return;
    }

    if (syscallNames.empty()) {
        std::cout << "\nSyscall Table:\n";
    } else {
        std::cout << "\nSyscall Table (with dynamically extracted names):\n";
    }
    std::cout << std::format("{:<4} {:<25} {:<18} {:<18} {:<10} {:<6} {:<8}\n",
                            "ID", "Name", "Call Address", "Munge Address", "Return", "Args", "Bytes");
    std::cout << std::string(100, '-') << "\n";


    size_t validEntries = 0;
    for (size_t i = 0; i < MAX_SYSCALLS && (i * entrySize + entrySize) <= sysentData.size(); ++i) {
        size_t offset = i * entrySize;

        uint64_t callAddress = 0;
        uint64_t mungeAddress = 0;
        uint32_t returnType = 0;
        uint16_t numArguments = 0;
        uint16_t argumentBytes = 0;

        if (is64Bit) {
            memcpy(&callAddress, sysentData.data() + offset, 8);
            memcpy(&mungeAddress, sysentData.data() + offset + 8, 8);
            memcpy(&returnType, sysentData.data() + offset + 16, 4);
            memcpy(&numArguments, sysentData.data() + offset + 20, 2);
            memcpy(&argumentBytes, sysentData.data() + offset + 22, 2);
        } else {

        }

        if (callAddress != 0) {
            std::string syscallName;
            if (i < syscallNames.size()) {
                syscallName = syscallNames[i];
            } else {
                syscallName = std::format("syscall_{}", i);
            }

            std::string returnTypeName;
            switch (returnType & 0xFF) {
                case 0:   returnTypeName = "none"; break;
                case 1:   returnTypeName = "int"; break;
                case 2:   returnTypeName = "uint"; break;
                case 3:   returnTypeName = "off_t"; break;
                case 4:   returnTypeName = "addr_t"; break;
                case 5:   returnTypeName = "size_t"; break;
                case 6:   returnTypeName = "ssize_t"; break;
                case 7:   returnTypeName = "uint64_t"; break;
                default:  returnTypeName = std::format("type_{}", returnType & 0xFF); break;
            }

            std::cout << std::format("{:<4} {:<25} 0x{:<16x} 0x{:<16x} {:<10} {:<6} {:<8}\n",
                                    i, syscallName, callAddress,
                                    mungeAddress, returnTypeName, numArguments, argumentBytes);
            validEntries++;
        }
    }

    std::cout << std::format("\nFound {} valid syscall entries\n", validEntries);

    if (!syscallNames.empty()) {
        std::cout << std::format("Successfully extracted {} syscall names from kernel binary\n", syscallNames.size());
    } else {
        std::cout << "No syscall names found - kernel may be stripped or use different layout\n";
    }
}
