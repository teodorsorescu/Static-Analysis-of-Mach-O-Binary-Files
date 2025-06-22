#include "signparse.h"

#include <cstring>
#include <iostream>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <fstream>

static uint32_t convertBigToHostEndian(uint32_t value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap32(value);
#else
    return value;
#endif
}

static uint64_t convertBigToHostEndian(uint64_t value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(value);
#else
    return value;
#endif
}

template<typename T>
std::string formatAsHex(T value, const int width = 0, const bool showPrefix = true) {
    std::ostringstream oss;
    if (showPrefix) {
        oss << "0x";
    }
    if (width > 0) {
        oss << std::setfill('0') << std::setw(width);
    }
    oss << std::hex << value;
    return oss.str();
}

std::optional<CS_GenericBlob> readGenericBlobHeader(std::span<const uint8_t> dataSpan, size_t offset) {
    if (offset + sizeof(CS_GenericBlob) > dataSpan.size()) {
        return std::nullopt;
    }
    CS_GenericBlob header;
    memcpy(&header, dataSpan.data() + offset, sizeof(CS_GenericBlob));
    return header;
}

std::string extractNullTerminatedString(std::span<const uint8_t> dataSpan, size_t offset, size_t maxLength = std::string::npos) {
    if (offset >= dataSpan.size()) {
        return "(offset out of bounds)";
    }
    std::span<const uint8_t> subSpan = dataSpan.subspan(offset);

    if (subSpan.empty()) {
        return offset == dataSpan.size() ? "(empty string at end of data)" : "(empty subspan for string)";
    }

    const char* ptr = reinterpret_cast<const char*>(subSpan.data());
    auto nullTerminatorIt = std::ranges::find(subSpan, '\0');
    size_t stringLength = static_cast<size_t>(std::distance(subSpan.begin(), nullTerminatorIt));

    if (maxLength != std::string::npos) {
        stringLength = std::min(stringLength, maxLength);
    }
    return std::string(ptr, stringLength);
}


std::string hashTypeToString(CsHashType hashType) {
    switch (hashType) {
        case CsHashType::SHA1: return "SHA-1";
        case CsHashType::SHA256: return "SHA-256";
        case CsHashType::SHA256_TRUNCATED: return "SHA-256 (Truncated)";
        case CsHashType::SHA384: return "SHA-384";
        default: return std::format("UnknownHash ({})", static_cast<int>(hashType));
    }
}


void printBlobDetail(const std::string& blobName,
                       uint32_t actualBlobMagic, uint32_t actualBlobLength,
                       uint32_t expectedMagicIfKnown = 0) {
    std::cout << std::format("  {:<20} (Length: {:<5}, Magic: {})",
                             blobName, actualBlobLength, formatAsHex(actualBlobMagic));
    if (expectedMagicIfKnown != 0 && actualBlobMagic != expectedMagicIfKnown) {
        std::cout << std::format(" WARNING: Expected Magic {}", formatAsHex(expectedMagicIfKnown));
    }
    std::cout << "\n";
}

void parseSingleRequirementExpression(const std::string& indentPrefix,
                                      uint32_t requirementTypeRaw,
                                      uint32_t expressionOffsetInParentPayload,
                                      size_t expressionDataLength) {
    std::cout << std::format("  {}{} (Offset: {}, Length: {} bytes)\n",
                             indentPrefix,
                             std::format("Type {}", requirementTypeRaw),
                             expressionOffsetInParentPayload,
                             expressionDataLength);
    std::cout << "...\n";
}


void parseRequirements(std::span<const uint8_t> requirementsPayloadData,
                       uint32_t outerBlobMagic,
                       uint32_t totalRequirementsBlobLength) {
    printBlobDetail("Requirement Set", outerBlobMagic, totalRequirementsBlobLength, CSMAGIC_REQUIREMENTS);
    if (requirementsPayloadData.size() < sizeof(uint32_t)) {
        std::cout << "    (Payload too small for count).\n";
        return;
    }
    uint32_t count = convertBigToHostEndian(*reinterpret_cast<const uint32_t*>(requirementsPayloadData.data()));
    std::cout << std::format("    Count: {}\n", count);
    if (count == 0) {
        return;
    }

    size_t expectedReqInternalsTotalSize = count * sizeof(CS_ReqInternal);
    if (requirementsPayloadData.size() < sizeof(uint32_t) + expectedReqInternalsTotalSize) {
        std::cout << "    (Data too small for declared requirement count and entries)\n"; return;
    }
    size_t currentCsReqInternalOffset = sizeof(uint32_t);
    for (uint32_t i = 0; i < count; ++i) {
        CS_ReqInternal reqInternalEntry;
        memcpy(&reqInternalEntry, requirementsPayloadData.data() + currentCsReqInternalOffset, sizeof(CS_ReqInternal));
        uint32_t expressionTypeRaw = convertBigToHostEndian(reqInternalEntry.type);
        uint32_t expressionOffsetFromPayloadStart = convertBigToHostEndian(reqInternalEntry.offset);
        size_t expressionLength = 0;
        if (expressionOffsetFromPayloadStart < requirementsPayloadData.size()) {
            if (i + 1 < count) {
                CS_ReqInternal nextReqInternalEntry;
                memcpy(&nextReqInternalEntry, requirementsPayloadData.data() + currentCsReqInternalOffset + sizeof(CS_ReqInternal), sizeof(CS_ReqInternal));
                uint32_t nextExpressionOffset = convertBigToHostEndian(nextReqInternalEntry.offset);
                if (nextExpressionOffset > expressionOffsetFromPayloadStart && nextExpressionOffset <= requirementsPayloadData.size()) {
                    expressionLength = nextExpressionOffset - expressionOffsetFromPayloadStart;
                } else { expressionLength = requirementsPayloadData.size() - expressionOffsetFromPayloadStart; }
            } else { expressionLength = requirementsPayloadData.size() - expressionOffsetFromPayloadStart; }
        }

        if (expressionOffsetFromPayloadStart > 0 && expressionLength > 0 && expressionOffsetFromPayloadStart + expressionLength <= requirementsPayloadData.size()) {
            parseSingleRequirementExpression(std::format("  Req[{}]: ", i), expressionTypeRaw, expressionOffsetFromPayloadStart, expressionLength);
        } else {
            std::cout << std::format("    Req[{}]: Invalid data offset ({}) or calculated length ({}).\n", i, expressionOffsetFromPayloadStart, expressionLength);
        }
        currentCsReqInternalOffset += sizeof(CS_ReqInternal);
    }
}


void parseCmsSignature(uint32_t totalBlobLength, uint32_t actualBlobMagic) {
    printBlobDetail("Blob Wrapper (CMS)", actualBlobMagic, totalBlobLength, CSMAGIC_BLOBWRAPPER);
    std::cout << "...\n";
}

void parseCodeDirectory(std::span<const uint8_t> cdPayloadData,
                        uint32_t actualBlobMagic,
                        uint32_t totalCdBlobLength) {
    printBlobDetail("Code Directory", actualBlobMagic, totalCdBlobLength, CSMAGIC_CODEDIRECTORY);

    constexpr size_t cdGenericHeaderSize = sizeof(CS_GenericBlob);

    if (cdPayloadData.size() < CS_CODEDIRECTORYFIELDS_FIXED_SIZE) {
        std::cout << "    Payload too small for Code Directory base fields.\n";
        return;
    }

    CsCodeDirectoryFixedFields cdFixedPart;
    memcpy(&cdFixedPart, cdPayloadData.data(), CS_CODEDIRECTORYFIELDS_FIXED_SIZE);

    // Convert fields from big-endian
    uint32_t version       = convertBigToHostEndian(cdFixedPart.version);
    uint32_t flags         = convertBigToHostEndian(cdFixedPart.flags);
    uint32_t hashOffset    = convertBigToHostEndian(cdFixedPart.hashOffset);
    uint32_t identOffset   = convertBigToHostEndian(cdFixedPart.identOffset);
    uint32_t nSpecialSlots = convertBigToHostEndian(cdFixedPart.nSpecialSlots);
    uint32_t nCodeSlots    = convertBigToHostEndian(cdFixedPart.nCodeSlots);
    uint32_t codeLimit     = convertBigToHostEndian(cdFixedPart.codeLimit);
    uint8_t platformByte   = cdFixedPart.platform;

    std::cout << std::format("    Version:          {}\n", (formatAsHex(version)));
    std::cout << std::format("    Flags:            {}\n", (flags == 0 ? "none" : formatAsHex(flags)));
    std::cout << std::format("    Platform:         {}\n", static_cast<int>(platformByte));
    std::cout << std::format("    CodeLimit:        {}\n", formatAsHex(codeLimit));

    if (identOffset > 0 && identOffset >= cdGenericHeaderSize) {
        size_t effectiveIdentOffsetInPayload = identOffset - cdGenericHeaderSize;
        if (effectiveIdentOffsetInPayload < cdPayloadData.size()) {
            std::cout << std::format("    Identifier:       {} (@{})\n",
                                     extractNullTerminatedString(cdPayloadData, effectiveIdentOffsetInPayload),
                                     formatAsHex(identOffset));
        } else { std::cout << std::format("    Identifier:       (offset {} invalid for payload)\n", identOffset); }
    } else {
        std::cout << "    Identifier:       (none)\n";
    }

    size_t currentOffsetAfterFixedFields = CS_CODEDIRECTORYFIELDS_FIXED_SIZE;

    if (version >= CS_SUPPORTSSCATTER) {
        currentOffsetAfterFixedFields += sizeof(uint32_t);
    }

    if (version >= CS_SUPPORTSTEAMID) {
        if (cdPayloadData.size() >= currentOffsetAfterFixedFields + sizeof(uint32_t)) {
            uint32_t teamIdOffsetStoredInCd = convertBigToHostEndian(
                *reinterpret_cast<const uint32_t*>(cdPayloadData.data() + currentOffsetAfterFixedFields)
            );
            if (teamIdOffsetStoredInCd > 0 && teamIdOffsetStoredInCd >= cdGenericHeaderSize) {
                size_t effectiveTeamIdOffsetInPayload = teamIdOffsetStoredInCd - cdGenericHeaderSize;
                if (effectiveTeamIdOffsetInPayload < cdPayloadData.size()) {
                    std::cout << std::format("    TeamID:           {}\n",
                                             extractNullTerminatedString(cdPayloadData, effectiveTeamIdOffsetInPayload));
                } else { std::cout << std::format("    TeamID:           (offset {} invalid for payload)\n", teamIdOffsetStoredInCd); }
            } else if (teamIdOffsetStoredInCd > 0) {
                 std::cout << std::format("    TeamID:           (offset {} invalid, points within CD GenericBlob header)\n", teamIdOffsetStoredInCd);
            }
        } else { std::cout << "    TeamID:           (data too short for teamOffset field)\n"; }
        currentOffsetAfterFixedFields += sizeof(uint32_t);
    }

    if (version >= CS_SUPPORTSCODELIMIT64) {
        currentOffsetAfterFixedFields += sizeof(uint32_t); // spare3
        currentOffsetAfterFixedFields += sizeof(uint64_t); // codeLimit64
    }

    if (version >= CS_SUPPORTSEXECSEG) {
        if (cdPayloadData.size() >= currentOffsetAfterFixedFields + (3 * sizeof(uint64_t))) {
            uint64_t execSegBase  = convertBigToHostEndian(*reinterpret_cast<const uint64_t*>(cdPayloadData.data() + currentOffsetAfterFixedFields + 0));
            uint64_t execSegLimit = convertBigToHostEndian(*reinterpret_cast<const uint64_t*>(cdPayloadData.data() + currentOffsetAfterFixedFields + 8));
            uint64_t execSegFlags = convertBigToHostEndian(*reinterpret_cast<const uint64_t*>(cdPayloadData.data() + currentOffsetAfterFixedFields + 16));
            std::cout << std::format("    Exec Segment:     Base {} Limit {} Flags {}\n",
                                     formatAsHex(execSegBase),
                                     formatAsHex(execSegLimit, 8),
                                     formatAsHex(execSegFlags, 8));
        } else { std::cout << std::format("    Exec Segment:     (data too short for version {})\n", formatAsHex(version)); }
    }

    uint32_t pageSizeValue = (cdFixedPart.pageSize > 0 ? (1 << cdFixedPart.pageSize) : 0);
    std::string pageSizeString = std::to_string(pageSizeValue);

    std::cout << std::format("    Hash Slots:       {} code ({} pages) + {} special\n",
                             nCodeSlots, pageSizeString, nSpecialSlots);
    std::cout << std::format("    Hashes Info:      Offset {}, Size {}, Type {}\n",
                             hashOffset,
                             static_cast<int>(cdFixedPart.hashSize),
                             hashTypeToString(static_cast<CsHashType>(cdFixedPart.hashType)));
}

void parseXmlEntitlements(std::span<const uint8_t> payloadData,
                         uint32_t actualBlobMagic,
                         uint32_t actualBlobLength) {
    printBlobDetail("Entitlements (XML)", actualBlobMagic, actualBlobLength);

    if (payloadData.empty()) {
        std::cout << "    (Empty XML entitlements payload)\n";
        return;
    }

    std::string xmlContent(reinterpret_cast<const char*>(payloadData.data()),
                          payloadData.size());

    xmlContent.erase(xmlContent.find_last_not_of('\0') + 1);

    std::cout << "    XML Content:\n";
    std::cout << xmlContent << "\n";
}

void parseDerEntitlements(std::span<const uint8_t> payloadData,
                         uint32_t actualBlobMagic,
                         uint32_t actualBlobLength) {
    printBlobDetail("Entitlements (DER)", actualBlobMagic, actualBlobLength);

    if (payloadData.empty()) {
        std::cout << "    (Empty DER entitlements payload)\n";
        return;
    }

    std::cout << std::format("    DER Data ({} bytes):\n", payloadData.size());

    // Print as hex dump
    const size_t bytesPerLine = 16;
    for (size_t i = 0; i < payloadData.size(); i += bytesPerLine) {
        std::cout << std::format("    {:08x}: ", i);

        for (size_t j = 0; j < bytesPerLine && i + j < payloadData.size(); ++j) {
            std::cout << std::format("{:02x} ", payloadData[i + j]);
        }

        for (size_t j = payloadData.size() - i; j < bytesPerLine && j > 0; ++j) {
            std::cout << "   ";
        }

        std::cout << " |";

        for (size_t j = 0; j < bytesPerLine && i + j < payloadData.size(); ++j) {
            uint8_t byte = payloadData[i + j];
            std::cout << (std::isprint(byte) ? static_cast<char>(byte) : '.');
        }

        std::cout << "|\n";
    }
}

void parseSuperBlob(std::span<const uint8_t> data) {
    if (data.size() < sizeof(CsSuperBlobHeader)) {
        std::cerr << "Error: Data too small for SuperBlob header.\n";
        return;
    }
    CsSuperBlobHeader sbHeader;
    memcpy(&sbHeader, data.data(), sizeof(CsSuperBlobHeader));

    uint32_t magic = convertBigToHostEndian(sbHeader.magic);
    uint32_t totalLength = convertBigToHostEndian(sbHeader.length);
    uint32_t count = convertBigToHostEndian(sbHeader.count);

    if (magic != CSMAGIC_EMBEDDED_SIGNATURE) {
        std::cerr << std::format("Error: Invalid SuperBlob magic {}. Expected {}.\n",
                                 formatAsHex(magic), formatAsHex(CSMAGIC_EMBEDDED_SIGNATURE));
        return;
    }

    std::cout << std::format("SuperBlob (Magic: {}, Length: {}, Blobs: {})\n",
                             formatAsHex(magic), totalLength, count);

    size_t currentIndexArrayOffset = sizeof(CsSuperBlobHeader);
    for (uint32_t i = 0; i < count; ++i) {
        if (currentIndexArrayOffset + sizeof(CS_BlobIndex) > totalLength) {
            std::cerr << std::format("  Error: Not enough data in SuperBlob for blob index entry {}.\n", i);
            return;
        }
        CS_BlobIndex blobIndexEntry;
        memcpy(&blobIndexEntry, data.data() + currentIndexArrayOffset, sizeof(CS_BlobIndex));

        uint32_t blobTypeFromIndex = convertBigToHostEndian(blobIndexEntry.type);
        uint32_t blobOffsetFromSuperBlobStart = convertBigToHostEndian(blobIndexEntry.offset);

        std::cout << std::format("\nBlob Index [{}]: TypeSlot {} (@{})\n",
                                 i, formatAsHex(blobTypeFromIndex), blobOffsetFromSuperBlobStart);

        std::optional<CS_GenericBlob> genericHeaderOpt = readGenericBlobHeader(data, blobOffsetFromSuperBlobStart);
        if (!genericHeaderOpt) {
            std::cerr << "  Error: Failed to read CS_GenericBlob header. Skipping.\n";
            currentIndexArrayOffset += sizeof(CS_BlobIndex);
            continue;
        }

        CS_GenericBlob genericHeader = *genericHeaderOpt;
        uint32_t actualBlobMagic = convertBigToHostEndian(genericHeader.magic);
        uint32_t actualBlobLength = convertBigToHostEndian(genericHeader.length);

        if (actualBlobLength < sizeof(CS_GenericBlob)) {
            std::cerr << std::format("  Error: Blob effective length {} too small for its CS_GenericBlob header. Skipping.\n", actualBlobLength);
            currentIndexArrayOffset += sizeof(CS_BlobIndex);
            continue;
        }

        std::span<const uint8_t> individualBlobPayload(
            data.data() + blobOffsetFromSuperBlobStart + sizeof(CS_GenericBlob),
            actualBlobLength - sizeof(CS_GenericBlob)
        );

        switch (blobTypeFromIndex) {
            case CSSLOT_CODEDIRECTORY:
                parseCodeDirectory(individualBlobPayload, actualBlobMagic, actualBlobLength);
                break;
            case CSSLOT_REQUIREMENTS:
                parseRequirements(individualBlobPayload, actualBlobMagic, actualBlobLength);
                break;
            case CSSLOT_SIGNATURESLOT:
                parseCmsSignature(actualBlobLength, actualBlobMagic);
                break;
            case CSSLOT_ENTITLEMENTS:
                parseXmlEntitlements(individualBlobPayload, actualBlobMagic, actualBlobLength);
                break;
            case CSSLOT_DER_ENTITLEMENTS:
                parseDerEntitlements(individualBlobPayload, actualBlobMagic, actualBlobLength);
                break;
            default:
                printBlobDetail(std::format("Other Blob (Type {})", blobTypeFromIndex), actualBlobMagic, actualBlobLength);
                if (blobTypeFromIndex == CSSLOT_INFOSLOT) std::cout << "    Type: Info.plist\n";
                else if (blobTypeFromIndex == CSSLOT_RESOURCEDIR) std::cout << "    Type: Resource Directory\n";
                else if (blobTypeFromIndex == CSSLOT_APPLICATION) std::cout << "    Type: Application Specific\n";
                else std::cout << "    Type: Unknown or Unhandled Slot\n";
                std::cout << "...\n";
                break;
        }
        currentIndexArrayOffset += sizeof(CS_BlobIndex);
    }
}