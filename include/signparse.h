#ifndef SIGNPARSE_H
#define SIGNPARSE_H

#include <string>
#include <vector>
#include <span>

// Magic numbers for different blob types
constexpr uint32_t CSMAGIC_EMBEDDED_SIGNATURE            = 0xfade0cc0;
constexpr uint32_t CSMAGIC_CODEDIRECTORY                 = 0xfade0c02;
constexpr uint32_t CSMAGIC_REQUIREMENT                   = 0xfade0c00; // Single Requirement data
constexpr uint32_t CSMAGIC_REQUIREMENTS                  = 0xfade0c01; // Set of Requirements
constexpr uint32_t CSMAGIC_BLOBWRAPPER                   = 0xfade0b01; // Wraps CMS Signature
constexpr uint32_t CSMAGIC_ENTITLEMENTS                  = 0xfade7171;
constexpr uint32_t CSMAGIC_DER_ENTITLEMENTS              = 0xfade7172;

// CS_CodeDirectory versions indicating feature support
constexpr uint32_t CS_SUPPORTSSCATTER                    = 0x20100;
constexpr uint32_t CS_SUPPORTSTEAMID                     = 0x20200;
constexpr uint32_t CS_SUPPORTSCODELIMIT64                = 0x20300;
constexpr uint32_t CS_SUPPORTSEXECSEG                    = 0x20400;

// Slot types used in the SuperBlob index
constexpr uint32_t CSSLOT_CODEDIRECTORY                  = 0;
constexpr uint32_t CSSLOT_INFOSLOT                       = 1;
constexpr uint32_t CSSLOT_REQUIREMENTS                   = 2;
constexpr uint32_t CSSLOT_RESOURCEDIR                    = 3;
constexpr uint32_t CSSLOT_APPLICATION                    = 4;
constexpr uint32_t CSSLOT_ENTITLEMENTS                   = 5;
constexpr uint32_t CSSLOT_DER_ENTITLEMENTS               = 7;
constexpr uint32_t CSSLOT_SIGNATURESLOT                  = 0x10000;

// CS_CodeDirectory flags (example)
constexpr uint32_t CS_ADHOC                              = 0x00000002;

enum class CsHashType : uint8_t {
    SHA1 = 1,
    SHA256 = 2,
    SHA256_TRUNCATED = 3,
    SHA384 = 4,
    UNKNOWN = 0
};



struct CS_GenericBlob {
    uint32_t magic;
    uint32_t length;
};

struct CS_BlobIndex {
    uint32_t type;
    uint32_t offset;
};


struct CsSuperBlobHeader {
    uint32_t magic;
    uint32_t length;
    uint32_t count;  // Number of CS_BlobIndex entries
};

struct CsCodeDirectoryFixedFields {
    uint32_t version;
    uint32_t flags;
    uint32_t hashOffset;
    uint32_t identOffset;
    uint32_t nSpecialSlots;
    uint32_t nCodeSlots;
    uint32_t codeLimit;
    uint8_t  hashSize;
    uint8_t  hashType;
    uint8_t  platform;
    uint8_t  pageSize;      // log2 of page size (e.g., 12 for 4KB pages)
    uint32_t spare2;        // Must be zero
};


constexpr size_t CS_CODEDIRECTORYFIELDS_FIXED_SIZE = sizeof(CsCodeDirectoryFixedFields);


struct CS_ReqInternal {
    uint32_t type;   // Type of requirement
    uint32_t offset;
};



void parseSuperBlob(std::span<const uint8_t> superBlobData);

std::string hashTypeToString(CsHashType hashType);


#endif //SIGNPARSE_H
