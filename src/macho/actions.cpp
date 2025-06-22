#include "macho/actions.h"

#include <iostream>

#include <string>

#include "utils.h"

#include "signparse.h"

void printMachoInfo(std::unique_ptr<LIEF::MachO::FatBinary> fat) {
    std::cout << std::format("========================================");

    size_t sliceIndex = 1;
    for (const LIEF::MachO::Binary& bin : *fat) {
        const LIEF::MachO::Header& header = bin.header();
        std::cout << std::format("\n--- Mach-O Slice #{:<3} ---\n", sliceIndex++);

        std::string architectureString = LIEF::to_string(LIEF::Header::from(bin).architecture());
        std::cout << std::format("{:<20} : {}\n", "Architecture", architectureString);
        std::cout << std::format("Header Details:\n");
        std::cout << std::format("  {:<18} : 0x{:08X} ({})\n",
                                 "Magic",
                                 static_cast<uint32_t>(header.magic()),
                                 LIEF::MachO::to_string(header.magic()));
        std::cout << std::format("  {:<18} : 0x{:08X} ({})\n",
                                 "CPU Type",
                                 static_cast<uint32_t>(header.cpu_type()),
                                 LIEF::MachO::to_string(header.cpu_type()));

        std::cout << std::format("  {:<18} : 0x{:08X}\n",
                                 "CPU Subtype",
                                 header.cpu_subtype());

        auto fileType = LIEF::MachO::to_string(header.file_type());
       if (static_cast<uint64_t>(header.file_type()) == 12) { // TODO: Make a PR for lief for that.
            fileType = "MH_FILESET";
       }
        std::cout << std::format("  {:<18} : 0x{:08X} ({})\n",
                                 "File Type",
                                 static_cast<uint32_t>(header.file_type()),
                                 fileType
                                 );

        std::cout << std::format("  {:<18} : {}\n",
                                 "Number Load Commands",
                                 header.nb_cmds());

        std::cout << std::format("  {:<18} : {} bytes\n",
                                 "Size of Load Commands",
                                 header.sizeof_cmds());

        std::string flagsDescriptionString;
        const auto& headerFlagsList = header.flags_list();
        if (!headerFlagsList.empty()) {
            for (size_t i = 0; i < headerFlagsList.size(); ++i) {
                flagsDescriptionString += LIEF::MachO::to_string(headerFlagsList[i]);
                if (i < headerFlagsList.size() - 1) {
                    flagsDescriptionString += " | ";
                }
            }
        } else {
            flagsDescriptionString = "NONE";
        }
        std::cout << std::format("  {:<18} : 0x{:08X} ({})\n",
                                 "Flags",
                                 header.flags(),
                                 flagsDescriptionString);

        std::cout << std::format("----------------------------------------");
    }
    std::cout << std::format("\n========================================");
}

void printMachoLoadCommands(std::unique_ptr<LIEF::MachO::Binary> bin) {
    const auto& commands = bin->commands();
    size_t numCommands = commands.size();

    std::cout << std::format("=================================================\n");
    std::cout << std::format("Found {} load command(s).\n", numCommands);

    if (numCommands == 0) {
        std::cout << std::format("No load commands to display.\n");
        std::cout << std::format("=================================================\n");
        return;
    }

    size_t loadCommandIndex = 0;
    for (const LIEF::MachO::LoadCommand& lc : commands) {
        std::cout << std::format("\n--- Load Command #{:<3} ---\n", loadCommandIndex++);
        std::cout << std::format("  {:<20} : {}\n", "Type", LIEF::MachO::to_string(lc.command()));

        if (LIEF::MachO::SegmentCommand::classof(&lc)) {
            if (const LIEF::MachO::SegmentCommand* segmentCommand = lc.cast<LIEF::MachO::SegmentCommand>()) {
                std::cout << std::format("  Segment Details:\n");
                std::cout << std::format("    {:<18} : \"{}\"\n", "Name", segmentCommand->name());
                std::cout << std::format("    {:<18} : 0x{:016X}\n", "Virtual Address", segmentCommand->virtual_address());
                std::cout << std::format("    {:<18} : {} bytes\n", "Virtual Size", segmentCommand->virtual_size());
                std::cout << std::format("    {:<18} : {}\n", "File Offset", segmentCommand->file_offset());
                std::cout << std::format("    {:<18} : {} bytes\n", "File Size", segmentCommand->file_size());


                const auto& sections = segmentCommand->sections();
                size_t numSections = sections.size();
                std::cout << std::format("    {:<18} : {} section(s)\n", "Sections", numSections);

                if (numSections > 0) {
                    size_t sectionIndex = 0;
                    for (const LIEF::MachO::Section& section : sections) {
                        std::cout << std::format("      --- Section #{:<2} ---\n", sectionIndex++);
                        std::cout << std::format("        {:<16} : \"{}\"\n", "Name", section.name());
                        std::cout << std::format("        {:<16} : {} bytes\n", "Size", section.size());
                        std::cout << std::format("        {:<16} : 0x{:08X} ({})\n", "Type", static_cast<uint32_t>(section.type()), LIEF::MachO::to_string(section.type()));
                        std::string sectionFlagsString;
                        const auto& sectionFlagsList = section.flags_list();
                        if (!sectionFlagsList.empty()) {
                            for (size_t i = 0; i < sectionFlagsList.size(); ++i) {
                                sectionFlagsString += LIEF::MachO::to_string(sectionFlagsList[i]);
                                if (i < sectionFlagsList.size() - 1) {
                                    sectionFlagsString += " | ";
                                }
                            }
                        } else {
                            sectionFlagsString = "NONE";
                        }
                        std::cout << std::format("        {:<16} : {}\n", "Flags", sectionFlagsString);
                    }
                }
            }
        } else if (LIEF::MachO::DylibCommand::classof(&lc)) {
            const auto* dylibCommand = lc.cast<LIEF::MachO::DylibCommand>();
            if (dylibCommand) {
                std::cout << std::format("  Dylib Details:\n");
                std::cout << std::format("    {:<18} : \"{}\"\n", "Name", dylibCommand->name());
            }
            std::cout << std::format("-------------------------------------------------\n");
        } else if (LIEF::MachO::FilesetCommand::classof(&lc)) {
            if (const auto* filesetCommand = lc.cast<LIEF::MachO::FilesetCommand>()) {
                std::cout << std::format("  Fileset Name: {}\n", filesetCommand->name());
            }
        }
        std::cout << std::format("\n=================================================\n");
    }
}

void convertMachoAddressToOffset(std::unique_ptr<LIEF::MachO::Binary> bin, std::string virtualAddress) {
    std::cout << std::format("========================================\n");
    std::cout << std::format("Input Virtual Address: {}\n", virtualAddress);

    if (!virtualAddress.starts_with("0x") && !virtualAddress.starts_with("0X")) {
        std::cerr << std::format("Error: Address '{}' must start with '0x' or '0X'.\n", virtualAddress);
        std::cout << std::format("========================================\n");
        std::exit(1);
    }

    std::string hexStringPart = virtualAddress.substr(2);

    uint64_t virtualAddressValue = 0;
    if (!Utils::stringToU64Base16(hexStringPart, virtualAddressValue)) {
        std::cerr << std::format("Error: Invalid Virtual Address '{}'\n", hexStringPart);
        std::cout << std::format("========================================\n");
        std::exit(1);
    }

    const LIEF::MachO::Section* section = bin->section_from_virtual_address(virtualAddressValue);

    if (!section) {
        std::cerr << std::format("Error: No section found containing virtual address 0x{:016X}.\n", virtualAddressValue);
        std::cout << std::format("========================================\n");
        std::exit(1);
    }

    const LIEF::MachO::SegmentCommand* segment = section->segment();

    uint64_t offsetInSection = virtualAddressValue - section->virtual_address();
    uint64_t fileOffsetValue = section->offset() + offsetInSection;

    std::cout << std::format("\n--- Location Details ---\n");
    std::cout << std::format("Segment Information:\n");
    std::cout << std::format("  {:<20} : \"{}\"\n", "Name", segment->name());
    std::cout << std::format("  {:<20} : 0x{:016X}\n", "Virtual Start", segment->virtual_address());
    std::cout << std::format("  {:<20} : 0x{:016X}\n", "Virtual End", segment->virtual_address() + segment->virtual_size() -1);
    std::cout << std::format("  {:<20} : {} bytes\n", "Virtual Size", segment->virtual_size());
    std::cout << std::format("  {:<20} : 0x{:0X}\n", "File Offset", segment->file_offset());
    std::cout << std::format("  {:<20} : {} bytes\n", "File Size", segment->file_size());

    std::cout << std::format("\nSection Information:\n");
    std::cout << std::format("  {:<20} : \"{}\"\n", "Name", section->name());
    std::cout << std::format("  {:<20} : 0x{:016X}\n", "Virtual Start", section->virtual_address());
    std::cout << std::format("  {:<20} : 0x{:016X}\n", "Virtual End", section->virtual_address() + section->size() -1);
    std::cout << std::format("  {:<20} : {} bytes\n", "Size", section->size());
    std::cout << std::format("  {:<20} : 0x{:0X}\n", "File Offset", section->offset());


    std::cout << std::format("\n--- Conversion Result ---\n");
    std::cout << std::format("Input Virtual Address: 0x{:016X}\n", virtualAddressValue);
    std::cout << std::format("Belongs to Segment   : \"{}\", Section: \"{}\"\n", segment->name(), section->name());
    std::cout << std::format("Calculated File Offset: 0x{:0X}\n", fileOffsetValue);
    std::cout << std::format("========================================\n");

}

void convertMachoOffsetToAddress(std::unique_ptr<LIEF::MachO::Binary> bin, std::string fileOffset) {
    std::cout << std::format("========================================\n");
    std::cout << std::format("Input File Offset: {}\n", fileOffset);

    if (!fileOffset.starts_with("0x") && !fileOffset.starts_with("0X")) {
        std::cerr << std::format("Error: Offset '{}' must start with '0x' or '0X'.\n", fileOffset);
        std::cout << std::format("========================================\n");
        std::exit(1);
    }

    std::string hexStringPart = fileOffset.substr(2);;

    uint64_t inputFileOffsetValue = 0;
    if (!Utils::stringToU64Base16(hexStringPart, inputFileOffsetValue)) {
        std::cerr << std::format("Error: Invalid Offset '{}'\n", hexStringPart);
        std::cout << std::format("========================================\n");
        std::exit(1);
    }


    const LIEF::MachO::Section* section = bin->section_from_offset(inputFileOffsetValue);


    if (!section) {
        std::cerr << std::format("Error: No section found containing offset address 0x{:016X}.\n", inputFileOffsetValue);
        std::cout << std::format("========================================\n");
        std::exit(1);
    }

    const LIEF::MachO::SegmentCommand* segment = section->segment();

    uint64_t offsetInSectionContent = inputFileOffsetValue - section->offset();
    uint64_t virtualAddressValue = section->virtual_address() + offsetInSectionContent;

    std::cout << std::format("\n--- Location Details ---\n");
    std::cout << std::format("Segment Information:\n");
    std::cout << std::format("  {:<20} : \"{}\"\n", "Name", segment->name());
    std::cout << std::format("  {:<20} : 0x{:016X}\n", "Virtual Start", segment->virtual_address());
    std::cout << std::format("  {:<20} : 0x{:016X}\n", "Virtual End", segment->virtual_address() + segment->virtual_size() - (segment->virtual_size() > 0 ? 1:0));
    std::cout << std::format("  {:<20} : {} bytes\n", "Virtual Size", segment->virtual_size());
    std::cout << std::format("  {:<20} : 0x{:X}\n", "File Offset", segment->file_offset());
    std::cout << std::format("  {:<20} : {} bytes\n", "File Size", segment->file_size());

    std::cout << std::format("\nSection Information (Containing Offset):\n");
    std::cout << std::format("  {:<20} : \"{}\"\n", "Name", section->name());
    std::cout << std::format("  {:<20} : 0x{:016X}\n", "Virtual Start", section->virtual_address());
    std::cout << std::format("  {:<20} : 0x{:016X}\n", "Virtual End", section->virtual_address() + section->size() - (section->size() > 0 ? 1:0));
    std::cout << std::format("  {:<20} : {} bytes\n", "Size (in file)", section->size());
    std::cout << std::format("  {:<20} : 0x{:X}\n", "File Offset", section->offset());


    std::cout << std::format("\n--- Conversion Result ---\n");
    std::cout << std::format("Input File Offset     : 0x{:X} ({})\n", inputFileOffsetValue, inputFileOffsetValue);
    std::cout << std::format("Belongs to Segment    : \"{}\", Section: \"{}\"\n", segment->name(), section->name());
    std::cout << std::format("Calculated Virtual Address: 0x{:016X}\n", virtualAddressValue);
    std::cout << std::format("========================================\n");
}

void printMachoSymbols(std::unique_ptr<LIEF::MachO::Binary> bin) {
    for (const LIEF::MachO::Symbol &sym : bin->symbols()) {
        std::cout << sym.name() << "\n";
    }
    for (const LIEF::MachO::Symbol &sym : bin->imported_symbols()) {
            std::cout << sym.name() << " (from " << sym.library()->name() << ")" << "\n";
    }

    for (const LIEF::MachO::Symbol &sym : bin->exported_symbols()) {
        std::cout << sym.name() << " (exported)" << "\n";
    }
}

void printMachoCodeSignature(std::unique_ptr<LIEF::MachO::Binary> bin) {
    if (bin && bin->code_signature()) {
        parseSuperBlob(bin->code_signature()->content());
    } else {
        std::cerr << "Binary or code signature missing in printMachoCodeSignature.\n";
    }
}
