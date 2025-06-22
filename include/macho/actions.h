#ifndef ACTIONS_H
#define ACTIONS_H

#include <LIEF/LIEF.hpp>

void printMachoInfo(std::unique_ptr<LIEF::MachO::FatBinary> fat);
void printMachoLoadCommands(std::unique_ptr<LIEF::MachO::Binary> bin);
void convertMachoAddressToOffset(std::unique_ptr<LIEF::MachO::Binary> bin, std::string virtualAddress);
void convertMachoOffsetToAddress(std::unique_ptr<LIEF::MachO::Binary> bin, std::string fileOffset);
void printMachoSymbols(std::unique_ptr<LIEF::MachO::Binary> bin);
void printMachoCodeSignature(std::unique_ptr<LIEF::MachO::Binary> bin);

#endif //ACTIONS_H
