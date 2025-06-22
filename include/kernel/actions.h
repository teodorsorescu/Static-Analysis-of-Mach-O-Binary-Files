#ifndef ACTIONS_H
#define ACTIONS_H
#include <filesystem>
#include <LIEF/LIEF.hpp>


void listKernelCachesInIpsw(std::filesystem::path zipPath);
void extractKernelCacheFromIpsw(std::filesystem::path zipPath, std::string kcToExtract);
void unwrapKernelCache(std::filesystem::path kcPath, std::string whereTo);
void decompressKernelCache(std::filesystem::path kcPath, std::string whereTo);
void extractKextsFromKernelCache(std::unique_ptr<LIEF::MachO::Binary> kcBin);
void getDarwinVersionFromKernelCache(std::unique_ptr<LIEF::MachO::Binary> kcBin);
void dumpMachTrapsFromKernelCache(std::unique_ptr<LIEF::MachO::Binary> kcBin);
void dumpSyscallsFromKernelCache(std::unique_ptr<LIEF::MachO::Binary> kcBin);

#endif //ACTIONS_H
