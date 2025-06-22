#include "kernel/kernel_cli.h"
#include "kernel/actions.h"
#include "utils.h"
#include <iostream>

void registerKernelCacheCommands(CLI::App &app, std::filesystem::path &path, std::string &extraString) {
    auto kc = app.add_subcommand("kc", "kernelcache utils");
    auto listIpswCmd = kc->add_subcommand("listIpsw", "List kernelcaches");
    listIpswCmd
            ->add_option("file", path, "Path to IPSW file")
            ->required()
            ->check(CLI::ExistingFile);
    listIpswCmd->callback([&]() {
        try {
            Utils::ensureIpswFile(path);
            listKernelCachesInIpsw(path);
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
            std::exit(1);
        }
    });


    auto extractKcCmd = kc->add_subcommand("extractKc", "Extract kenelcache");
    extractKcCmd
            ->add_option("file", path, "Path to IPSW file")
            ->required()
            ->check(CLI::ExistingFile);
    extractKcCmd->add_option("kcToExtract", extraString, "the kernelcache to extract")->required();
    extractKcCmd->callback([&]() {
        try {
            Utils::ensureIpswFile(path);
            extractKernelCacheFromIpsw(path, extraString);
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
            std::exit(1);
        }
    });

    auto unwrapKcCmd = kc->add_subcommand("unwrapKc", "Unwrap kenelcache from im4p");
    unwrapKcCmd
            ->add_option("file", path, "path to kc file")
            ->required()
            ->check(CLI::ExistingFile);
    unwrapKcCmd->add_option("whereTo", extraString, "path where to unwrap")->required();
    unwrapKcCmd->callback([&]() {
        try {
            unwrapKernelCache(path, extraString);
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
            std::exit(1);
        }
    });


    auto dcKcCmd = kc->add_subcommand("dcKc", "decompress kc file (that is already unwrapped from img4)");
    dcKcCmd
            ->add_option("file", path, "path to kc file")
            ->required()
            ->check(CLI::ExistingFile);
    dcKcCmd->add_option("whereTo", extraString, "path where to decompress")->required();
    dcKcCmd->callback([&]() {
        try {
            decompressKernelCache(path, extraString);
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
            std::exit(1);
        }
    });

    auto extractKextsCmd = kc->add_subcommand("extractKexts", "Extract kenelcache");
    extractKextsCmd
            ->add_option("file", path, "Path to uncompressed kernelcache file")
            ->required()
            ->check(CLI::ExistingFile);
    extractKextsCmd->callback([&]() {
        try {
            Utils::ensureMachoFile(path);
            auto fat = Utils::getFatFromFile(path);
            if (Utils::isFat(path) || fat->size() > 1) {
                std::cerr << "Mach-O is not thin, probably not a kernelcache";
                std::exit(1);
            }
            auto thin = fat->take(0);
            std::unique_ptr<LIEF::MachO::Binary> bin = std::move(thin);
            extractKextsFromKernelCache(std::move(bin));
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
            std::exit(1);
        }
    });

    auto getVCmd = kc->add_subcommand("getV", "Extract kenelcache");
    getVCmd->add_option("file", path, "Path to uncompressed kernelcache file")
            ->required()
            ->check(CLI::ExistingFile);
    getVCmd->callback([&]() {
        try {
            Utils::ensureMachoFile(path);
            auto fat = Utils::getFatFromFile(path);
            if (Utils::isFat(path) || fat->size() > 1) {
                std::cerr << "Mach-O is not thin, probably not a kernelcache";
                std::exit(1);
            }
            auto thin = fat->take(0);
            std::unique_ptr<LIEF::MachO::Binary> bin = std::move(thin);
            getDarwinVersionFromKernelCache(std::move(bin));
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
            std::exit(1);
        }
    });

    auto mtCmd = kc->add_subcommand("mT", "dump mach traps");
    mtCmd->add_option("file", path, "Path to a com.apple.kernel file")
            ->required()
            ->check(CLI::ExistingFile);
    mtCmd->callback([&]() {
        try {
            Utils::ensureMachoFile(path);
            auto fat = Utils::getFatFromFile(path);
            if (Utils::isFat(path) || fat->size() > 1) {
                std::cerr << "Mach-O is not thin, probably not a kernelcache";
                std::exit(1);
            }
            auto thin = fat->take(0);
            std::unique_ptr<LIEF::MachO::Binary> bin = std::move(thin);
            dumpMachTrapsFromKernelCache(std::move(bin));
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
            std::exit(1);
        }
    });

    auto syscallsCmd = kc->add_subcommand("syscalls", "dump mach syscalls");
    syscallsCmd->add_option("file", path, "Path to com.apple.kernel file")
            ->required()
            ->check(CLI::ExistingFile);
    syscallsCmd->callback([&]() {
        try {
            Utils::ensureMachoFile(path);
            auto fat = Utils::getFatFromFile(path);
            if (Utils::isFat(path) || fat->size() > 1) {
                std::cerr << "Mach-O is not thin, probably not a kernelcache";
                std::exit(1);
            }
            auto thin = fat->take(0);
            std::unique_ptr<LIEF::MachO::Binary> bin = std::move(thin);
            dumpSyscallsFromKernelCache(std::move(bin));
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
            std::exit(1);
        }
    });
}
