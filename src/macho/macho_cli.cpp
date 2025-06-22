#include "macho/macho_cli.h"
#include "macho/actions.h"
#include "utils.h"

void registerMachoCommands(CLI::App &app, std::filesystem::path &file,
                           std::optional<std::string> &arch,
                           std::string &extraString) {
    auto m = app.add_subcommand("macho", "Analyze Mach-O files");
    // TODO: add functionality so you can call macho file and it will print the info


    // m->add_option("--arch", arch, "Slice architecture (only for fat)");

    // Ensure every macho subcommand starts by verifying the file is a Mach-O
    auto ensureMacho = [](const std::filesystem::path &file) {
        try {
            Utils::ensureMachoFile(file);
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
            std::exit(1);
        }
    };

    auto getSliceOrExit = [](const std::filesystem::path &file,
                             const std::optional<std::string> &arch) -> std::unique_ptr<LIEF::MachO::Binary> {
        auto fat = Utils::getFatFromFile(file); // TODO: This can be optimised probably
        if (!Utils::isFat(file) || fat->size() == 1) {
            const auto thinArchString = LIEF::to_string(LIEF::Header::from(*fat->at(0)).architecture());
            if (arch) {
                if (arch != thinArchString) {
                    std::cerr << "Error: architecture '" << arch.value()
                            << "' does not match thin binary architecture '"
                            << thinArchString << "'." << std::endl;
                    std::exit(1);
                } else {
                    std::cerr << "Warning: --arch='" << arch.value()
                            << "' is redundant for thin binary; using '"
                            << thinArchString << "'." << std::endl;
                }
            }
            auto slice = fat->take(0);
            return slice;
        } else {
            // fat
            const auto fatArchStrings = Utils::getArchesAsStrings(*fat);
            if (!arch) {
                std::cerr << "Error: fat binary detected; run with --arch <arch>. Available:" << std::endl;
                for (auto &a: fatArchStrings) {
                    std::cerr << "  - " << a << std::endl;
                };
                std::exit(1);
            }
            auto slice = Utils::getSliceFromArch(std::move(fat), arch.value());
            if (!slice) {
                std::cerr << "Error: arch '" << arch.value() << "' not found. Available:" << std::endl;
                for (auto &a: fatArchStrings) {
                    std::cerr << "  - " << a << std::endl;
                };
                std::exit(1);
            }
            return slice;
        }
    };

    auto info_subcommand = m->add_subcommand("info", "General info");

    info_subcommand->add_option("file", file, "Path to Mach-O file")
            ->required()
            ->check(CLI::ExistingFile);

    info_subcommand->callback([&]() {
        ensureMacho(file);
        try {
            auto fat = Utils::getFatFromFile(file);
            printMachoInfo(std::move(fat));
        } catch (const std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
            std::exit(1);
        }
    });

    auto addSliceCmd = [&](const char *name, auto &&fn) {
        auto cmd = m->add_subcommand(name, name);
        cmd->add_option("file", file, "Path to Mach-O file")->required()->check(CLI::ExistingFile);
        cmd->add_option("--arch", arch, "Slice architecture (only for fat)");
        cmd->callback([&, fn]() {
            ensureMacho(file);
            try {
                std::unique_ptr<LIEF::MachO::Binary> slice = getSliceOrExit(file, arch);
                fn(std::move(slice));
            } catch (const std::exception &e) {
                std::cerr << "Error: " << e.what() << std::endl;
                std::exit(1);
            }
        });
    };

    auto addSliceExtraStringCmd = [&](const char *name, auto &&fn) {
        auto cmd = m->add_subcommand(name, name);
        cmd->add_option("file", file, "Path to Mach-O file")->required()->check(CLI::ExistingFile);
        cmd->add_option("--arch", arch, "Slice architecture (only for fat)");
        cmd->add_option("address", extraString, "Virtual address (e.g. 0x100000420)")->required();
        cmd->callback([&, fn]() {
            ensureMacho(file);
            try {
                std::unique_ptr<LIEF::MachO::Binary> slice = getSliceOrExit(file, arch);
                fn(std::move(slice), extraString);
            } catch (const std::exception &e) {
                std::cerr << "Error: " << e.what() << std::endl;
                std::exit(1);
            }
        });
    };

    addSliceCmd("lc", printMachoLoadCommands);
    addSliceCmd("syms", printMachoSymbols);
    addSliceCmd("cs", printMachoCodeSignature);

    addSliceExtraStringCmd("a2o", convertMachoAddressToOffset);
    addSliceExtraStringCmd("o2a", convertMachoOffsetToAddress);
}
