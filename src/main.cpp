#include <CLI11.hpp>

#include <macho/macho_cli.h>
#include <kernel/kernel_cli.h>

int main(int argc, char **argv) {
    CLI::App app{"extrktr: placeholder"}; // TODO: add app description
    std::filesystem::path file;
    std::optional<std::string> arch;
    std::string extraString;

    registerMachoCommands(app, file, arch, extraString);
    registerKernelCacheCommands(app, file, extraString);
    CLI11_PARSE(app, argc, argv);
    return 0;
}
