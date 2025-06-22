#ifndef MACHO_CLI_H
#define MACHO_CLI_H

#include <CLI11.hpp>

void registerMachoCommands(CLI::App &app, std::filesystem::path &filePath, std::optional<std::string> &arch,
                           std::string &extraString);

#endif //MACHO_CLI_H
