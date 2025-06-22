#ifndef KERNEL_CLI_H
#define KERNEL_CLI_H

#include <CLI11.hpp>

void registerKernelCacheCommands(CLI::App &app, std::filesystem::path &path, std::string &extraString);

#endif //KERNEL_CLI_H
