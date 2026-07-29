#pragma once

#include "core/errors/error.hpp"

#include <memory>
#include <string>

namespace smo {

    class CLIApplication
    {
    public:
        CLIApplication();
        ~CLIApplication();

        Result<int> run(int argc, char* argv[]);
        Result<void> initialize(const std::string& data_dir = "~/.smo");

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };

} // namespace smo
