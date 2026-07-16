#include "main.hpp"

#include <iostream>
#include <cstdlib>
#include <string>

int main(int argc, char* argv[]) {
    smo::CLIApplication app;
    
    // Determine data directory
    std::string data_dir = std::getenv("SMO_DATA_DIR");
    if (data_dir.empty()) {
        const char* home = std::getenv("HOME");
        if (home) {
            data_dir = std::string(home) + "/.smo";
        } else {
            data_dir = "/tmp/smo";
        }
    }
    
    auto init_result = app.initialize(std::getenv("SMO_DATA_DIR") ? std::string(std::getenv("SMO_DATA_DIR")) : "");
    if (!init_result) {
        std::cerr << "Initialization failed: " << init_result.error().message << "\n";
        return 1;
    }
    
    return app.run(argc, argv);
}