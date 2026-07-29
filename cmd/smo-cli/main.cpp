#include "cli_application.hpp"
#include "cli_context.hpp"
#include "intent_parser.hpp"

#include <providers/suite1_classical/suite1_classical_provider.hpp>
#ifdef SMO_WITH_PQC
#include <providers/suite3_purepqc/suite3_purepqc_provider.hpp>
#endif

#include <iostream>
#include <cstdlib>
#include <string>

int main(int argc, char* argv[])
{
    smo::providers::register_suite1_classical();
#ifdef SMO_WITH_PQC
    smo::providers::register_suite3_purepqc();
#endif
    smo::CLIApplication app;
    auto init_result = app.initialize("~/.smo");
    if (!init_result)
    {
        std::cerr << "Failed to initialize: " << init_result.error().message << "\n";
        return 1;
    }
    auto result = app.run(argc, argv);
    if (!result)
        return 1;
    return result.value();
}
