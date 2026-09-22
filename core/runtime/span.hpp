#pragma once

#include <string>

namespace smo::runtime {

    // Span struct for distributed tracing
    struct Span
    {
        std::string span_id;
        std::string trace_id;
        std::string parent_span_id;
        std::string operation_name;
        int64_t start_ns = 0;
        int64_t end_ns = 0;
        std::string status;
    };

} // namespace smo::runtime
