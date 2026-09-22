#pragma once

#include <core/errors/error.hpp>
#include <core/types.hpp>

#include <string>
#include <functional>
#include <unordered_map>
#include <memory>
#include <thread>
#include <atomic>

namespace smo::observability {

    class HttpServer
    {
    public:
        struct HttpRequest
        {
            std::string method;
            std::string path;
            std::string body;
            std::unordered_map<std::string, std::string> headers;
        };

        struct HttpResponse
        {
            int status_code = 200;
            std::string status_text = "OK";
            std::string content_type = "text/plain";
            std::string body;
            std::unordered_map<std::string, std::string> headers;

            std::string to_string() const;
        };

        using RequestHandler = std::function<void(const HttpRequest&, HttpResponse&)>;

        HttpServer();
        ~HttpServer();

        HttpServer(HttpServer&&) = default;
        HttpServer& operator=(HttpServer&&) = default;

        HttpServer(const HttpServer&) = delete;
        HttpServer& operator=(const HttpServer&) = delete;

        Result<void> start(uint16_t port);
        void stop();
        bool is_running() const;

        void register_handler(const std::string& path, RequestHandler handler);

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };

} // namespace smo::observability