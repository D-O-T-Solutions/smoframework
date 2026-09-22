#include "http_server.hpp"

#include <core/errors/error.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <vector>

namespace smo::observability {

namespace {

bool recv_all(int fd, std::string& buf, size_t max_len)
{
    char tmp[4096];
    while (buf.size() < max_len)
    {
        ssize_t n = ::recv(fd, tmp, sizeof(tmp), MSG_DONTWAIT);
        if (n > 0)
        {
            buf.append(tmp, static_cast<size_t>(n));
        }
        else if (n == 0)
        {
            return true;
        }
        else if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            break;
        }
        else
        {
            return false;
        }
    }
    return true;
}

bool parse_http_request(const std::string& raw, HttpServer::HttpRequest& req)
{
    auto line_end = raw.find("\r\n");
    if (line_end == std::string::npos)
    {
        return false;
    }

    auto first_space = raw.find(' ');
    if (first_space == std::string::npos || first_space >= line_end)
    {
        return false;
    }
    auto second_space = raw.find(' ', first_space + 1);
    if (second_space == std::string::npos || second_space >= line_end)
    {
        return false;
    }

    req.method = raw.substr(0, first_space);
    req.path = raw.substr(first_space + 1, second_space - first_space - 1);

    size_t header_start = line_end + 2;
    size_t headers_end = raw.find("\r\n\r\n", header_start);
    if (headers_end == std::string::npos)
        return false;

    std::string headers_section = raw.substr(header_start, headers_end - header_start);
    size_t pos = 0;
    while (pos < headers_section.size())
    {
        auto line_end = headers_section.find("\r\n", pos);
        if (line_end == std::string::npos)
            line_end = headers_section.size();
        std::string line = headers_section.substr(pos, line_end - pos);
        auto colon = line.find(':');
        if (colon != std::string::npos)
        {
            std::string key = line.substr(0, colon);
            std::string value = line.substr(colon + 1);
            while (!value.empty() && value[0] == ' ')
                value.erase(0, 1);
            req.headers[key] = value;
        }
        pos = line_end + 2;
    }

    size_t content_length = 0;
    auto cl_it = req.headers.find("Content-Length");
    if (cl_it != req.headers.end())
    {
        content_length = static_cast<size_t>(std::stoll(cl_it->second));
    }

    size_t body_start = headers_end + 4;
    if (body_start < raw.size())
    {
        req.body = raw.substr(body_start);
    }

    if (req.body.size() < content_length)
    {
        return false;
    }

    return true;
}

} // anonymous namespace

std::string HttpServer::HttpResponse::to_string() const
{
    std::ostringstream resp;
    resp << "HTTP/1.1 " << status_code << " " << status_text << "\r\n"
         << "Content-Type: " << content_type << "\r\n"
         << "Content-Length: " << body.size() << "\r\n"
         << "Connection: close\r\n";
    for (const auto& [key, value] : headers)
    {
        resp << key << ": " << value << "\r\n";
    }
    resp << "\r\n" << body;
    return resp.str();
}

class HttpServer::Impl
{
public:
    uint16_t port_ = 0;
    int server_fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::unordered_map<std::string, RequestHandler> handlers_;

    Result<void> start(uint16_t port)
    {
        port_ = port;

        server_fd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (server_fd_ < 0)
        {
            return SMO_ERR_STORAGE(900, Error, RetrySafe, None, "Failed to create HTTP server socket");
        }

        int opt = 1;
        ::setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (::bind(server_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        {
            ::close(server_fd_);
            server_fd_ = -1;
            return SMO_ERR_STORAGE(224, Error, RetrySafe, None,
                                   "Failed to bind HTTP server to port " + std::to_string(port));
        }

        if (::listen(server_fd_, 5) < 0)
        {
            ::close(server_fd_);
            server_fd_ = -1;
            return SMO_ERR_STORAGE(900, Error, RetrySafe, None, "Failed to listen on HTTP server socket");
        }

        running_ = true;
        thread_ = std::thread([this]() { run(); });

        return {};
    }

    void stop()
    {
        running_ = false;
        if (server_fd_ >= 0)
        {
            ::shutdown(server_fd_, SHUT_RDWR);
            ::close(server_fd_);
            server_fd_ = -1;
        }
        if (thread_.joinable())
        {
            thread_.join();
        }
    }

    void register_handler(const std::string& path, RequestHandler handler)
    {
        handlers_[path] = std::move(handler);
    }

private:
    void run()
    {
        std::vector<struct pollfd> fds;
        fds.push_back({server_fd_, POLLIN, 0});

        while (running_)
        {
            int ret = ::poll(fds.data(), fds.size(), 100);
            if (ret < 0)
            {
                if (errno == EINTR)
                    continue;
                break;
            }

            if (fds[0].revents & POLLIN)
            {
                struct sockaddr_in client_addr;
                socklen_t addr_len = sizeof(client_addr);
                int client_fd = ::accept4(server_fd_, (struct sockaddr*)&client_addr, &addr_len, SOCK_NONBLOCK);
                if (client_fd >= 0)
                {
                    handle_client(client_fd);
                }
            }
        }
    }

    void handle_client(int client_fd)
    {
        std::string raw;
        if (!recv_all(client_fd, raw, 65536))
        {
            ::close(client_fd);
            return;
        }

        HttpRequest req;
        HttpResponse resp;

        if (!parse_http_request(raw, req) || raw.find("\r\n\r\n") == std::string::npos)
        {
            struct pollfd pfd = {client_fd, POLLIN, 0};
            while (::poll(&pfd, 1, 5000) > 0 && (pfd.revents & POLLIN))
            {
                if (!recv_all(client_fd, raw, 65536))
                    break;
                if (parse_http_request(raw, req))
                    break;
                pfd.revents = 0;
            }

            if (!parse_http_request(raw, req))
            {
                resp.status_code = 400;
                resp.status_text = "Bad Request";
                resp.content_type = "application/json";
                resp.body = R"({"error":"Invalid HTTP request"})";
                std::string out = resp.to_string();
                ::send(client_fd, out.data(), out.size(), 0);
                ::close(client_fd);
                return;
            }
        }

        auto it = handlers_.find(req.path);
        if (it != handlers_.end())
        {
            it->second(req, resp);
        }
        else
        {
            resp.status_code = 404;
            resp.status_text = "Not Found";
            resp.content_type = "application/json";
            resp.body = R"({"error":"Not found"})";
        }

        std::string out = resp.to_string();
        ::send(client_fd, out.data(), out.size(), 0);
        ::close(client_fd);
    }
};

HttpServer::HttpServer() : impl_(std::make_unique<Impl>()) {}
HttpServer::~HttpServer() { stop(); }

Result<void> HttpServer::start(uint16_t port) { return impl_->start(port); }
void HttpServer::stop() { impl_->stop(); }
bool HttpServer::is_running() const { return impl_->running_.load(); }
void HttpServer::register_handler(const std::string& path, RequestHandler handler)
{
    impl_->register_handler(path, std::move(handler));
}

} // namespace smo::observability