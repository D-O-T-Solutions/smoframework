#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <filesystem>
#include "core/contract/contract.hpp"
#include "core/errors/error.hpp"

namespace smo::contract::native {

// ===========================================================================
// Filesystem Contracts
// ===========================================================================

enum class FSOpcode : uint8_t {
    LIST          = 0x01,
    MAKEDIR       = 0x02,
    REMOVE        = 0x03,
    COPY          = 0x04,
    MOVE          = 0x05,
    STAT          = 0x06,
    READ          = 0x07,
    WRITE         = 0x07,
    CREATE        = 0x08,
    CHMOD         = 0x09,
    CHOWN         = 0x0A,
    SYMLINK       = 0x0B,
    READLINK      = 0x0C,
    REALPATH      = 0x0D,
};

struct FSListRequest {
    std::string path;
    bool recursive = false;
    bool long_format = false;
    bool show_hidden = false;
};

struct FSListResponse {
    struct Entry {
        std::string name;
        std::string path;
        bool is_directory = false;
        bool is_symlink = false;
        uint64_t size = 0;
        uint64_t modified_ns = 0;
        std::string permissions;
        std::string owner;
        std::string group;
        std::string symlink_target;
    };
    std::vector<Entry> entries;
    std::string path;
};

struct FSMkdirRequest {
    std::string path;
    bool parents = false;
    uint32_t mode = 0755;
};

struct FSMkdirResponse {
    std::string path;
    bool created = false;
};

struct FSRemoveRequest {
    std::string path;
    bool recursive = false;
    bool force = false;
};

struct FSRemoveResponse {
    std::string path;
    bool removed = false;
    size_t removed_count = 0;
};

struct FSCopyRequest {
    std::string src;
    std::string dst;
    bool recursive = false;
    bool preserve = false;
    bool overwrite = false;
};

struct FSCopyResponse {
    std::string src;
    std::string dst;
    bool copied = false;
    size_t bytes_copied = 0;
};

struct FSMoveRequest {
    std::string src;
    std::string dst;
    bool overwrite = false;
};

struct FSMoveResponse {
    std::string src;
    std::string dst;
    bool moved = false;
};

struct FSStatRequest {
    std::string path;
    bool follow_symlinks = true;
};

struct FSStatResponse {
    std::string path;
    bool exists = false;
    bool is_directory = false;
    bool is_symlink = false;
    bool is_file = false;
    uint64_t size = 0;
    uint64_t modified_ns = 0;
    uint64_t accessed_ns = 0;
    uint64_t created_ns = 0;
    std::string permissions;
    std::string owner;
    std::string group;
    std::string symlink_target;
};

struct FSReadRequest {
    std::string path;
    int64_t offset = 0;
    int64_t length = -1;  // -1 = read all
};

struct FSReadResponse {
    std::string path;
    std::vector<uint8_t> data;
    int64_t offset = 0;
    int64_t length = 0;
    bool eof = false;
};

struct FSWriteRequest {
    std::string path;
    std::vector<uint8_t> data;
    int64_t offset = 0;
    bool append = false;
    bool create = true;
    uint32_t mode = 0644;
};

struct FSWriteResponse {
    std::string path;
    int64_t bytes_written = 0;
    int64_t offset = 0;
};

struct FSChmodRequest {
    std::string path;
    uint32_t mode;
    bool recursive = false;
};

struct FSChmodResponse {
    std::string path;
    uint32_t old_mode = 0;
    uint32_t new_mode = 0;
};

struct FSChownRequest {
    std::string path;
    std::string owner;
    std::string group;
    bool recursive = false;
};

struct FSChownResponse {
    std::string path;
    std::string old_owner;
    std::string old_group;
    std::string new_owner;
    std::string new_group;
};

struct FSSymlinkRequest {
    std::string target;
    std::string link_path;
};

struct FSSymlinkResponse {
    std::string link_path;
    std::string target;
    bool created = false;
};

struct FSReadlinkRequest {
    std::string path;
};

struct FSReadlinkResponse {
    std::string path;
    std::string target;
};

struct FSRealpathRequest {
    std::string path;
};

struct FSRealpathResponse {
    std::string path;
    std::string resolved_path;
};

// Opcode strings for contract definition
inline const char* fs_opcode_to_string(FSOpcode op) {
    switch (op) {
        case FSOpcode::LIST: return "fs.list";
        case FSOpcode::MAKEDIR: return "fs.mkdir";
        case FSOpcode::REMOVE: return "fs.remove";
        case FSOpcode::COPY: return "fs.copy";
        case FSOpcode::MOVE: return "fs.move";
        case FSOpcode::STAT: return "fs.stat";
        case FSOpcode::READ: return "fs.read";
        case FSOpcode::WRITE: return "fs.write";
        case FSOpcode::CREATE: return "fs.create";
        case FSOpcode::CHMOD: return "fs.chmod";
        case FSOpcode::CHOWN: return "fs.chown";
        case FSOpcode::SYMLINK: return "fs.symlink";
        case FSOpcode::READLINK: return "fs.readlink";
        case FSOpcode::REALPATH: return "fs.realpath";
    }
    return "fs.unknown";
}

} // namespace smo::contract::native