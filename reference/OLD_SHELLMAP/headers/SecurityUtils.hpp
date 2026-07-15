#ifndef SECURITY_UTILS_HPP
#define SECURITY_UTILS_HPP

#include <string>
#include <vector>
#include <algorithm>
#include <iostream>

// Color definitions for console output
#define COLOR_RESET     "\033[0m"
#define COLOR_RED       "\033[31m"
#define COLOR_YELLOW    "\033[33m"

/**
 * @class SecurityUtils
 * @brief Path traversal protection and security checks
 * 
 * CRITICAL: All file operations must pass through is_safe_path()
 */
class SecurityUtils {
public:
    /**
     * @brief Check if path is safe (no traversal, absolute paths allowed)
     * 
     * Rules:
     * 1. FORBID: "../" or "..\\" sequences (path traversal)
     * 2. FORBID: Absolute paths starting with "/" (Linux) or "C:\" (Windows)
     * 3. ALLOW: Relative paths within shellmap/shared/
     * 4. ALLOW: Empty path (root of shared folder)
     * 
     * @param path Path to validate
     * @param base_dir Base directory (default: "shared")
     * @return true if path is safe, false if attack detected
     */
     static bool is_safe_path(const std::string& path, const std::string& base_dir = "shared") {
          // Allow empty path (root of current directory)
          if (path.empty()) {
              return true;
          }
          
          // Allow single "." (current directory)
          if (path == ".") {
              return true;
          }
          
          // Rule 1: Forbid standalone ".." at end of string (string is exactly "..")
          // But allow "../" sequences for path resolution since they will be clamped by resolve_path
          if (path == "..") {
              // This is allowed - it's a single level up request
              return true;
          }
          
          // Forbid "~" home directory (we don't support user home)
          if (path[0] == '~') {
              std::cout << COLOR_RED << "[SECURITY] Home directory shortcut (~) not allowed" << COLOR_RESET << std::endl;
              return false;
          }
          
          // Rule 2: Forbid absolute paths starting with "/"
          if (!path.empty() && path[0] == '/') {
              std::cout << COLOR_RED << "[SECURITY] Absolute path attack detected: / prefix" << COLOR_RESET << std::endl;
              return false;
          }
          
          // Check for Windows absolute path (C:\, D:\, etc)
          if (path.length() >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/')) {
              std::cout << COLOR_RED << "[SECURITY] Absolute path attack detected: Windows drive letter" << COLOR_RESET << std::endl;
              return false;
          }
          
          // Rule 3: Additional check - forbid null bytes
          if (path.find('\0') != std::string::npos) {
              std::cout << COLOR_RED << "[SECURITY] Null byte attack detected in path" << COLOR_RESET << std::endl;
              return false;
          }
          
          // All checks passed
          return true;
      }
    
     /**
      * @brief Normalize path (remove trailing slashes, resolve . and ..)
      * CRITICAL: Must call is_safe_path() BEFORE normalize
      * 
      * @param path Path to normalize
      * @return Normalized path
      */
     static std::string normalize_path(const std::string& path) {
         std::string result = path;
         
         // Remove trailing slashes
         while (!result.empty() && (result.back() == '/' || result.back() == '\\')) {
             result.pop_back();
         }
         
         // Convert backslashes to forward slashes for consistency
         std::replace(result.begin(), result.end(), '\\', '/');
         
         // Remove multiple consecutive slashes
         std::string normalized;
         bool prev_slash = false;
         for (char c : result) {
             if (c == '/' && prev_slash) continue;
             normalized += c;
             prev_slash = (c == '/');
         }
         
         return normalized;
     }
     
     /**
      * @brief Resolve path with . and .. handling (shell-like semantics)
      * Handles "." (current) and ".." (parent), clamping to root ("")
      * CRITICAL: Call is_safe_path() BEFORE resolve_path()
      * 
      * @param current_path Current working directory (normalized)
      * @param requested_path User-requested path (may contain . and ..)
      * @return Resolved absolute path (clamped to root ""), or empty string on error
      */
     static std::string resolve_path(const std::string& current_path, const std::string& requested_path) {
         // If requested_path is empty, return current_path
         if (requested_path.empty()) {
             return current_path;
         }
         
         // Start with current path and split into components
         std::vector<std::string> components;
         std::string working = current_path.empty() ? "" : current_path;
         
         // Split current path by '/'
         if (!working.empty()) {
             size_t start = 0;
             size_t end = working.find('/');
             while (end != std::string::npos) {
                 if (end > start) {
                     components.push_back(working.substr(start, end - start));
                 }
                 start = end + 1;
                 end = working.find('/', start);
             }
             if (start < working.length()) {
                 components.push_back(working.substr(start));
             }
         }
         
         // Now process requested_path components
         std::string req = requested_path;
         // Convert backslashes to forward slashes
         std::replace(req.begin(), req.end(), '\\', '/');
         
         // Remove trailing slashes
         while (!req.empty() && req.back() == '/') {
             req.pop_back();
         }
         
         // Split requested_path by '/'
         size_t start = 0;
         size_t end = req.find('/');
         while (end != std::string::npos) {
             std::string component = req.substr(start, end - start);
             
             if (component == ".." || component == "..\\") {
                 // Go up one level (if not at root)
                 if (!components.empty()) {
                     components.pop_back();
                 }
                 // If already at root, stay at root (don't go higher)
             } else if (component != "." && !component.empty()) {
                 // Add component (skip "." which means current dir)
                 components.push_back(component);
             }
             
             start = end + 1;
             end = req.find('/', start);
         }
         
         // Process final component
         if (start < req.length()) {
             std::string component = req.substr(start);
             if (component == ".." || component == "..\\") {
                 if (!components.empty()) {
                     components.pop_back();
                 }
             } else if (component != "." && !component.empty()) {
                 components.push_back(component);
             }
         }
         
         // Reconstruct path
         std::string resolved;
         for (const auto& comp : components) {
             resolved += "/" + comp;
         }
         
         // Remove leading slash for relative paths (root should be "")
         if (resolved == "/") {
             return "";
         }
         if (resolved.length() > 1 && resolved[0] == '/') {
             return resolved.substr(1);
         }
         
         return resolved;
     }
    
     /**
      * @brief Log security attack attempt
      * @param node_id Attacking peer node ID
      * @param attack_type Type of attack (e.g., "Path Traversal")
      */
     static void log_security_attack(const std::string& node_id, const std::string& attack_type) {
         std::cout << COLOR_RED << "[SECURITY] " << attack_type << " attack blocked from " 
                   << node_id.substr(0, 8) << "!" << COLOR_RESET << std::endl;
     }
};

#endif // SECURITY_UTILS_HPP
