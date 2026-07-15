#ifndef TERMINAL_INPUT_HPP
#define TERMINAL_INPUT_HPP

#include <string>
#include <vector>
#include <iostream>
#include <termios.h>
#include <unistd.h>
#include <cstring>

/**
 * @class TerminalInput
 * @brief Handles raw terminal input with command history and arrow keys
 */
class TerminalInput {
private:
    std::vector<std::string> history_;
    size_t history_pos_;
    std::string current_line_;
    termios original_term_;
    bool raw_mode_enabled_;

    // Enable raw terminal mode
    void enable_raw_mode() {
        if (raw_mode_enabled_) return;
        
        termios raw = original_term_;
        raw.c_lflag &= ~(ECHO | ICANON);
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 0;
        
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
        raw_mode_enabled_ = true;
    }

    // Disable raw terminal mode
    void disable_raw_mode() {
        if (!raw_mode_enabled_) return;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_term_);
        raw_mode_enabled_ = false;
    }

public:
    TerminalInput() : history_pos_(0), raw_mode_enabled_(false) {
        tcgetattr(STDIN_FILENO, &original_term_);
    }

    ~TerminalInput() {
        disable_raw_mode();
    }

    /**
     * @brief Read a line from terminal with history support
     * Arrow up/down navigates history, Enter submits
     */
    std::string read_line(const std::string& prompt) {
        enable_raw_mode();
        current_line_.clear();
        history_pos_ = history_.size();  // Start at end of history (new line)
        
        std::cout << prompt << std::flush;
        
        while (true) {
            char c;
            if (read(STDIN_FILENO, &c, 1) != 1) {
                usleep(10000);  // Sleep 10ms if no input
                continue;
            }

            // Handle escape sequences (arrow keys)
            if (c == '\033') {  // ESC
                char seq[2];
                if (read(STDIN_FILENO, &seq[0], 1) != 1) continue;
                if (read(STDIN_FILENO, &seq[1], 1) != 1) continue;
                
                if (seq[0] == '[') {
                    if (seq[1] == 'A') {  // Arrow UP
                        handle_history_up(prompt);
                    } else if (seq[1] == 'B') {  // Arrow DOWN
                        handle_history_down(prompt);
                    }
                }
                continue;
            }

            // Handle regular characters
            switch (c) {
                case '\n':  // Enter
                case '\r': {
                    std::cout << "\n";
                    disable_raw_mode();
                    
                    // Save non-empty commands to history
                    if (!current_line_.empty() && 
                        (history_.empty() || history_.back() != current_line_)) {
                        history_.push_back(current_line_);
                    }
                    return current_line_;
                }
                
                case 127:  // Backspace
                case '\b': {
                    if (!current_line_.empty()) {
                        current_line_.pop_back();
                        std::cout << "\b \b" << std::flush;
                    }
                    break;
                }
                
                case '\x03':  // Ctrl+C
                    std::cout << "\n";
                    disable_raw_mode();
                    current_line_.clear();
                    return current_line_;
                
                case '\x04':  // Ctrl+D (EOF)
                    std::cout << "\n";
                    disable_raw_mode();
                    return "";  // Signal EOF
                
                default:
                    if (c >= 32 && c <= 126) {  // Printable ASCII
                        current_line_ += c;
                        std::cout << c << std::flush;
                    }
                    break;
            }
        }
    }

private:
    void handle_history_up(const std::string& prompt) {
        if (history_.empty()) return;
        
        if (history_pos_ > 0) {
            history_pos_--;
        } else {
            return;  // Already at the beginning
        }
        
        // Clear the current line from terminal
        std::cout << "\r" << prompt;
        for (size_t i = 0; i < current_line_.length() + prompt.length(); ++i) {
            std::cout << " ";
        }
        std::cout << "\r" << prompt;
        
        current_line_ = history_[history_pos_];
        std::cout << current_line_ << std::flush;
    }

    void handle_history_down(const std::string& prompt) {
        if (history_.empty()) return;
        
        if (history_pos_ < history_.size() - 1) {
            history_pos_++;
        } else if (history_pos_ < history_.size()) {
            history_pos_ = history_.size();
            // Clear the current line
            std::cout << "\r" << prompt;
            for (size_t i = 0; i < current_line_.length() + prompt.length(); ++i) {
                std::cout << " ";
            }
            std::cout << "\r" << prompt << std::flush;
            current_line_.clear();
            return;
        } else {
            return;  // Already at the end
        }
        
        // Clear the current line from terminal
        std::cout << "\r" << prompt;
        for (size_t i = 0; i < current_line_.length() + prompt.length(); ++i) {
            std::cout << " ";
        }
        std::cout << "\r" << prompt;
        
        current_line_ = history_[history_pos_];
        std::cout << current_line_ << std::flush;
    }
};

#endif // TERMINAL_INPUT_HPP
