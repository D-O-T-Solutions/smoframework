#include "readline/readline.h"
#include "readline/history.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <vector>
#include <string>

/* Global readline state */
rl_completion_func_t rl_attempted_completion_function = nullptr;
int rl_attempted_completion_over = 0;
char rl_line_buffer[1024] = {0};

int rl_bind_key(int, rl_command_func_t) {
    return 0;
}

int rl_complete(int, int) {
    return 0;
}

char* readline(const char* prompt) {
    if (prompt) {
        fputs(prompt, stdout);
        fflush(stdout);
    }

    size_t cap = 256;
    size_t len = 0;
    char* buf = static_cast<char*>(std::malloc(cap));
    if (!buf) return nullptr;

    int c;
    while ((c = fgetc(stdin)) != EOF && c != '\n') {
        if (len + 1 >= cap) {
            cap *= 2;
            char* new_buf = static_cast<char*>(std::realloc(buf, cap));
            if (!new_buf) {
                std::free(buf);
                return nullptr;
            }
            buf = new_buf;
        }
        buf[len++] = static_cast<char>(c);
    }

    if (c == EOF && len == 0) {
        std::free(buf);
        return nullptr;
    }

    buf[len] = '\0';
    std::strncpy(rl_line_buffer, buf, sizeof(rl_line_buffer) - 1);
    return buf;
}

char** rl_completion_matches(const char* text, rl_compentry_func_t func) {
    if (!func) return nullptr;

    std::vector<char*> matches;
    int state = 0;
    while (char* match = func(text, state++)) {
        matches.push_back(match);
    }

    if (matches.empty()) return nullptr;

    // Allocate NULL-terminated array
    char** result = static_cast<char**>(std::malloc((matches.size() + 1) * sizeof(char*)));
    if (!result) return nullptr;

    for (size_t i = 0; i < matches.size(); ++i) {
        result[i] = matches[i];
    }
    result[matches.size()] = nullptr;
    return result;
}

void rl_free_line_state(void) {}
void rl_cleanup_after_signal(void) {}
int rl_on_new_line(void) { return 0; }
void rl_replace_line(const char*, int) {}
void rl_redisplay(void) {}

void add_history(const char*) {
    // no-op stub
}

int read_history(const char*) {
    return 0;
}

int write_history(const char*) {
    return 0;
}
