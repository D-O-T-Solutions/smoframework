#ifndef READLINE_READLINE_H
#define READLINE_READLINE_H

#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifdef __cplusplus
extern "C" {
#endif

/* Function type for completion */
typedef char** (*rl_completion_func_t)(const char*, int, int);

/* Completion match generator */
typedef char* (*rl_compentry_func_t)(const char*, int);

/* Global variables */
extern rl_completion_func_t rl_attempted_completion_function;
extern int rl_attempted_completion_over;
extern char rl_line_buffer[1024];

/* Key binding function type */
typedef int (*rl_command_func_t)(int, int);

/* Bind a key to a function */
extern int rl_bind_key(int key, rl_command_func_t func);

/* Default completion function */
extern int rl_complete(int, int);

/* Read a line from input */
extern char* readline(const char* prompt);

/* Completion match generation */
extern char** rl_completion_matches(const char* text, rl_compentry_func_t func);

/* Signal handling helpers */
extern void rl_free_line_state(void);
extern void rl_cleanup_after_signal(void);
extern int rl_on_new_line(void);
extern void rl_replace_line(const char* text, int clear_undo);
extern void rl_redisplay(void);

/* History file functions */
extern int read_history(const char* filename);
extern int write_history(const char* filename);

#ifdef __cplusplus
}
#endif

#endif /* READLINE_READLINE_H */
