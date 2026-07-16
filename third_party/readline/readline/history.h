#ifndef READLINE_HISTORY_H
#define READLINE_HISTORY_H

#ifdef __cplusplus
extern "C" {
#endif

/* Add a line to the history list */
extern void add_history(const char* line);

#ifdef __cplusplus
}
#endif

#endif /* READLINE_HISTORY_H */