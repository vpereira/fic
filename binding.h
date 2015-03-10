#ifndef __binding_h__
#define __binding_h__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fic_handle fic_handle_t;

fic_handle_t *fic_new(const char *key, const char *md, uint64_t id);

/* returns 1 on success */
int fic_verify_content(fic_handle_t *, const char *path);

/*returns 1 on success */
int fic_verify_meta(fic_handle_t *, const char *path);

/*returns 1 on success */
int fic_sign_content(fic_handle_t *, const char *path);

/*returns 1 on success */
int fic_sign_meta(fic_handle_t *, const char *path);

void fic_free(fic_handle_t *);

const char *fic_error(fic_handle_t *);

#ifdef __cplusplus
}
#endif

#endif

