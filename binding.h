#ifndef __binding_h__
#define __binding_h__

#include <stdint.h>

extern "C" {

struct fic_handle;

fic_handle *fic_new(const char *key, const char *md, uint64_t id);

int fic_verify_content(fic_handle *, const char *path);

int fic_verify_meta(fic_handle *, const char *path);

int fic_sign_content(fic_handle *, const char *path);

int fic_sign_meta(fic_handle *, const char *path);

void fic_destroy(fic_handle *);

const char *fic_error(fic_handle *);

}

#endif

