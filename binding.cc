/*
 * This file is part of the fic, the file integrity checker.
 *
 * (C) 2015 by Sebastian Krahmer,
 *             krahmer [at] suse [dot] de
 *
 * fic is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * fic is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with fic.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <string>
#include <cstring>
#include <stdint.h>
#include "binding.h"
#include "fic.h"
#include "openpgp.h"

extern "C" {

using namespace std;

typedef struct fic_handle {
	fic *f;
	open_pgp *pgp;
	uint64_t id;
	string md;
	const char *err;
} fic_handle_t;


fic_handle *fic_new(const char *key, const char *md, uint64_t id)
{
	fic_handle *fh = new (nothrow) fic_handle;

	if (!fh)
		return NULL;

	if (!(fh->f = new (nothrow) fic)) {
		delete fh;
		return NULL;
	}

	if (!(fh->pgp = new (nothrow) open_pgp)) {
		delete fh->f;
		delete fh;
		return NULL;
	}


	if (fh->pgp->add_keys(key) != 0) {
		delete fh->pgp;
		delete fh->f;
		delete fh;
		return NULL;
	}

	fh->id = id;
	fh->md = md;
	fh->err = "";

	return fh;

}


int fic_verify_content(fic_handle *fh, const char *path)
{
	if (!fh)
		return -1;

	fh->err = "";
	EVP_PKEY *key = fh->pgp->find_pkey(fh->id);
	if (!key) {
		fh->err = "Invalid key ID for verifying.";
		return -1;
	}
	fh->f->key(key);
	return fh->f->verify_content(NULL, path, fh->md);
}


int fic_verify_meta(fic_handle *fh, const char *path)
{
	if (!fh)
		return -1;

	fh->err = "";
	EVP_PKEY *key = fh->pgp->find_pkey(fh->id);
	if (!key) {
		fh->err = "Invalid key ID for verifying.";
		return -1;
	}
	fh->f->key(key);
	return fh->f->verify_meta(NULL, path, fh->md);

}

int fic_sign_content(fic_handle *fh, const char *path)
{
	if (!fh)
		return -1;

	fh->err = "";
	EVP_PKEY *key = fh->pgp->find_skey(fh->id);
	if (!key) {
		fh->err = "Invalid key ID for signing.";
		return -1;
	}
	fh->f->key(key);
	return fh->f->sign_content(NULL, path, fh->md);

}

int fic_sign_meta(fic_handle *fh, const char *path)
{
	if (!fh)
		return -1;

	fh->err = "";
	EVP_PKEY *key = fh->pgp->find_skey(fh->id);
	if (!key) {
		fh->err = "Invalid key ID for signing.";
		return -1;
	}
	fh->f->key(key);
	return fh->f->sign_meta(NULL, path, fh->md);

}

void fic_free(fic_handle *fh)
{
	if (!fh)
		return;

	delete fh->pgp;
	delete fh->f;
	delete fh;
}

const char *fic_error(fic_handle *fh)
{
	if (!fh)
		return NULL;
	return fh->err;
}

} // extern "C"



