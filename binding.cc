/*
 * This file is part of the fic, the file integrity checker.
 *
 * (C) 2015 by Sebastian Krahmer,
 *             krahmer [at] suse [dot] com
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

#include <openssl/pem.h>
#include <openssl/evp.h>

using namespace std;

struct fic_handle {
	fic *f;
	EVP_PKEY *pubkey, *privkey;
	open_pgp *pgp;
	uint64_t id;
	string md;
	const char *err;

	fic_handle() : f(NULL), pubkey(NULL), privkey(NULL), pgp(NULL), id(0), md(""), err(NULL)
	{}

	~fic_handle()
	{
		delete f;
		if (pgp)
			delete pgp;
		else {
			EVP_PKEY_free(pubkey);
			EVP_PKEY_free(privkey);
		}
	}
};

typedef struct fic_handle fic_handle_t;


fic_handle *fic_new(const char *keyfile, const char *md, uint64_t id)
{
	fic_handle *fh = new (nothrow) fic_handle;

	if (!fh)
		return NULL;

	if (!(fh->f = new (nothrow) fic)) {
		delete fh;
		return NULL;
	}

	if (id) {
		if (!(fh->pgp = new (nothrow) open_pgp)) {
			delete fh;
			return NULL;
		}
		if (fh->pgp->add_keys(keyfile) == 0) {
			fh->pubkey = fh->pgp->find_pkey(id);	// only shallow copy, so we need to keep pgp object
			fh->privkey = fh->pgp->find_skey(id);
		}
	} else {
		FILE *f = fopen(keyfile, "r");
		if (f) {
			fh->pubkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
			rewind(f);
			fh->privkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
			fclose(f);
		}
	}

	if (!fh->pubkey && !fh->privkey) {
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
	if (!fh->pubkey) {
		fh->err = "Invalid key ID for verifying.";
		return -1;
	}
	fh->f->key(fh->pubkey);
	return fh->f->verify_content(NULL, path, fh->md);
}


int fic_verify_meta(fic_handle *fh, const char *path)
{
	if (!fh)
		return -1;

	fh->err = "";
	if (!fh->pubkey) {
		fh->err = "Invalid key ID for verifying.";
		return -1;
	}
	fh->f->key(fh->pubkey);
	return fh->f->verify_meta(NULL, path, fh->md);

}

int fic_sign_content(fic_handle *fh, const char *path)
{
	if (!fh)
		return -1;

	fh->err = "";
	if (!fh->privkey) {
		fh->err = "Invalid key ID for signing.";
		return -1;
	}
	fh->f->key(fh->privkey);
	return fh->f->sign_content(NULL, path, fh->md);

}

int fic_sign_meta(fic_handle *fh, const char *path)
{
	if (!fh)
		return -1;

	fh->err = "";
	if (!fh->privkey) {
		fh->err = "Invalid key ID for signing.";
		return -1;
	}
	fh->f->key(fh->privkey);
	return fh->f->sign_meta(NULL, path, fh->md);

}

void fic_free(fic_handle *fh)
{
	delete fh;
}

const char *fic_error(fic_handle *fh)
{
	if (!fh)
		return NULL;
	return fh->err;
}

} // extern "C"



