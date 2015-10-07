/*
 * This file is part of the fic, the file integrity checker.
 *
 * (C) 2014 by Sebastian Krahmer,
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

#include <ftw.h>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <string>
#include <cstdint>
#include <iostream>
#include "fic.h"
#include "openpgp.h"

extern "C" {
#include <openssl/evp.h>
#include <openssl/pem.h>
}


using namespace std;


void usage()
{
	cout<<"File Integrity Checker v0.1\n\n"
	    <<"Usage: fic [-sSvVipdF] [-k keyid] <-K keyfile> [path1] [path2] ... [pathN]\n\n"
	    <<"\t -s -- sign meta info\n"
	    <<"\t -S -- sign content\n"
	    <<"\t -v -- verify meta info\n"
	    <<"\t -V -- verify content\n"
	    <<"\t -i -- print key ID(s) to stdout\n"
	    <<"\t -p -- sign dryrun: only print signature(s) to stdout\n"
	    <<"\t -d -- dump key(s) as PEM from keyfile\n"
	    <<"\t -F -- only print FAILure, no success\n\n";

	exit(1);
}


namespace global {

fic *checker = NULL;

enum : uint32_t {
	OP_NONE		= 0,

	OP_VRFY_CONTENT = 0x1,
	OP_VRFY_META	= 0x2,
	OP_VRFY_MASK	= 0xf,

	OP_SIGN_CONTENT = 0x10,
	OP_SIGN_META	= 0x20,
	OP_SIGN_MASK	= 0xf0,

	OP_PRINT_SIG	= 0x100,
	OP_PRINT_KEYID	= 0x200,
	OP_PRINT_KEYS	= 0x400,
	OP_FAILONLY	= 0x800,
	OP_MASK		= 0xf00
};

uint32_t op = OP_NONE;

int walk(const char *fpath, const struct stat *st, int type, struct FTW *ftwbuf)
{
	if ((!S_ISREG(st->st_mode) && !S_ISLNK(st->st_mode)) || (type & FTW_SLN))
		return 0;

	int c = 0;
	string good = "SIGNED", bad = "FAILED";

	if (op & OP_SIGN_CONTENT)
		c = checker->sign_content(st, fpath);
	if (op & OP_SIGN_META)
		c = checker->sign_meta(st, fpath);
	if (op & OP_VRFY_CONTENT) {
		c = checker->verify_content(st, fpath);
		good = "GOODSIG";
	}
	if (op & OP_VRFY_META) {
		c = checker->verify_meta(st, fpath);
		good = "GOODSIG";
	}

	if (!(op & OP_FAILONLY) || c != 1)
		cout<<fpath<<" "<<(c == 1 ? good : bad)<<endl;

	if (c < 0) {
		cerr<<checker->why()<<endl;
		return -1;
	}
	return 0;
}


}

using namespace global;

int main(int argc, char **argv)
{
	uint64_t keyid = 0;
	bool has_keyid = 0;

	int c = 0;
	string keyfile = "";
	while ((c = getopt(argc, argv, "sSvVk:K:pidF")) != -1) {
		switch (c) {
		case 'S':
			op |= OP_SIGN_CONTENT;
			op &= (OP_SIGN_MASK|OP_MASK);
			break;
		case 's':
			op |= OP_SIGN_META;
			op &= (OP_SIGN_MASK|OP_MASK);
			break;
		case 'V':
			op |= OP_VRFY_CONTENT;
			op &= (OP_VRFY_MASK|OP_MASK);
			break;
		case 'v':
			op |= OP_VRFY_META;
			op &= (OP_VRFY_MASK|OP_MASK);
			break;
		case 'k':
			keyid = strtoull(optarg, NULL, 16);
			has_keyid = 1;
			break;
		case 'K':
			keyfile = optarg;
			break;
		case 'p':
			op |= OP_PRINT_SIG;
			break;
		case 'i':
			op |= OP_PRINT_KEYID;
			break;
		case 'd':
			op |= OP_PRINT_KEYS;
			break;
		case 'F':
			op |= OP_FAILONLY;
			break;
		default:
			usage();
		}
	}

	if (op == OP_NONE)
		usage();

	if (!keyfile.size())
		usage();

	open_pgp pgpkey;

	if (has_keyid || (op & OP_PRINT_KEYS)) {
		if (op & OP_PRINT_KEYID)
			pgpkey.print_id(1);

		if (pgpkey.add_keys(keyfile) < 0) {
			cerr<<pgpkey.why()<<endl;
			return 1;
		}

		if (op & OP_PRINT_KEYS)
			cout<<pgpkey.as_pem()<<endl;
	}

	if ((checker = new (nothrow) fic) == NULL) {
		cerr<<"OOM";
		return 2;
	}

	if (op & OP_PRINT_SIG)
		checker->dryrun(1);

	EVP_PKEY *k = NULL;

	// handle as native PEM file if no keyid given
	if (!has_keyid && (op & OP_SIGN_MASK)) {
		FILE *f = fopen(keyfile.c_str(), "r");
		if (f) {
			k = PEM_read_PrivateKey(f, NULL, NULL, NULL);
			fclose(f);
		}
	} else if (!has_keyid && (op & OP_VRFY_MASK)) {
		FILE *f = fopen(keyfile.c_str(), "r");
		if (f) {
			k = PEM_read_PUBKEY(f, NULL, NULL, NULL);
			fclose(f);
		}
	} else if (op & OP_SIGN_MASK) {
		k = pgpkey.find_skey(keyid);
	} else if (op & OP_VRFY_MASK) {
		k = pgpkey.find_pkey(keyid);
	} else {
		delete checker;
		return 0;
	}

	if (!k) {
		cerr<<"No suitable Key with ID "<<std::hex<<keyid<<" found for this operation.\n";
		return 2;
	}

	checker->key(k);

	int r = 0;
	while (argc > optind) {
		if ((r = nftw(argv[optind++], walk, 1024, 0)) < 0)
			break;
	}

	delete checker;

	if (!has_keyid)
		EVP_PKEY_free(k);

	return r;
}

