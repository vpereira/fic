/*
 * This file is part of the fic, the file integrity checker.
 *
 * (C) 2014 by Sebastian Krahmer,
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

#ifndef __opengpg_h__
#define __openpgp_h__

#include <iostream>
#include <cstddef>
#include <stdint.h>
#include <cerrno>
#include <cstring>
#include <map>

#include <cstdio>

extern "C" {
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
}


enum {
	OPENPGP_PTAG_SIGNATURE		= 2,
	OPENPGP_PTAG_SECRET_KEY 	= 5,
	OPENPGP_PTAG_PUBLIC_KEY 	= 6,
	OPENPGP_PTAG_SECRET_SKEY	= 7,
	OPENPGP_PTAG_ENCSYM		= 9,
	OPENPGP_PTAG_LITERAL		= 11,
	OPENPGP_PTAG_USERID		= 13,
	OPENPGP_PTAG_PUBLIC_SKEY	= 14,
	OPENPGP_PTAG_USER_ATTR		= 17,

	OPENPGP_ALGO_RSA_ES	= 1,
	OPENPGP_ALGO_RSA_E	= 2,
	OPENPGP_ALGO_RSA_S	= 3,
	OPENPGP_ALGO_ELGAMAL	= 16,
	OPENPGP_ALGO_DSA	= 17
};


// RFC 4880 to openssl key decoding
class open_pgp {
private:

	bool verbose;

	std::string algo, err;

	std::map<RSA *, int> rsa_keys;
	std::map<DSA *, int> dsa_keys;
	std::map<DH *, int> dh_keys;
	std::map<uint64_t, EVP_PKEY *> id2skey, id2pkey;

	enum {
		KEYTYPE_PUBLIC = 0,
		KEYTYPE_PRIVATE = 1
	} key_type;

	int build_error(const std::string &msg, int r = -1)
	{
		err = "open_pgp::";
		err += msg;
		if (errno)
			err = strerror(errno);
		return r;
	}

	int decode_key(uint8_t, const unsigned char *, uint32_t);

public:

	open_pgp()
		: verbose(0), algo{""}, err{""}
	{
	}

	~open_pgp()
	{
		for (auto i : rsa_keys)
			RSA_free(i.first);
		for (auto i : dsa_keys)
			DSA_free(i.first);
		for (auto i : dh_keys)
			DH_free(i.first);
		for (auto i : id2pkey)
			EVP_PKEY_free(i.second);
		for (auto i : id2skey)
			EVP_PKEY_free(i.second);
	}

	void print_id(bool p)
	{
		verbose = p;
	}

	const char *why()
	{
		return err.c_str();
	}

	// gpg --edit-key 0x11223344 passwd to delete the passphrase
	// gpg -a --export-secret-key 0x11223344
	int add_keys(const std::string &fname);

	int as_pem(const std::string &fname);

	std::string as_pem();

	bool has_rsa()
	{
		return rsa_keys.size() > 0;
	}

	bool has_dsa()
	{
		return dsa_keys.size() > 0;
	}

	bool has_elgamal()
	{
		return dh_keys.size() > 0;
	}


	// gpg --list-keys --keyid-format LONG
	EVP_PKEY *find_pkey(uint64_t id)
	{
		if (id2pkey.count(id) == 0)
			return nullptr;
		return id2pkey[id];
	}

	EVP_PKEY *find_skey(uint64_t id)
	{
		if (id2skey.count(id) == 0)
			return nullptr;
		return id2skey[id];
	}
};


#endif

