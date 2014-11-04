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

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <map>
#include <vector>
#include <algorithm>
#include <fstream>
#include <iostream>

#include "base64.h"
#include "openpgp.h"

extern "C" {
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
}

using namespace std;


int open_pgp::add_keys(const string &fname)
{
	string key{""};

	// For such a weird filename, we expect that the string contains
	// the key itself
	if (fname.find("----BEGIN PGP") == string::npos) {
		ifstream in(fname);

		if (!in.is_open())
			return build_error("open:");

		string b64key{""}, l{""};
		bool begin = 0;
		while (!in.eof()) {
			getline(in, l);
			if (l.size() <= 1)
				continue;
			else if (l.find(":") != string::npos)
				continue;

			if (l.find("----BEGIN PGP") != string::npos)
				begin = 1;

			if (!begin)
				continue;

			if (l.find("PUBLIC KEY") != string::npos) {
				key_type = KEYTYPE_PUBLIC;
				continue;
			} else if (l.find("PRIVATE KEY") != string::npos) {
				key_type = KEYTYPE_PRIVATE;
				continue;
			} else if (l.find("----END") != string::npos)
				break;

			b64key += l;
		}
		in.close();
		b64_decode(b64key, key);
	} else
		b64_decode(fname, key);

	uint8_t ptag = 0, hlen = 0;
	uint32_t idx = 0, plen = 0;
	const char *end = key.c_str() + key.size();

	for (; idx < key.size();) {
		ptag = (uint8_t)key[idx];
		hlen = 0;
		plen = 1;
		//printf("P=%d %x %x %d\n", ptag, key[idx+1], key[idx+2], ptag & 3);

		// old packet header
		if ((ptag & 0xc0) == 0x80) {
			switch (ptag & 3) {
			case 0:
				plen = (uint8_t)key[idx + 1];
				hlen = 2;
				break;
			case 1:
				plen = 0;
				memcpy(&plen, key.c_str() + idx + 1, 2);
				plen = ntohs(plen);
				hlen = 3;
				break;
			case 2:
				memcpy(&plen, key.c_str() + idx + 1, 4);
				plen = ntohl(plen);
				hlen = 5;
				break;
			case 3:
				hlen = 1;
				plen = key.size() - idx;
				break;
			}
			ptag = (ptag>>2)&0xf;
		// new phdr
		} else if ((ptag & 0xc0) == 0xc0) {
			plen = (uint8_t)key[idx + 1];
			hlen = 2;
			if (plen > 191 && plen <= 223) {
				memcpy(&plen, key.c_str() + idx + 1, 2);
				plen = ntohs(plen);
				hlen = 3;
			} else if (plen == 255) {
				memcpy(&plen, key.c_str() + idx + 2, 4);
				plen = ntohl(plen);
				hlen = 6;
			} else if (plen > 223) {
				plen = key.size() - idx;
			}
			ptag &= 0x3f;
		} else {
			return build_error("invalid packet tag");
		}

		if (plen > key.size() || key.c_str() + hlen + plen > end)
			return build_error("invalid packet content");

		//printf("hlen=%d plen=%d %d idx=%d s=%d\n", hlen, plen, ptag, idx, key.size());
		idx += hlen;

		switch (ptag) {
		case OPENPGP_PTAG_SECRET_KEY:
		case OPENPGP_PTAG_SECRET_SKEY:
			if (key_type != KEYTYPE_PRIVATE)
				return build_error("ptag keytype mismatch (private vs. public)");
			// fallthrough
		case OPENPGP_PTAG_PUBLIC_KEY:
		case OPENPGP_PTAG_PUBLIC_SKEY:
			if (decode_key(ptag, reinterpret_cast<const unsigned char *>(key.c_str() + idx), plen) < 0)
				return -1;
			// fallthrough
		default:
			idx += plen;
		}
	}
	return 0;
}


// decode the MPI parameters of the key
int open_pgp::decode_key(uint8_t ktype, const unsigned char *ptr, uint32_t plen)
{
	const unsigned char *end = ptr + plen;
	uint32_t idx = 0;
	uint16_t nbits = 0, nbytes = 0;

	if (ptr[0] != 4)
		return build_error("decode_key: Only V4 keys are supported.");

	RSA *rsa = NULL;
	DSA *dsa = NULL;
	DH *dh = NULL;

	// hash input for v4 keys to compute key ID
	string hi = "\x99";
	uint16_t hn = 0;
	EVP_PKEY *evp = EVP_PKEY_new();

	// skip version and creation time
	idx = 5;

	string emsg = "decode_key: Invalid key packet.";

	// find algorithm name
	switch (ptr[idx++]) {
	case OPENPGP_ALGO_RSA_ES:
	case OPENPGP_ALGO_RSA_E:
	case OPENPGP_ALGO_RSA_S:
		rsa = RSA_new();

		// both private and public key format contains the public part
		memcpy(&nbits, ptr + idx, sizeof(nbits));
		idx += 2;
		nbits = ntohs(nbits);
		nbytes = (nbits+7)/8;
		if (nbytes > plen || ptr + idx + nbytes > end)
			break;
		rsa->n = BN_bin2bn(ptr + idx, nbytes, NULL);
		idx += nbytes;

		memcpy(&nbits, ptr + idx, sizeof(nbits));
		idx += 2;
		nbits = ntohs(nbits);
		nbytes = (nbits+7)/8;
		if (nbytes > plen || ptr + idx + nbytes > end)
			break;
		rsa->e = BN_bin2bn(ptr + idx, nbytes, NULL);
		idx += nbytes;

		hn = (uint16_t)idx;

		if (ktype == OPENPGP_PTAG_SECRET_KEY || ktype == OPENPGP_PTAG_SECRET_SKEY) {
			if (ptr[idx++] != 0) {
				emsg = "encrypted keys not supported";
				break;
			}
			memcpy(&nbits, ptr + idx, sizeof(nbits));
			idx += 2;
			nbits = ntohs(nbits);
			nbytes = (nbits+7)/8;
			if (nbytes > plen || ptr + idx + nbytes > end)
				break;
			rsa->d = BN_bin2bn(ptr + idx, nbytes, NULL);
			idx += nbytes;

			memcpy(&nbits, ptr + idx, sizeof(nbits));
			idx += 2;
			nbits = ntohs(nbits);
			nbytes = (nbits+7)/8;
			if (nbytes > plen || ptr + idx + nbytes > end)
				break;
			rsa->p = BN_bin2bn(ptr + idx, nbytes, NULL);
			idx += nbytes;

			memcpy(&nbits, ptr + idx, sizeof(nbits));
			idx += 2;
			nbits = ntohs(nbits);
			nbytes = (nbits+7)/8;
			if (nbytes > plen || ptr + idx + nbytes > end)
				break;
			rsa->q = BN_bin2bn(ptr + idx, nbytes, NULL);
			idx += nbytes;

			memcpy(&nbits, ptr + idx, sizeof(nbits));
			idx += 2;
			nbits = ntohs(nbits);
			nbytes = (nbits+7)/8;
			if (nbytes > plen || ptr + idx + nbytes > end)
				break;
			rsa->iqmp = BN_bin2bn(ptr + idx, nbytes, NULL);
			idx += nbytes;
			rsa_keys[rsa] = KEYTYPE_PRIVATE;
		} else
			rsa_keys[rsa] = KEYTYPE_PUBLIC;
		EVP_PKEY_set1_RSA(evp, rsa);

		// No error happened, so clear emsg
		emsg = "";
		break;
	case OPENPGP_ALGO_DSA:
		dsa = DSA_new();
		// both private and public key format contains the public part
		memcpy(&nbits, ptr + idx, sizeof(nbits));
		idx += 2;
		nbits = ntohs(nbits);
		nbytes = (nbits+7)/8;
		if (nbytes > plen || ptr + idx + nbytes > end)
			break;
		dsa->p = BN_bin2bn(ptr + idx, nbytes, NULL);
		idx += nbytes;

		memcpy(&nbits, ptr + idx, sizeof(nbits));
		idx += 2;
		nbits = ntohs(nbits);
		if (nbytes > plen || ptr + idx + nbytes > end)
			break;
		nbytes = (nbits+7)/8;
		dsa->q = BN_bin2bn(ptr + idx, nbytes, NULL);
		idx += nbytes;

		memcpy(&nbits, ptr + idx, sizeof(nbits));
		idx += 2;
		nbits = ntohs(nbits);
		nbytes = (nbits+7)/8;
		if (nbytes > plen || ptr + idx + nbytes > end)
			break;
		dsa->g = BN_bin2bn(ptr + idx, nbytes, NULL);
		idx += nbytes;

		memcpy(&nbits, ptr + idx, sizeof(nbits));
		idx += 2;
		nbits = ntohs(nbits);
		nbytes = (nbits+7)/8;
		if (nbytes > plen || ptr + idx + nbytes > end)
			break;
		dsa->pub_key = BN_bin2bn(ptr + idx, nbytes, NULL);
		idx += nbytes;

		hn = (uint16_t)idx;

		if (ktype == OPENPGP_PTAG_SECRET_KEY || ktype == OPENPGP_PTAG_SECRET_SKEY) {
			if (ptr[idx++] != 0) {
				emsg = "encrypted keys not supported";
				break;
			}
			memcpy(&nbits, ptr + idx, sizeof(nbits));
			idx += 2;
			nbits = ntohs(nbits);
			nbytes = (nbits+7)/8;
			if (nbytes > plen || ptr + idx + nbytes > end)
				break;
			dsa->priv_key = BN_bin2bn(ptr + idx, nbytes, NULL);
			idx += nbytes;
			dsa_keys[dsa] = KEYTYPE_PRIVATE;
		} else
			dsa_keys[dsa] = KEYTYPE_PUBLIC;
		EVP_PKEY_set1_DSA(evp, dsa);
		emsg = "";
		break;
	case OPENPGP_ALGO_ELGAMAL:
		dh = DH_new();
		// both private and public key format contains the public part
		memcpy(&nbits, ptr + idx, sizeof(nbits));
		idx += 2;
		nbits = ntohs(nbits);
		nbytes = (nbits+7)/8;
		if (nbytes > plen || ptr + idx + nbytes > end)
			break;
		dh->p = BN_bin2bn(ptr + idx, nbytes, NULL);
		idx += nbytes;

		memcpy(&nbits, ptr + idx, sizeof(nbits));
		idx += 2;
		nbits = ntohs(nbits);
		nbytes = (nbits+7)/8;
		if (nbytes > plen || ptr + idx + nbytes > end)
			break;
		dh->g = BN_bin2bn(ptr + idx, nbytes, NULL);
		idx += nbytes;

		memcpy(&nbits, ptr + idx, sizeof(nbits));
		idx += 2;
		nbits = ntohs(nbits);
		nbytes = (nbits+7)/8;
		if (nbytes > plen || ptr + idx + nbytes > end)
			break;
		dh->pub_key = BN_bin2bn(ptr + idx, nbytes, NULL);
		idx += nbytes;

		hn = (uint16_t)idx;

		if (ktype == OPENPGP_PTAG_SECRET_KEY || ktype == OPENPGP_PTAG_SECRET_SKEY) {
			if (ptr[idx++] != 0) {
				emsg = "encrypted keys not supported";
				break;
			}
			memcpy(&nbits, ptr + idx, sizeof(nbits));
			idx += 2;
			nbits = ntohs(nbits);
			nbytes = (nbits+7)/8;
			if (nbytes > plen || ptr + idx + nbytes > end)
				break;
			dsa->priv_key = BN_bin2bn(ptr + idx, nbytes, NULL);
			idx += nbytes;
			dh_keys[dh] = KEYTYPE_PRIVATE;
		} else
			dh_keys[dh] = KEYTYPE_PUBLIC;
		EVP_PKEY_set1_DH(evp, dh);
		emsg = "";
		break;
	default:
		emsg = "no suitable algorith found (DSA, RSA or ElGamal)";
	}

	if (emsg.size() > 0) {
		if (rsa)
			RSA_free(rsa);
		if (dsa)
			DSA_free(dsa);
		if (dh)
			DH_free(dh);
		if (evp)
			EVP_PKEY_free(evp);
		return build_error(emsg);
	}


	// length of hash input
	hn = htons(hn);
	hi.append(reinterpret_cast<char *>(&hn), sizeof(hn));
	hi.append(reinterpret_cast<const char *>(ptr), ntohs(hn));

	unsigned char md[SHA_DIGEST_LENGTH];
	union {
		uint64_t keyid = 0;
		uint8_t keyid_bytes[8];
	};
	SHA_CTX hctx;
	SHA1_Init(&hctx);
	SHA1_Update(&hctx, hi.c_str(), hi.size());
	SHA1_Final(md, &hctx);
	// low order 64bits reversed
	reverse_copy(md + SHA_DIGEST_LENGTH - sizeof(keyid), md + SHA_DIGEST_LENGTH, keyid_bytes);

	if (verbose)
		cout<<std::hex<<keyid<<endl;

	if (ktype == OPENPGP_PTAG_SECRET_KEY || ktype == OPENPGP_PTAG_SECRET_SKEY)
		id2skey[keyid] = evp;
	else
		id2pkey[keyid] = evp;

	return 0;
}


string open_pgp::as_pem()
{
	BIO *b = BIO_new(BIO_s_mem());

	for (auto i : rsa_keys) {
		if (i.second == KEYTYPE_PRIVATE)
			PEM_write_bio_RSAPrivateKey(b, i.first, NULL, NULL, 0, NULL, NULL);
		else
			PEM_write_bio_RSAPublicKey(b, i.first);
	}
	for (auto i : dsa_keys) {
		if (i.second == KEYTYPE_PRIVATE)
			PEM_write_bio_DSAPrivateKey(b, i.first, NULL, NULL, 0, NULL, NULL);
		else
			PEM_write_bio_DSA_PUBKEY(b, i.first);
	}
	for (auto i : dh_keys) {
		PEM_write_bio_DHparams(b, i.first);
	}

	BUF_MEM *bptr = NULL;
	BIO_get_mem_ptr(b, &bptr);
	string ret = string(bptr->data, bptr->length);
	BIO_free(b);
	return ret;
}

// take care to have a correct umask (077) if
// handling private keys
int open_pgp::as_pem(const string &fname)
{
	mode_t u = umask(077);
	ofstream out(fname, std::ios::out);
	umask(u);
	if (out.is_open()) {
		out<<as_pem();
		out.close();
		return 0;
	}
	return build_error("as_pem::open:");
}



