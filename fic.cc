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

#include "fic.h"
#include "base64.h"
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <iostream>

extern "C" {
#include <openssl/evp.h>
}


using namespace std;


std::string fic::xattr_content = "user.fic.content.v1.none";
std::string fic::xattr_meta = "user.fic.meta.v1.none";

int fic::key(EVP_PKEY *k)
{
	pkey = k;
	return 0;
}


// meta buffer at least of META_SIZE bytes
static void stat2meta(const struct stat &st, char *meta)
{
	struct {
		dev_t dev, rdev;
		ino_t ino;
		mode_t mode;
		uid_t uid;
		gid_t gid;
		off_t size;
	} st2;

	st2.dev = st.st_dev;
	st2.rdev = st.st_rdev;
	st2.ino = st.st_ino;
	st2.mode = st.st_mode;
	st2.uid = st.st_uid;
	st2.gid = st.st_gid;
	st2.size = st.st_size;

	memcpy(meta, &st2, sizeof(st2));
}


int fic::sign(const struct stat *st, const string &what, const string &fname, const std::string &md)
{
	if (fname.size() == 0 || !pkey)
		return build_error("sign: No filename or key available.");

	struct stat st2;
	if (!st) {
		if (lstat(fname.c_str(), &st2) < 0)
			return build_error("sign::lstat");
	} else
		memcpy(&st2, st, sizeof(st2));

	if (!S_ISREG(st2.st_mode) && !S_ISLNK(st2.st_mode))
		return build_error("sign: Only regular files may be signed.");

	const EVP_MD *type = NULL;
	if (md == "sha256")
		type = EVP_sha256();
	else if (md == "ripemd160")
		type = EVP_ripemd160();
	else
		type = EVP_sha512();

	EVP_MD_CTX md_ctx;
	EVP_MD_CTX_init(&md_ctx);

	if (EVP_DigestSignInit(&md_ctx, NULL, type, NULL, pkey) != 1)
		return build_error("sign: EVP_DigestSignInit error.");

	int fd = -1;
	if ((fd = open(fname.c_str(), O_RDONLY|O_NOCTTY|O_NONBLOCK)) < 0)
		return build_error("sign::open");

	if (fstat(fd, &st2) < 0) {
		close(fd);
		return build_error("sign::fstat");
	}

	// we need a second check on the fd and we also were passed an lstat()
	// by ftw() but we need a stat on the real file
	if (!S_ISREG(st2.st_mode)) {
		close(fd);
		return build_error("sign: Only regular files may be signed.");
	}

	if (what.find(".content.") != string::npos) {
		char buf[4096];
		ssize_t r = 0;
		memset(buf, 0, sizeof(buf));
		do {
			if ((r = read(fd, buf, sizeof(buf))) < 0) {
				close(fd);
				return build_error("sign::read");
			}
			if (EVP_DigestSignUpdate(&md_ctx, buf, r) != 1) {
				close(fd);
				return build_error("sign: EVP_DigestSignUpdate error.");
			}
		} while (r > 0);
	} else if (what.find(".meta.") != string::npos) {
		char buf[META_SIZE];
		memset(buf, 0, META_SIZE);
		stat2meta(st2, buf);
		if (EVP_DigestSignUpdate(&md_ctx, buf, META_SIZE) != 1)
			return build_error("sign: EVP_DigestSignUpdate error.");
	} else
		return build_error("sign: Invalid kind of signing operation.");

	size_t slen = EVP_PKEY_size(pkey);
	unsigned char sig[4096];
	if (slen > sizeof(sig))
		return build_error("sign: Huh? Insanely large EVP_PKEY_size()!");

	if (EVP_DigestSignFinal(&md_ctx, sig, &slen) != 1) {
		close(fd);
		return build_error("sign::EVP_DigestSignFinal error");
	}
	EVP_MD_CTX_cleanup(&md_ctx);

	string b64sig = "";
	b64sig = b64_encode(string(reinterpret_cast<char *>(sig), slen), b64sig);

	if (dry_run)
		cout<<fname<<" "<<b64sig<<endl;
	else {
		if (fsetxattr(fd, what.c_str(), b64sig.c_str(), b64sig.size(), 0) < 0) {
			close(fd);
			return build_error("sign::fsetxattr:");
		}
	}

	close(fd);
	return 1;
}


int fic::verify(const struct stat *st, const string &what, const string &fname, const string &md)
{
	if (fname.size() == 0 || !pkey)
		return build_error("verify: No filename or key available.");

	struct stat st2;
	if (!st) {
		if (lstat(fname.c_str(), &st2) < 0)
			return build_error("verify::lstat");
	} else
		memcpy(&st2, st, sizeof(st2));

	if (!S_ISREG(st2.st_mode) && !S_ISLNK(st2.st_mode))
		return build_error("verify: Only regular files may be verified.");

	const EVP_MD *type = NULL;
	if (md == "sha256")
		type = EVP_sha256();
	else if (md == "ripemd160")
		type = EVP_ripemd160();
	else
		type = EVP_sha512();

	EVP_MD_CTX md_ctx;
	EVP_MD_CTX_init(&md_ctx);

	if (EVP_DigestVerifyInit(&md_ctx, NULL, type, NULL, pkey) != 1)
		return build_error("verify: EVP_DigestVerifyInit error.");

	int fd = -1;
	if ((fd = open(fname.c_str(), O_RDONLY|O_NOCTTY)) < 0)
		return build_error("verify::open");

	if (fstat(fd, &st2) < 0) {
		close(fd);
		return build_error("verify::fstat");
	}

	if (!S_ISREG(st2.st_mode)) {
		close(fd);
		return build_error("verify: Only regular files may be verified.");
	}

	if (what.find(".content.") != string::npos) {
		char buf[4096];
		ssize_t r = 0;
		memset(buf, 0, sizeof(buf));
		do {
			if ((r = read(fd, buf, sizeof(buf))) < 0) {
				close(fd);
				return build_error("verify::read");
			}
			if (EVP_DigestVerifyUpdate(&md_ctx, buf, r) != 1) {
				close(fd);
				return build_error("verify: EVP_DigestVerifyUpdate error.");
			}
		} while (r > 0);
	} else if (what.find(".meta.") != string::npos) {
		char buf[META_SIZE];
		memset(buf, 0, META_SIZE);
		stat2meta(st2, buf);
		if (EVP_DigestVerifyUpdate(&md_ctx, buf, META_SIZE) != 1)
			return build_error("verify: EVP_DigestVerifyUpdate error.");
	} else
		return build_error("verify: Invalid kind of verify operation.");

	char b64sig[4096];
	int r = fgetxattr(fd, what.c_str(), b64sig, sizeof(b64sig));
	if (r <= 0) {
		close(fd);
		// No hard error but FAILED signature
		if (errno == ENODATA)
			return build_error("verify: FAILED. Missing signature.", 0);
		return build_error("verify::getxattr");
	}

	close(fd);

	string sig = "";
	sig = b64_decode(b64sig, sig);
	if (!sig.size())
		return build_error("verify: Invalid signature format (not base64).");

	r = EVP_DigestVerifyFinal(&md_ctx, (unsigned char *)(sig.c_str()), sig.size());

	if (r < 0)
		return build_error("verify::EVP_DigestSignFinal error");
	else if (r != 1)
		return build_error("verify: Verification FAILED!", 0);

	return 1;
}


int fic::verify_content(const struct stat *st, const string &fname, const string &algo)
{
	return verify(st, xattr_content, fname, algo);
}


int fic::verify_meta(const struct stat *st, const string &fname, const string &algo)
{
	return verify(st, xattr_meta, fname, algo);
}


int fic::sign_content(const struct stat *st, const string &fname, const string &algo)
{
	return sign(st, xattr_content, fname, algo);
}


int fic::sign_meta(const struct stat *st, const string &fname, const string &algo)
{
	return sign(st, xattr_meta, fname, algo);
}

