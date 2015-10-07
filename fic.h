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

#ifndef fic_fic_h
#define fic_fic_h

#include <string>
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

extern "C" {
#include <openssl/evp.h>
}


class fic {

	bool dry_run;

	static std::string xattr_content, xattr_meta;

	enum { META_SIZE = 1024 };

	EVP_PKEY *pkey;

	std::string path, err;

	int build_error(const std::string &msg, int r = -1)
	{
		err = "fic::";
		err += msg;
		if (errno) {
			err += ":";
			err += strerror(errno);
		}
		return r;
	}

	int close(int fd)
	{
		if (fd >= 0)
			return ::close(fd);
		return 0;
	}

	int verify(const struct stat *, const std::string &, const std::string &, const std::string &);

	int sign(const struct stat *, const std::string &, const std::string &, const std::string &);

public:
	fic() : dry_run(0), pkey(NULL), path(""), err("")
	{
	}

	~fic()
	{
	}

	const char *why()
	{
		return err.c_str();
	}

	void dryrun(bool d)
	{
		dry_run = d;
	}

	int key(EVP_PKEY *);

	int sign_content(const struct stat *, const std::string &, const std::string &s = "sha512");

	int sign_meta(const struct stat *, const std::string &, const std::string &s = "sha512");

	int verify_content(const struct stat *, const std::string &, const std::string &s = "sha512");

	int verify_meta(const struct stat *, const std::string &, const std::string &s = "sha512");
};


#endif

