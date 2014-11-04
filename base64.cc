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

#include <string>
#include <cstring>


static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


using namespace std;

/* The base64 routines have been taken from the Samba 3 source (GPL)
 * and have been C++-ified
 */
string &b64_decode(const string &src, string &dst)
{
	int bit_offset, byte_offset, idx, i = 0, n = 0, j = 0;
	const char *p = NULL;

	dst = "";
	dst.resize(src.size()*4 + 1, 0);
	while (src[j] && (p = strchr(b64, src[j]))) {
		idx = (int)(p - b64);
		byte_offset = (i*6)/8;
		bit_offset = (i*6)%8;
		dst[byte_offset] &= ~((1<<(8-bit_offset))-1);
		if (bit_offset < 3) {
			dst[byte_offset] |= (idx << (2-bit_offset));
			n = byte_offset+1;
		} else {
			dst[byte_offset] |= (idx >> (bit_offset-2));
			dst[byte_offset+1] = 0;
			dst[byte_offset+1] |= (idx << (8-(bit_offset-2))) & 0xFF;
			n = byte_offset+2;
		}
		j++; i++;
	}

	if (src[j] == '=')
		n -= 1;

	dst.resize(n);
	return dst;
}


string &b64_encode(const string &src, string &dst)
{
	unsigned int bits = 0;
	int char_count = 0, i = 0;

	dst = "";
	string::size_type len = src.size();
	while (len--) {
		unsigned int c = (unsigned char)src[i++];
		bits += c;
		char_count++;
		if (char_count == 3) {
			dst += b64[bits >> 18];
			dst += b64[(bits >> 12) & 0x3f];
			dst += b64[(bits >> 6) & 0x3f];
	    		dst += b64[bits & 0x3f];
		    	bits = 0;
		    	char_count = 0;
		} else	{
	    		bits <<= 8;
		}
    	}
	if (char_count != 0) {
		bits <<= 16 - (8 * char_count);
		dst += b64[bits >> 18];
		dst += b64[(bits >> 12) & 0x3f];
		if (char_count == 1) {
			dst += '=';
			dst += '=';
		} else {
			dst += b64[(bits >> 6) & 0x3f];
			dst += '=';
		}
	}
	return dst;
}

