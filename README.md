File Integrity Checker
======================

About
-----

_fic_ allows to cryptographically sign and verify files (content and meta data) using
__OpenPGP__ keys and __POSIX__ extended file attributes `(xattrs)`.

Install
-------

    $ make

Next, generate keys using `gpg` or use existing ones. Export them using `gpg`:

    $ gpg --export-secret-key -a foobar > foobar.sec.asc
    $ gpg --export-key -a foobar > foobar.pub.asc

From the _foobar_ user. Note that the _secret key must have no passphrase assigned._ Since you
probably want to create a dedicated key for signing your files, just leave the passphrase empty.
Thats not a security risk, since in most cases you will throw away the secret key after signing
anyway and only keep the public key in place for later verification.


Usage
-----

Lets see which keys can be used:

    $ fic -i -K foobar.sec.asc
    1122334455667788

Thats your key id. There may be multiple key id's if you have a large keyblob.
Sign a file:

    $ fic -k 1122334455667788 -K foobar.sec.asc -S test
    test/testfile.txt SIGNED

This will sign all files in the `test` dir recursively. You can also sign single files. Actually this signs
the _content_ of the file(s). You can also sign the meta info (inode number, permissions etc.) by using
`-s` instead of `-S`.

To verify:

    $ fic -k 1122334455667788 -K foobar.pub.asc -V test
    test/testfile.txt GOODSIG

If the file is tampered with or the signature is removed, you will see:

    $ fic -k 1122334455667788 -K foobar.pub.asc -V test
    test/testfile.txt FAILED

You can also dump the base64 encoded signatuire by hand:

    $ getfattr -d test/testfile.txt
    # file: test/testfile.txt
    user.fic.content.v1.none="V2hhdD8/PyBJIGNhbnQgYmVsaWV2ZSB5b3UgZGlkIHRoYXQhCg=="


_fic_ also allows you to convert __OpenPGP__ keys to the PEM format suitable
for use with __OpenSSL__, by using the `-d` switch.
_fic_ can sign single files or whole directories. Directories are traversed recursively using `nftw(3)`.
You can also use file globs (`*.txt`) which are expanded by the shell, since _fic_ allows multiple files
to be specified.

Misc
----

In case you already have keys in your _gpg_ keyring, thats how you strip off the passphrase:

    $ gpg --edit-key 0x11223344 passwd
    $ gpg -a --export-secret-key 0x11223344

Note that _fic_ is using the long format for handling key id's (64bit). Thats equivalent to use

    $ gpg --list-keys --keyid-format LONG


with _gpg_. However it is __strongly recommended__ to use dedicated keys with _fic_ and not
your EMail key.

