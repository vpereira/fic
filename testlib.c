#include <stdio.h>
#include <stdlib.h>
#include "binding.h"


// test pubkey.asc privkey.asc key-id filename
int main(int argc, char **argv)
{
	if (argc != 5)
		return -1;

	fic_handle_t *fh = fic_new(argv[2], "sha512", strtoull(argv[3], NULL, 16));

	if (fic_sign_content(fh, argv[4]) != 1)
		fprintf(stderr, "Error signing file.\n");

	fic_free(fh);
	fh = fic_new(argv[1], "sha512", strtoull(argv[3], NULL, 16));

	if (fic_verify_content(fh, argv[4]) != 1)
		fprintf(stderr, "Error verifying file.\n");
	else
		printf("Success.\n");

	fic_free(fh);
	return 0;
}

