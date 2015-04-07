#include <stdio.h>
#include <stdlib.h>
#include "binding.h"


// test pubkey.asc privkey.asc key-id filename
int main(int argc, char **argv)
{
	if (argc != 5)
		return -1;

	fic_handle_t *sign = fic_new(argv[2], "sha512", strtoull(argv[3], NULL, 16));
	fic_handle_t *vrfy = fic_new(argv[1], "sha512", strtoull(argv[3], NULL, 16));

	if (fic_sign_content(sign, argv[4]) != 1)
		fprintf(stderr, "Error signing file.\n");

	if (fic_verify_content(vrfy, argv[4]) != 1)
		fprintf(stderr, "Error verifying file.\n");
	else
		printf("Success verifying content.\n");

	if (fic_sign_meta(sign, argv[4]) != 1)
		 fprintf(stderr, "Error signing file.\n");

	if (fic_verify_meta(vrfy, argv[4]) != 1)
		fprintf(stderr, "Error verifying file.\n");
	else
		printf("Success verifying meta.\n");

	fic_free(sign);
	fic_free(vrfy);
	return 0;
}

