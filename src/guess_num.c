#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
//#include <openssl/x509.h>
//#include <openssl/rand.h>
#include "cse543-kvs.h"
#include "cse543-cracker.h"
#include "cse543-ssl.h"

/* Defines */
#define MAX_PASSWD       30




int main(int argc, char *argv[])
{ 
  FILE *fp;  // default: replaced if input and lookup files are specified and replaced when kvs_dump is run 
  char *err;
  unsigned int pwdlen;
  char input_passwd[MAX_PASSWD];
  char *passwd;
  char *filename , *crackfile;
  /* Load the human readable error strings for libcrypto */
  ERR_load_crypto_strings();

  /* Load all digest and cipher algorithms */
  OpenSSL_add_all_algorithms();

  /* Load config file, and other important initialisation */
  OPENSSL_config(NULL);

//wenhui test
  /* assert on argc */
  /* main password_file master_passwd crack_file */
  assert( argc == 3 );
 

  /* Open file for input requests, if present */ 
  filename = argv[1];  // read input
  crackfile = argv[2];

  fp = fopen(filename, "r");
  err = fgets(input_passwd, MAX_PASSWD, fp);
  while(err != NULL) {
  	double guessNumber;
  	pwdlen = strlen( input_passwd );
  	memcpy(&passwd, input_passwd, pwdlen + 1); 

  	guessNumber = get_markov_guess_number( &passwd, pwdlen, crackfile );
//      printf("Guess number of %s is %lf \n", input_passwd, guessNumber);
  	err = fgets(input_passwd, MAX_PASSWD, fp);
 } 
  if (argc == 3 ) 
    fclose( fp );
  return 0;
}

