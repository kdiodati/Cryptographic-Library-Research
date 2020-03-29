//imports
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <wolfssl/options.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/random.h>
//#include <wolfssl/wolfcrypt/hash.h>
//#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/rsa.h>
//#include <wolfssl/wolfcrypt/sha256.h>
//#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>

#define RSA_KEY_SIZE 1024
#define DER_FILE_BUFFER 4096
#define LINE_SIZE 64

//helper functions

void print_byte_array(byte* input_string, int len) {
    int i;
    for (i = 0; i < len; i++) {
        if (i > 0) printf(":");
        printf("%02X", input_string[i]);
        //printf("%s", input_string[i]);
    }
    printf("\n");
}

void string_to_byte_array(char* input, byte* output) {
    int loop = 0, i = 0;

    while(input[loop] != '\0') {
        output[i] = input[loop];
        i++;
        loop++;
    } 
}

//RSA Functions

int rsa_keygen() {
    int ret;
    RsaKey rsaKey;
    WC_RNG rng;

    byte *rsaKeyBuf = NULL, *rsaPubKeyBuf = NULL;
    word32 rsaKeyLen, rsaPubKeyLen;

    FILE *fp;

    //initialize wolfCrypt
    wolfCrypt_Init(); //may not be needed

    //initialize RNG
    ret = wc_InitRng(&rng);
    if(ret != 0) {
        printf("Initializion of RNG failed!\n");
        return 2;
    }

    //initialize Key
    ret = wc_InitRsaKey(&rsaKey, NULL);
    if(ret != 0) {
        printf("Initialization of PrivKey failed!\n");
        return 2;
    }
    //printf("RSA Key Size: %d\n", RSA_KEY_SIZE);

    ret = wc_MakeRsaKey(&rsaKey, RSA_KEY_SIZE, 65537, &rng);
    if(ret != 0) { //using 65537 recommended for exponent
        printf("RSA Make Priv Key Failed!\n");
        return 2;
    }

    //display private key data
    rsaKeyLen = DER_FILE_BUFFER;
    rsaKeyBuf = malloc(rsaKeyLen); //FREE!

    ret = wc_RsaKeyToDer(&rsaKey, rsaKeyBuf, rsaKeyLen);
    if(ret <= 0) {
        printf("RSA private key Der export failed!\n");
        return 2;
    }
    rsaKeyLen = ret;

    //print debug info for priv key
    //printf("RSA Priv Key Len: %d\n", rsaKeyLen);
    //printf("RSA Priv Key : ");
    //print_byte_array(rsaKeyBuf, rsaKeyLen);

    //create der file for private key
    fp = fopen("./rsaPrivKey.der", "wb");
    if (!fp) {
        printf("Error opening rsaPrivKey.der for write\n");
        return -1;
    }
    fwrite(rsaKeyBuf, rsaKeyLen, 1, fp);
    fclose(fp);
    printf("ECC Private Key Successfully Exported to rsaPrivKey.der\n");

    //display public key data
    rsaPubKeyLen = DER_FILE_BUFFER;
    rsaPubKeyBuf = malloc(rsaPubKeyLen); //FREE!

    ret = wc_RsaKeyToPublicDer(&rsaKey, rsaPubKeyBuf, rsaPubKeyLen);
    if(ret <= 0) {
        printf("RSA public key Der export failed!\n");
        return 2;
    }
    rsaPubKeyLen = ret;

    //print debug info for pub key
    //printf("RSA Pub Key Len: %d\n", rsaPubKeyLen);
    //printf("RSA Pub Key : ");
    //print_byte_array(rsaPubKeyBuf, rsaPubKeyLen);

    //create der file for public key
    fp = fopen("./rsaPubKey.der", "wb");
    if (!fp) {
        printf("Error opening rsaPubKey.der for write\n");
        return -1;
    }
    fwrite(rsaPubKeyBuf, rsaPubKeyLen, 1, fp);
    fclose(fp);
    printf("ECC Public Key Successfully Exported to rsaPubKey.der\n");

    wc_FreeRsaKey(&rsaKey);
    wc_FreeRng(&rng);
    free(rsaPubKeyBuf);
    free(rsaKeyBuf);
    wolfCrypt_Cleanup();
    return 1; //return of 1 means function works as intended
}

//TESTING
int main(void) {
    int ret;
    printf("---Running RSA KeyGen---\n");
    clock_t start = clock(), end;
    ret = rsa_keygen();
    end = clock() - start;
    int msec = end * 1000 /CLOCKS_PER_SEC;
    printf("RSA Keygen time: %d msec\n", msec);
    return ret;
}