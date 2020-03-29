/*
Use line below to install 
./configure --enable-openssh --enable-opensslextra --enable-rsa --enable-keygen --enable-rng --enable-ecc --enable-hkdf --enable-eccencrypt --enable-ecccustcurves && make && sudo make install

*/
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
#include <wolfssl/wolfcrypt/aes.h>
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

int rsa_encryptDecrypt() {
    int ret;
    byte input_string[] = "TestingTesting123!";
    RsaKey privKey, pubKey;
    WC_RNG rng;

    byte rsaKeyBuf[DER_FILE_BUFFER];
    word32 rsaKeyLen = sizeof(rsaKeyBuf);
    word32 idx = 0;
    FILE *fp;

    //initialize wolfCrypt
    wolfCrypt_Init();

    //initialize RNG
    ret = wc_InitRng(&rng);
    if(ret != 0) {
        printf("Initializion of RNG failed!\n");
        return -1;
    }

    //initialize private Key
    ret = wc_InitRsaKey(&privKey, NULL);
    if(ret != 0) {
        printf("Initialization of PrivKey failed!\n");
        return -1;
    }

    //initialize public key
    ret = wc_InitRsaKey(&pubKey, NULL);
    if(ret != 0) {
        printf("Initialization of PubKey failed!\n");
        return -1;
    }

    //set RNG to both keys
    ret = wc_RsaSetRNG(&privKey, &rng);
    if(ret != 0) {
        printf("Private RNG Setting failed!\n");
        return -1;
    }
    ret = wc_RsaSetRNG(&pubKey, &rng);
    if(ret != 0) {
        printf("Public RNG Setting failed!\n");
        return -1;
    }

    //read der to private key
    memset(rsaKeyBuf, 0, sizeof(rsaKeyBuf));
    fp = fopen("./rsaPrivKey.der", "r");
    if (!fp) {
        printf("Error opening rsaPrivKey.der for write\n");
        return -1;
    }
    fread(rsaKeyBuf, sizeof(rsaKeyBuf), 1, fp);
    //decode key from Der format
    ret = wc_RsaPrivateKeyDecode(rsaKeyBuf, &idx, &privKey, rsaKeyLen);
    if (ret != 0) {
        printf("RSA private key import failed! %d\n", ret);
        return -1;
    }
    fclose(fp);
    //printf("RSA Key Size: %d\n", RSA_KEY_SIZE);

    //read der to public key
    memset(rsaKeyBuf, 0, sizeof(rsaKeyBuf));
    fp = fopen("./rsaPubKey.der", "r");
    if (!fp) {
        printf("Error opening rsaPubKey.der for write\n");
        return -1;
    }
    fread(rsaKeyBuf, sizeof(rsaKeyBuf), 1, fp);
    rsaKeyLen = sizeof(rsaKeyBuf);
    idx = 0;
    //decode key from Der format
    ret = wc_RsaPublicKeyDecode(rsaKeyBuf, &idx, &pubKey, rsaKeyLen);
    if (ret != 0) {
        printf("RSA public key import failed! %d\n", ret);
        return -1;
    }
    fclose(fp);
    //end of key grabbing
    
    //print input string
    //printf("Input String: %s\n", input_string);

    //encrypt string with public key (public key stored in private key)
    int string_len = sizeof(input_string);
    int enc_size = wc_RsaEncryptSize(&privKey);
    byte encrypted_string[enc_size];

    ret = wc_RsaPublicEncrypt(input_string, sizeof(input_string), encrypted_string, sizeof(encrypted_string), &pubKey, &rng);
    if (ret < 0) {
        printf("RSA encryption error %d\n", ret);
        return -1;
    }
    //idx = 0;

    //print encrypted string
    /*
    printf("Encrypted String : ");
    print_byte_array(encrypted_string, ret);
    */

    //decrypt string with private key
    byte decrypted_string[enc_size];
    //printf("decrypted_size = %d\n", sizeof(decrypted_string));

    ret = wc_RsaPrivateDecrypt(encrypted_string, sizeof(encrypted_string), decrypted_string, sizeof(decrypted_string), &privKey);
    if (ret < 0) {
        printf("RSA decryption error %d\n", ret);
        return 4;
    }

    //print decrypted string
    //printf("Decrypted String: %s\n", decrypted_string);

    wc_FreeRsaKey(&privKey);
    wc_FreeRsaKey(&pubKey);
    wc_FreeRng(&rng);
    wolfCrypt_Cleanup();
    return 1; //return of 1 means function works as intended
}

//TESTING
int main(void) {
    int ret;
    printf("---Running RSA Test---\n");
    clock_t start = clock(), end;
    ret = rsa_encryptDecrypt();
    end = clock() - start;
    int msec = end * 1000 /CLOCKS_PER_SEC;
    printf("RSA Crypto time: %d msec\n", msec);
    return ret;
}