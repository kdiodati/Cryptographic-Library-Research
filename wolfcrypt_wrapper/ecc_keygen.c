#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/asn_public.h>
//#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#define MAX_CERT_SIZE 4096
#define TEST_ECC_KEY_SIZE 32
#define TEST_ECC_KEY_CURVE ECC_SECP256R1
//#define TEST_ECC_KEY_CURVE ECC_SECP256K1 //for Koblitz curve

int ecc_keygen(void) {
    int ret;
    byte der[MAX_CERT_SIZE], pem[MAX_CERT_SIZE];
    word32 der_size, pem_size;
    WC_RNG rng;
    ecc_key key;
    FILE *fp;
    
    //WOLFSSL_DEBUGGING_ON();

    //initialize wolfCrypt
    ret = wolfCrypt_Init();
    if (ret != 0) {
        printf("wolfCrypt_Init error : %d\n", ret);
        return -1;
    }

    //initialize RNG
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("wc_InitRng error : %d\n", ret);
        return -1;
    }

    //initialize ECC
    ret = wc_ecc_init(&key);
    if (ret != 0) {
        printf("wc_ecc_init error : %d\n", ret);
        return -1;
    }

    //make the ecc key
    ret = wc_ecc_make_key_ex(&rng, TEST_ECC_KEY_SIZE, &key, TEST_ECC_KEY_CURVE);
    if (ret != 0) {
        printf("wc_ecc_make_key_ex error : %d\n", ret);
        return -1;
    }
    //printf("ECC Key Generated: %d bits\n", TEST_ECC_KEY_SIZE * 8);

    //convert private key to der format
    memset(der, 0 ,sizeof(der));
    ret = wc_EccKeyToDer(&key, der, sizeof(der));
    if (ret < 0) {
        printf("wc_EccKeyToDer error : %d\n", ret);
        return -1;
    }
    der_size = ret;

    //create der file for private key
    fp = fopen("./eccPrivKey.der", "wb");
    if (!fp) {
        printf("Error opening eccPrivKey.der for write\n");
        return -1;
    }
    fwrite(der, der_size, 1, fp);
    fclose(fp);
    printf("ECC Private Key Successfully Exported to eccPrivKey.der\n");

    /*
    //convert der to pem for private key
    memset(pem, 0 , sizeof(pem));
    ret = wc_DER_TO_PEM(der, der_size, pem, sizeof(pem), ECC_PRIVATEKEY_TYPE);
    if (ret < 0) {
        printf("wc_DER_TO_PEM error : %d\n", ret);
        return -1;
    }
    pem_size = ret;

    //create pem file for private key
    fp = fopen("./eccPrivKey.pem", "wb");
    if (!fp) {
        printf("Error opening eccPrivKey.pem for write\n");
        return -1;
    }
    fwrite(pem, pem_size, 1, fp);
    fclose(fp);
    printf("ECC Private Key Exported to eccPrivKey.der\n");
    */

    //create public key
    memset(der, 0, sizeof(der));
    ret = wc_EccPublicKeyToDer(&key, der, sizeof(der), TEST_ECC_KEY_CURVE);
    if (ret < 0) {
        printf("wc_EccPublicKeyToDer error : %d\n", ret);
        return -1;
    }
    der_size = ret;

    //create der file for public key
    fp = fopen("./eccPubKey.der", "wb");
    if (!fp) {
        printf("Error opening eccPubKey.der for write\n");
        return -1;
    }
    fwrite(der, der_size, 1, fp);
    fclose(fp);
    printf("ECC Private Key Successfully Exported to eccPubKey.der\n");

    /*
    //convert der to pem for public key
    memset(pem, 0 , sizeof(pem));
    ret = wc_DER_TO_PEM(der, der_size, pem, sizeof(pem), ECC_PUBLICKEY_TYPE);
    if (ret < 0) {
        printf("wc_DER_TO_PEM error : %d\n", ret);
        return -1;
    }
    pem_size = ret;

    //create pem file for public key
    fp = fopen("./eccPubKey.pem", "wb");
    if (!fp) {
        printf("Error opening eccPubKey.pem for write\n");
        return -1;
    }
    fwrite(pem, pem_size, 1, fp);
    fclose(fp);
    printf("ECC Private Key Exported to eccPubKey.der\n");
    */

    //free resources
    wc_ecc_free(&key);
    wc_FreeRng(&rng);
    wolfCrypt_Cleanup();

    return 1;
}

//TESTING
int main(void) {
    int ret;
    printf("---Running ECC KeyGen---\n");
    clock_t start = clock(), end;
    ret = ecc_keygen();
    end = clock() - start;
    int msec = end * 1000 /CLOCKS_PER_SEC;
    printf("ECC Keygen time: %d msec\n", msec);
    return ret;
}