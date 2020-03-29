#include <stdio.h>
#include <string.h>
#include <time.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#define MAX_CERT_SIZE 4096
#define TEST_ECC_KEY_SIZE 32
#define TEST_ECC_KEY_CURVE ECC_SECP256R1

int ecc_encryptDecrypt() {
    int ret;
    ecc_key priv, pub;
    int maxFwLen = (1024 * 1024);
    int gFwLen = maxFwLen;
    word32 hashLen = SHA256_DIGEST_SIZE;
    word32 sigLenInner = ECC_MAX_SIG_SIZE;
    word32 *sigLen = &sigLenInner;
    int gFwChunkLen = 128;
    byte sigBuf[ECC_MAX_SIG_SIZE];
    byte hashBuf[SHA256_DIGEST_SIZE];
    byte gFwBuf[maxFwLen];
    word32 idx;
    byte der[MAX_CERT_SIZE];
    FILE *fp;
    ecEncCtx *ctx;
    WC_RNG rng;

    //initialize wolfCrypt
    ret = wolfCrypt_Init();
    if (ret != 0) {
        printf("wolfCrypt_Init error : %d\n", ret);
        return -1;
    }

    //initialize rng
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("wc_InitRng error : %d\n", ret);
        return -1;
    }

    //get ctx to use for encrypting/decrypting
    ctx = wc_ecc_ctx_new(REQ_RESP_CLIENT, &rng);
    if(ctx == NULL) {
        printf("wc_ecc_ctx_new failed!\n");
        return -1;
    }

    //initialize private key
    ret = wc_ecc_init(&priv);
    if (ret != 0) {
        printf("wc_ecc_init error : %d\n", ret);
        return -1;
    }

    //initialize public key
    ret = wc_ecc_init(&pub);
    if (ret != 0) {
        printf("wc_ecc_init error : %d\n", ret);
        return -1;
    }

    //read der file to private key
    memset(der, 0, sizeof(der));
    fp = fopen("./eccPrivKey.der", "r");
    if (!fp) {
        printf("Error opening eccPrivKey.der for write\n");
        return -1;
    }
    fread(der, sizeof(der), 1, fp);
    wc_EccPrivateKeyDecode(der, &idx, &priv, sizeof(der));
    fclose(fp);

    //printf("Private Key Creation Successful\n");

    //read der file to public key
    memset(der, 0, sizeof(der));
    idx = 0;
    fp = fopen("./eccPubKey.der", "r");
    if (!fp) {
        printf("Error opening eccPrivKey.der for write\n");
        return -1;
    }
    fread(der, sizeof(der), 1, fp);
    wc_EccPublicKeyDecode(der, &idx, &pub, sizeof(der));
    fclose(fp);

    //printf("Public Key Creation Successful\n");

    //init fake firmware data
    int i;
    for (i=0; i<gFwLen; i++) {
        gFwBuf[i] = (byte)i;
        //printf(gFwBuf[i]);
    }

    //hash firmware
    Sha256 sha;
    int len = gFwLen, sz;
    idx = 0;

    ret = wc_InitSha256(&sha);

    while (len > 0) {
        sz = len;
        if (sz > gFwChunkLen) {
            sz = gFwLen;
        }

        ret = wc_Sha256Update(&sha, &gFwBuf[idx], (word32)sz);
        if (ret != 0) {
            printf("Error updating Sha256!\n");
            return -1;
        }

        len -= sz;
        idx += sz;
    }

    if (ret == 0) {
        ret = wc_Sha256Final(&sha, hashBuf);
    }
    //printf("%s\n", hashBuf); //debug

    wc_Sha256Free(&sha);

    //sign hash
    ret = wc_ecc_sign_hash(hashBuf, hashLen, sigBuf, sigLen, &rng, &priv);
    if (ret != 0) {
        printf("Error signing hash!\n");
        return -1;
    }
    //printf("Sign ret %d, sigLen %d\n", ret, *sigLen);

    //test signing
    int is_valid_sig = 0;
    ret = wc_ecc_verify_hash(sigBuf, *sigLen, hashBuf, hashLen, &is_valid_sig, &priv);
    if (ret != 0) {
        printf("Error verifying signature hash!\n");
        return -1;
    }
    printf("Successful ECC Signing!\n");
    //printf("%s\n", sigBuf); //debug

    //free memory
    wc_ecc_free(&pub);
    wc_ecc_free(&priv);
    wolfCrypt_Cleanup();
    return 1;

    /*
    EXAMPLE OF BAD Encryption method, wc_ecc_encrypt uses private and public key for encryption.
    This means both keys must be sent over network, where they could be intercepted, and would require key send to be encrypted themselves,
    leading to requiring another cryptosystem to send keys.


    //print input data
    printf("input: %s\n", in);
    printf("inputsize: %d\n", inSize);
    printf("outputsize: %d\n", outSize);

    //encrypt data
    int oldlen = strlen(in);
    int len = strlen(in);
    int odd = (len % 16);
    if (odd != 0) {
        int addlen = (16 - odd);
        len += addlen;
        if (len > 1024) return -1;
        memset(&in[oldlen], 0, addlen);
    }
    printf("inputsize: %d\n", inSize);
    
    ret = wc_ecc_encrypt(&priv, &pub, in, inSize, out, &outSize, NULL);
    if (ret != 0) {
        printf("wc_ecc_encrypt error : %d\n", ret);
        return -1;
    }

    printf("this worked!\n");

    //print encrypted data
    printf("encrypted: %s\n", out);

    //decrypt data
    byte plain[sizeof(in)];
    ret = wc_ecc_decrypt(&priv, &pub, out, outSize, plain, &inSize, NULL);
    if (ret != 0) {
        printf("wc_ecc_encrypt error : %d\n", ret);
        return -1;
    }

    //print decrypted data
    printf("decrypted: %s\n", plain);
    */
}

//TESTING
int main(void) {
    int ret;
    printf("---Running ECC Test---\n");
    clock_t start = clock(), end;
    ret = ecc_encryptDecrypt();
    end = clock() - start;
    int msec = end * 1000 /CLOCKS_PER_SEC;
    printf("ECC Crypto time: %d msec\n", msec);
    return ret;
}