/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2018, 2018 All Rights Reserved
 * ===========================================================================
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, see <http://www.gnu.org/licenses/>.
 *
 * ===========================================================================
 */

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "jdk_crypto_jniprovider_NativeCrypto.h"










#include <dlfcn.h>

//handleErrors
char *             (* ERR_error_string222)        (unsigned long, char *);
unsigned long      (* ERR_get_error222)           (void);
//sha
const EVP_MD*      (* EVP_sha1222)                (void);
const EVP_MD*      (* EVP_sha256222)              (void);
const EVP_MD*      (* EVP_sha224222)              (void);
const EVP_MD*      (* EVP_sha384222)              (void);
const EVP_MD*      (* EVP_sha512222)              (void);
EVP_MD_CTX*        (* EVP_MD_CTX_new222)          (void);
int                (* EVP_DigestInit_ex222)       (EVP_MD_CTX *, const EVP_MD *, ENGINE *);
int                (* EVP_MD_CTX_copy_ex222)      (EVP_MD_CTX *, const EVP_MD_CTX *);
int                (* EVP_DigestUpdate222)        (EVP_MD_CTX *, const void *, size_t);
int                (* EVP_DigestFinal_ex222)      (EVP_MD_CTX *, unsigned char *, unsigned int *);
int                (* EVP_MD_CTX_reset222)        (EVP_MD_CTX *);
//cbc
void               (* OpenSSL_add_all_algorithms222) (void);
void               (* ERR_load_crypto_strings222)    (void);
EVP_CIPHER_CTX*    (* EVP_CIPHER_CTX_new222)         (void);
void               (* EVP_CIPHER_CTX_free222)        (EVP_CIPHER_CTX *);
const EVP_CIPHER*  (* EVP_aes_128_cbc222)            (void);
const EVP_CIPHER*  (* EVP_aes_192_cbc222)            (void);
const EVP_CIPHER*  (* EVP_aes_256_cbc222)            (void);
int                (* EVP_CipherInit_ex222)          (EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *, const unsigned char *, const unsigned char *, int);
int                (* EVP_CIPHER_CTX_set_padding222) (EVP_CIPHER_CTX *, int);
int                (* EVP_CipherUpdate222)           (EVP_CIPHER_CTX *, unsigned char *, int *, const unsigned char *, int);
int                (* EVP_CipherFinal_ex222)         (EVP_CIPHER_CTX *, unsigned char *, int *);


//gcm
const EVP_CIPHER*  (* EVP_aes_128_gcm222)            (void);
int                (* EVP_CIPHER_CTX_ctrl222)        (EVP_CIPHER_CTX *, int, int, void *);
int                (* EVP_DecryptInit_ex222)         (EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *, const unsigned char *, const unsigned char *);
int                (* EVP_DecryptUpdate222)          (EVP_CIPHER_CTX *, unsigned char *, int *, const unsigned char *, int); 
int                (* EVP_DecryptFinal222)           (EVP_CIPHER_CTX *, unsigned char *, int *); 


int                (* tmp_foo123)                       ( int ); 










/* Structure for OpenSSL Digest context */
typedef struct OpenSSLMDContext {
        EVP_MD_CTX *ctx;
        const EVP_MD *digestAlg;
        unsigned char* nativeBuffer;
} OpenSSLMDContext;

/* Structure for OpenSSL Cipher context */
typedef struct OpenSSLCipherContext {
        unsigned char* nativeBuffer;
        unsigned char* nativeBuffer2;
        EVP_CIPHER_CTX *ctx;
        const EVP_CIPHER* evp_cipher_128;
        const EVP_CIPHER* evp_cipher_256;
} OpenSSLCipherContext;


/* Handle errors from OpenSSL calls */
static void handleErrors(void) {
    unsigned long errCode;

    printf("An error occurred\n");

    while(errCode = (*ERR_get_error222)())
    {
        char *err = (*ERR_error_string222)(errCode, NULL);
        printf("Generating error message\n" );
        printf("%s\n", err);
    }
    abort();
}





/*
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    loadOpenSSL
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_loadOpenSSL
  (JNIEnv *env, jclass thisObj){

	void *handle;
	char *error;

    // ---------- Determine version of openssl ----------

    char * (*OpenSSL_version222) (int);
    char * (*SSLeay_version222)  (int);
    char *openssl_version;

	handle = dlopen ("libcrypto.so",  RTLD_NOW);
    if (!handle) {
        fputs (dlerror(), stderr);
        fprintf(stderr, "FAIL TO LOAD OPENSSL LIBRARY\n");
		fflush(stderr);
        exit(1);
    }

    //new_ossl is 1.1.0 or 1.1.1
    int new_ossl = 1;

    // 1.1.0 or 1.1.1
    OpenSSL_version222 = dlsym(handle, "OpenSSL_version");
    if ((error = dlerror()) != NULL)  {
        fprintf(stderr,"NOT NEW OSSL!!!!!!!!!!!!!!!!!!\n");
        new_ossl = 0;
    }else{
        fprintf(stderr,"NEWOSSL!!!!!!!!!!!\n");
    }

    // 1.0.2
    if (!new_ossl){
        SSLeay_version222 = dlsym(handle, "SSLeay_version");
        if ((error = dlerror()) != NULL)  {
            fprintf(stderr, "Only openssl 1.0.2 and 1.1.0 and 1.1.1 are supported\n");
            fputs(error, stderr);
            exit(1);
        }
    }

    if (new_ossl){
        openssl_version = (*OpenSSL_version222)(0);
        //Only compare "OpenSSL 1.1."
        if (strncmp(openssl_version, "OpenSSL 1.1.0h  27 Mar 2018", 12) != 0 ||
                (openssl_version[12] != '0' && openssl_version[12] != '1')){
            fprintf(stderr, "incompatable OpenSSL version: %s\n", openssl_version);
        }
    } else{
        openssl_version = (*SSLeay_version222)(0);
        //Only compare "OpenSSL 1.0.2"
        if (strncmp(openssl_version, "OpenSSL 1.0.2p  14 Aug 2018", 13) != 0)
            fprintf(stderr, "incompatable OpenSSL version: %s\n", openssl_version);
    }


    fprintf(stderr, "NEW OPENSSL: %d \n", new_ossl);
    fflush(stderr);




    // ---------- Load function for OpenSSL_1.1.1 or 1.1.0 ----------

    //handleErrors
    ERR_error_string222 = dlsym(handle, "ERR_error_string");
    ERR_get_error222    = dlsym(handle, "ERR_get_error");


    //this is for 1.1.0 (1.1.1)
    //sha
    EVP_sha1222   = dlsym(handle, "EVP_sha1");
	if ((error = dlerror()) != NULL)  {
        fprintf(stderr, "loading fail          evp_sha1!!!!!!!!!!!!!!!!!!\n");
}
else{fprintf(stderr, "loading success        evp_sha1!!!!!!!!!!!!!!!!!!\n");
}
    EVP_sha256222 = dlsym(handle, "EVP_sha256");
    EVP_sha224222 = dlsym(handle, "EVP_sha224");
    EVP_sha384222 = dlsym(handle, "EVP_sha384");
    EVP_sha512222 = dlsym(handle, "EVP_sha512");
    if (new_ossl)
        EVP_MD_CTX_new222 = dlsym(handle, "EVP_MD_CTX_new");
    else 
        EVP_MD_CTX_new222 = dlsym(handle, "EVP_MD_CTX_create");
    EVP_DigestInit_ex222 = dlsym(handle, "EVP_DigestInit_ex");
    EVP_MD_CTX_copy_ex222 = dlsym(handle, "EVP_MD_CTX_copy_ex");
    EVP_DigestUpdate222 = dlsym(handle, "EVP_DigestUpdate");
    EVP_DigestFinal_ex222 = dlsym(handle, "EVP_DigestFinal_ex");
    if (new_ossl)
        EVP_MD_CTX_reset222 = dlsym(handle, "EVP_MD_CTX_reset");
    else
        EVP_MD_CTX_reset222 = dlsym(handle, "EVP_MD_CTX_cleanup");



    //cbc
    OpenSSL_add_all_algorithms222 = dlsym(handle, "OpenSSL_add_all_algorithms");
    ERR_load_crypto_strings222    = dlsym(handle, "ERR_load_crypto_strings");
    EVP_CIPHER_CTX_new222         = dlsym(handle, "EVP_CIPHER_CTX_new");
    EVP_CIPHER_CTX_free222        = dlsym(handle, "EVP_CIPHER_CTX_free");
    EVP_aes_128_cbc222            = dlsym(handle, "EVP_aes_128_cbc");
    EVP_aes_192_cbc222            = dlsym(handle, "EVP_aes_192_cbc");
    EVP_aes_256_cbc222            = dlsym(handle, "EVP_aes_256_cbc");
    EVP_CipherInit_ex222          = dlsym(handle, "EVP_CipherInit_ex");
    EVP_CIPHER_CTX_set_padding222 = dlsym(handle, "EVP_CIPHER_CTX_set_padding");
    EVP_CipherUpdate222           = dlsym(handle, "EVP_CipherUpdate");
    EVP_CipherFinal_ex222         = dlsym(handle, "EVP_CipherFinal_ex");



    //gcm


    EVP_aes_128_gcm222            = dlsym(handle, "EVP_aes_128_gcm");
    EVP_CIPHER_CTX_ctrl222        = dlsym(handle, "EVP_CIPHER_CTX_ctrl");
    EVP_DecryptInit_ex222         = dlsym(handle, "EVP_DecryptInit_ex");
    EVP_DecryptUpdate222          = dlsym(handle, "EVP_DecryptUpdate");
    EVP_DecryptFinal222           = dlsym(handle, "EVP_DecryptFinal");


	tmp_foo123                    = dlsym(handle, "foo123");
	


    if ((error = dlerror()) != NULL)  {
        fprintf(stderr, "loading foo fail, only openssl 1.0.2 and 1.1.0 and 1.1.1 are supported\n");
        fputs(error, stderr);
        fflush(stderr);
        exit(1);
    }

	fprintf(stderr,"111 RESULT FROM EVP_sha1: %d\n", (*EVP_sha1222)())  ;



	fprintf(stderr,"111 RESULT FROM FOO: %d\n", (*tmp_foo123)(54321))	;
    fprintf(stderr, "111 address of foo pointer: %p \n", tmp_foo123);
	fflush(stderr);
    dlclose(handle);

}



/* Create Digest context
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    DigestCreateContext
 * Signature: (JI)J
 */
JNIEXPORT jlong JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_DigestCreateContext
  (JNIEnv *env, jclass thisObj, jlong copyContext, jint algoIdx) {
	fprintf(stderr, "222 entering DigestCreateContext \n");
	fprintf(stderr, "222 address of foo pointer: %p \n", tmp_foo123);
	fflush(stderr);
	fprintf(stderr,"222 RESULT FROM FOO: %d\n", (*tmp_foo123)(54321))   ;
	fflush(stderr);
	

    EVP_MD_CTX *ctx;
    const EVP_MD *digestAlg = NULL;
    OpenSSLMDContext *context = NULL;

    switch (algoIdx) {
        case 0:
           // digestAlg = EVP_sha1();
            digestAlg = EVP_sha1();
	//		fprintf(stderr,"sha1 address check    %p\n", EVP_sha1222); 
	//		(*tmp_foo123)(54321);
	//		fflush (stderr);
	//		(*EVP_sha1222)();
            break;
        case 1:
            digestAlg = (*EVP_sha256222)();
            break;
        case 2:
            digestAlg = (*EVP_sha224222)();
            break;
        case 3:
            digestAlg = (*EVP_sha384222)();
            break;
        case 4:
            digestAlg = (*EVP_sha512222)();
            break;
        default:
            assert(0);
    }

    if((ctx = EVP_MD_CTX_create()) == NULL)
        handleErrors();
    fprintf(stderr, "HERE!!!!!!!!!!!!!!!!!!!!!!!!");
    fflush(stderr);

    if(1 != EVP_DigestInit_ex(ctx, digestAlg, NULL))
        handleErrors();


    context = malloc(sizeof(OpenSSLMDContext));
    context->ctx = ctx;
    context->digestAlg = digestAlg;

    if (copyContext != 0) {
        EVP_MD_CTX *contextToCopy = ((OpenSSLMDContext*) copyContext)->ctx;
        EVP_MD_CTX_copy_ex(ctx,contextToCopy);
    }


    return (long)context;
}

/* Update Digest context
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    DigestUpdate
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_DigestUpdate
  (JNIEnv *env, jclass thisObj, jlong c, jbyteArray message, jint messageOffset,
  jint messageLen) {

    OpenSSLMDContext *context = (OpenSSLMDContext*) c;

    if (message == NULL) {
        // Data passed in through direct byte buffer
        if (1 != EVP_DigestUpdate(context->ctx, context->nativeBuffer, messageLen))
            handleErrors();
    } else {
        jboolean isCopy;
        unsigned char* messageNative = (*env)->GetPrimitiveArrayCritical(env, message, &isCopy);
        messageNative = messageNative + messageOffset;

        if (1 != EVP_DigestUpdate(context->ctx, messageNative, messageLen))
            handleErrors();

        (*env)->ReleasePrimitiveArrayCritical(env, message,  NULL, 0);
    }

    return 0;
}

/* Compute and Reset Digest
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    DigestComputeAndReset
 * Signature: (J[BII[BII)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_DigestComputeAndReset
  (JNIEnv *env, jclass thisObj, jlong c, jbyteArray message, jint messageOffset, jint messageLen,
  jbyteArray digest, jint digestOffset, jint digestLen) {

    OpenSSLMDContext *context = (OpenSSLMDContext*) c;

    unsigned int size;
    jboolean isCopy;
    unsigned char* messageNative;
    unsigned char* digestNative;

    if (message != NULL) {
       messageNative = (*env)->GetPrimitiveArrayCritical(env, message, &isCopy);
       messageNative = messageNative + messageOffset;
       if (1 != EVP_DigestUpdate(context->ctx, messageNative, messageLen)) handleErrors();
           (*env)->ReleasePrimitiveArrayCritical(env, message, NULL, 0);
    }

    digestNative = (*env)->GetPrimitiveArrayCritical(env, digest , &isCopy);
    digestNative = digestNative + digestOffset;

    if (1 != EVP_DigestFinal_ex(context->ctx, digestNative, &size))
        handleErrors();

    (*env)->ReleasePrimitiveArrayCritical(env, digest,  NULL, 0);

    EVP_MD_CTX_cleanup(context->ctx);

    if (1 != EVP_DigestInit_ex(context->ctx, context->digestAlg, NULL))
        handleErrors();

    return size;
}

/* Create Cipher context
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    CBCCreateContext
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_CBCCreateContext
  (JNIEnv *env, jclass thisObj, jlong nativeBuffer, jlong nativeBuffer2) {

    EVP_CIPHER_CTX *ctx = NULL;
    OpenSSLCipherContext *context = NULL;

// OpenSSL_add_all_algorithms();
// ERR_load_crypto_strings();

    /* Create and initialise the context */
    if (!(ctx = (*EVP_CIPHER_CTX_new222)()))
        handleErrors();

    context = malloc(sizeof(OpenSSLCipherContext));
    context->nativeBuffer  = (unsigned char*)nativeBuffer;
    context->nativeBuffer2 = (unsigned char*)nativeBuffer2;
    context->ctx = ctx;

    return (long)context;
}

/* Destroy Cipher context
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    CBCDestroyContext
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_CBCDestroyContext
  (JNIEnv *env, jclass thisObj, jlong c) {

     OpenSSLCipherContext *context = (OpenSSLCipherContext*) c;

     (*EVP_CIPHER_CTX_free222)(context->ctx);
     free(context);

}

/* Initialize CBC context
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    CBCInit
 * Signature: (JI[BI[BI)V
 */
JNIEXPORT void JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_CBCInit
  (JNIEnv *env, jclass thisObj, jlong c, jint mode, jbyteArray iv, jint iv_len,
  jbyteArray key, jint key_len) {

    EVP_CIPHER_CTX *ctx = ((OpenSSLCipherContext*)c)->ctx;
    unsigned char* ivNative;
    unsigned char* keyNative;
    jboolean isCopy;
    const EVP_CIPHER * evp_cipher1 = NULL;

    switch(key_len) {
        case 16:
            evp_cipher1 = (*EVP_aes_128_cbc222)();
            break;
        case 24:
            evp_cipher1 = (*EVP_aes_192_cbc222)();
            break;
        case 32:
            evp_cipher1 = (*EVP_aes_256_cbc222)();
            break;
    }

    ivNative  = (unsigned char*)((*env)->GetByteArrayElements(env, iv,  &isCopy));
    keyNative = (unsigned char*)((*env)->GetByteArrayElements(env, key, &isCopy));

    if (1 != (*EVP_CipherInit_ex222)(ctx, evp_cipher1, NULL, keyNative, ivNative, mode))
        handleErrors();

    (*EVP_CIPHER_CTX_set_padding222)(ctx, 0);

    (*env)->ReleaseByteArrayElements(env, iv,  ivNative,  JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, key, keyNative, JNI_ABORT);
}

/* Update CBC context
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    CBCUpdate
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_CBCUpdate
  (JNIEnv *env, jclass thisObj, jlong c, jbyteArray input, jint inputOffset, jint inputLen,
  jbyteArray output, jint outputOffset) {

    EVP_CIPHER_CTX *ctx = (((OpenSSLCipherContext*)c)->ctx);
    int outputLen = -1;

    jboolean isCopy;
    unsigned char* inputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input , &isCopy));
    unsigned char* outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output, &isCopy));

    inputNative = inputNative + inputOffset;
    outputNative = outputNative + outputOffset;

    if(1 != (*EVP_CipherUpdate222)(ctx, outputNative, &outputLen, inputNative, inputLen))
        handleErrors();

    (*env)->ReleasePrimitiveArrayCritical(env, input , NULL, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, output, NULL, 0);

    return outputLen;
}

/* CBC Final Encryption
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    CBCFinalEncrypt
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_CBCFinalEncrypt
  (JNIEnv *env, jclass thisObj, jlong c, jbyteArray input, jint inputOffset, jint inputLen,
  jbyteArray output, jint outputOffset) {

    EVP_CIPHER_CTX *ctx = (((OpenSSLCipherContext*)c)->ctx);

    unsigned char buf[16];

    int outputLen = -1;
    int outputLen1 = -1;

    jboolean isCopy;
    unsigned char* inputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input , &isCopy));
    unsigned char* outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output, &isCopy));

    inputNative    = inputNative  + inputOffset;
    outputNative   = outputNative + outputOffset;

    if (1 != (*EVP_CipherUpdate222)(ctx, outputNative, &outputLen, inputNative, inputLen))
        handleErrors();

    if (1 != (*EVP_CipherFinal_ex222)(ctx, buf, &outputLen1))
        handleErrors();

    (*env)->ReleasePrimitiveArrayCritical(env, input , NULL, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, output, NULL, 0);

    return outputLen+outputLen1;
}

const EVP_CIPHER* evp_gcm_cipher;
int first_time_gcm = 0;

/* GCM Encryption
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    GCMEncrypt
 * Signature: ([BI[BI[BII[BI[BII)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_GCMEncrypt
  (JNIEnv * env, jclass obj, jbyteArray key, jint keyLen, jbyteArray iv, jint ivLen,
  jbyteArray input, jint inOffset, jint inLen, jbyteArray output, jint outOffset,
  jbyteArray aad, jint aadLen, jint tagLen) {

    jboolean isCopy;
    unsigned char* inputNative;
    int len, len_cipher = 0;
    unsigned char* keyNative    = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, key,   &isCopy));
    unsigned char* ivNative     = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, iv,    &isCopy));
    unsigned char* outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output,&isCopy));
    unsigned char* aadNative    = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, aad,   &isCopy));

    EVP_CIPHER_CTX* ctx = NULL;
    if (inLen > 0) {
        inputNative  = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input, &isCopy));
    }

    if (first_time_gcm == 0) {
        //OpenSSL_add_all_algorithms();
        //ERR_load_crypto_strings();
        first_time_gcm = 1;

        evp_gcm_cipher = (*EVP_aes_128_gcm222)();
    } 

    ctx = (*EVP_CIPHER_CTX_new222)();
    if(1 != (*EVP_CipherInit_ex222)(ctx, evp_gcm_cipher, NULL, NULL, NULL, 1 )) /* 1 - Encrypt mode 0 Decrypt Mode*/
        handleErrors();

    if(1 != (*EVP_CIPHER_CTX_ctrl222)(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, NULL))
        handleErrors();

    if(1 != (*EVP_CipherInit_ex222)(ctx, NULL, NULL, keyNative, ivNative, -1))
        handleErrors();

    /* provide AAD */
    if(1 != (*EVP_CipherUpdate222)(ctx, NULL, &len, aadNative, aadLen))
        handleErrors();

    /* encrypt plaintext and obtain ciphertext */
    if (inLen > 0) {
        if(1 != (*EVP_CipherUpdate222)(ctx, outputNative + outOffset, &len, inputNative + inOffset, inLen))
            handleErrors();
        len_cipher = len;
    }

    /* finalize the encryption */
    if(1 != (*EVP_CipherFinal_ex222)(ctx, outputNative + outOffset + len_cipher, &len))
        handleErrors();

    /* Get the tag, place it at the end of the cipherText buffer */
    if(1 != (*EVP_CIPHER_CTX_ctrl222)(ctx, EVP_CTRL_GCM_GET_TAG, tagLen, outputNative + outOffset + len + len_cipher))
        handleErrors();

    (*EVP_CIPHER_CTX_free222)(ctx);

    (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative,   0);
    (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative,    0);
    (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative,0);

    if (inLen > 0) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, 0);
    }

    (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative,  0);
}

/* GCM Decryption
 *
 * Class:     jdk_crypto_jniprovider_NativeCrypto
 * Method:    GCMDecrypt
 * Signature: ([BI[BI[BII[BI[BII)I
 */
JNIEXPORT jint JNICALL Java_jdk_crypto_jniprovider_NativeCrypto_GCMDecrypt
  (JNIEnv * env, jclass obj, jbyteArray key, jint keyLen, jbyteArray iv, jint ivLen,
  jbyteArray input, jint inOffset, jint inLen, jbyteArray output, jint outOffset,
  jbyteArray aad, jint aadLen, jint tagLen) {

    jboolean isCopy;
    unsigned char* inputNative;
    unsigned char* aadNative;
    int ret, len, plaintext_len = 0;
    unsigned char* keyNative    = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, key,   &isCopy));
    unsigned char* ivNative     = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, iv,    &isCopy));
    unsigned char* outputNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, output,&isCopy));

    EVP_CIPHER_CTX* ctx = NULL;

    if (inLen > 0) {
        inputNative  = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, input, &isCopy));
    }

    if (aadLen > 0) {
        aadNative    = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, aad,   &isCopy));
    }

    if (first_time_gcm == 0) {
        //printf("Initializing OpenSSL GCM algorithm-1\n");
        //OpenSSL_add_all_algorithms();
        //ERR_load_crypto_strings();
        first_time_gcm = 1;
        evp_gcm_cipher = (*EVP_aes_128_gcm222)();
    } 

    ctx = (*EVP_CIPHER_CTX_new222)();

    if(1 != (*EVP_CipherInit_ex222)(ctx, evp_gcm_cipher, NULL, NULL, NULL, 0 )) /* 1 - Encrypt mode 0 Decrypt Mode*/
        handleErrors();

    if(1 != (*EVP_CIPHER_CTX_ctrl222)(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!(*EVP_DecryptInit_ex222)(ctx, NULL, NULL, keyNative, ivNative))
        handleErrors();

    /* Provide any AAD data */
    if (aadLen > 0) {
        if (!(*EVP_DecryptUpdate222)(ctx, NULL, &len, aadNative, aadLen))
            handleErrors();
    }

    if (inLen - tagLen > 0) {
        if(!(*EVP_DecryptUpdate222)(ctx, outputNative + outOffset, &len, inputNative + inOffset, inLen - tagLen))
            handleErrors();

        plaintext_len = len;
    }

    if(!(*EVP_CIPHER_CTX_ctrl222)(ctx, EVP_CTRL_GCM_SET_TAG, tagLen, inputNative + inOffset + inLen - tagLen))
        handleErrors();

    ret = (*EVP_DecryptFinal222)(ctx, outputNative + outOffset + len, &len);

    (*EVP_CIPHER_CTX_free222)(ctx);

    (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative,   0);
    (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative,    0);
    (*env)->ReleasePrimitiveArrayCritical(env, output, outputNative,0);

    if (inLen > 0) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, 0);
    }

    if (aadLen > 0) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative,  0);
    }

    if (ret > 0) {
        /* Successful Decryption */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Tag Mismatch */
        return -1;
    }
}
