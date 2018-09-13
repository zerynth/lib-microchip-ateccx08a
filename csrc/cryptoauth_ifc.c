/*
* @Author: lorenzo
* @Date:   2018-05-18 09:26:35
* @Last Modified by:   Lorenzo
* @Last Modified time: 2018-09-04 12:36:54
*/

#define ZERYNTH_PRINTF
#include "zerynth.h"
#include "zerynth_hwcrypto.h"
#include "cryptoauthlib.h"

ATCAIfaceCfg cfg_ateccx08a_i2c = {
    .iface_type             = ATCA_I2C_IFACE,
    .devtype                = ATECC508A,
    .atcai2c.slave_address  = 0x60,
    .atcai2c.bus            = 0,
    .atcai2c.baud           = 100000,
    .wake_delay             = 1000,
    .rx_retries             = 50
};

int cryptoauth_hwcrypto_pkeyslot = -1;

static int cryptoauth_hwcrypto_ec_get_pubkey(uint8_t* public_key) {
    return atcab_get_pubkey(cryptoauth_hwcrypto_pkeyslot, public_key);
}

#define CRYPTOAUTH_RETRY(fun, status, retries) do { \
    while (retries && status) { \
        status = fun; \
        retries--; \
    } \
} while(0)

static int cryptoauth_hwcrypto_digest_sha256( const unsigned char *input, size_t ilen, unsigned char *output ) {
    int status = atcab_sha(ilen, (const uint8_t *)input, output);
    int retries = 20;
    CRYPTOAUTH_RETRY(atcab_sha(ilen, (const uint8_t *)input, output), status, retries);
    return status;
}


static void cryptoauth_hwcrypto_digest_sha256_starts(atca_sha256_ctx_t* ctx) {
    int status = atcab_hw_sha2_256_init((atca_sha256_ctx_t *) ctx);
    int retries = 20;
    CRYPTOAUTH_RETRY(atcab_hw_sha2_256_init((atca_sha256_ctx_t *) ctx), status, retries);
}

static void cryptoauth_hwcrypto_digest_sha256_update(atca_sha256_ctx_t* ctx, const unsigned char *input, size_t ilen) {
    int status = atcab_hw_sha2_256_update(ctx, input, ilen);
    int retries = 20;
    CRYPTOAUTH_RETRY(atcab_hw_sha2_256_update(ctx, input, ilen), status, retries);
}

static void cryptoauth_hwcrypto_digest_sha256_finish(atca_sha256_ctx_t* ctx, unsigned char output[32]) {
    int status = atcab_hw_sha2_256_finish(ctx, output);
    int retries = 20;
    CRYPTOAUTH_RETRY(atcab_hw_sha2_256_finish(ctx, output), status, retries);
}

static void *cryptoauth_hwcrypto_digest_sha256_ctx_alloc(void) {
     void *ctx = gc_malloc( sizeof( atca_sha256_ctx_t ) );
    return( ctx );   
}

/* Implementation that should never be optimized out by the compiler */
static void cryptoauth_hwcrypto_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

static void cryptoauth_hwcrypto_digest_sha256_free(void* ctx) {
    if( ctx == NULL )
        return;
    cryptoauth_hwcrypto_zeroize( ctx, sizeof( atca_sha256_ctx_t ) );
}

static void cryptoauth_hwcrypto_digest_sha256_ctx_free( void *ctx )
{
    cryptoauth_hwcrypto_digest_sha256_free( (atca_sha256_ctx_t *) ctx );
    gc_free( ctx );
}

static int cryptoauth_hwcrypto_ecdsa_secp256r1_sign(const unsigned char *hash, size_t hash_len, 
                                unsigned char *sig, size_t *sig_len)
{
        ATCA_STATUS status = ATCA_SUCCESS;

        uint8_t raw_sig[64];
        uint8_t der_sig_at[80]; // with tag, length and spare bits
        int sig_offset = 3; // to discard tag, length and spare bits from the result
        *sig_len = 80;

        status = atcab_sign(cryptoauth_hwcrypto_pkeyslot, hash, raw_sig);
        atcacert_der_enc_ecdsa_sig_value(raw_sig, der_sig_at, sig_len);
        // discard first elements for atcacert der encoding
        *sig_len -= sig_offset;
        memcpy(sig, der_sig_at + sig_offset, *sig_len);

        return 0;
}

const ZHWCryptoAPIPointers cryptoauth_api_pointers = {
    cryptoauth_hwcrypto_ec_get_pubkey,
    cryptoauth_hwcrypto_ecdsa_secp256r1_sign,
    cryptoauth_hwcrypto_digest_sha256,
    cryptoauth_hwcrypto_digest_sha256_starts,
    cryptoauth_hwcrypto_digest_sha256_update,
    cryptoauth_hwcrypto_digest_sha256_finish,
    cryptoauth_hwcrypto_digest_sha256_ctx_alloc,
    cryptoauth_hwcrypto_digest_sha256_ctx_free
};

const ZHWCryptoInfo cryptoauth_hwinfo = {
    ZHWCRYPTO_KEY_ECKEY
};

C_NATIVE(_cryptoauth_zerynth_hwcrypto_init) {
    NATIVE_UNWARN();

    ATCA_STATUS status = ATCA_SUCCESS;
    int i2c_drv;
    uint32_t i2c_addr, devtype;

    zhwcrypto_api_pointers = &cryptoauth_api_pointers;
    zhwcrypto_info         = &cryptoauth_hwinfo;

    if (parse_py_args("iiii", nargs, args, &i2c_drv, &cryptoauth_hwcrypto_pkeyslot, &i2c_addr, &devtype) != 4)
        return ERR_TYPE_EXC;

    cfg_ateccx08a_i2c.devtype = devtype;
    cfg_ateccx08a_i2c.atcai2c.slave_address = i2c_addr;
    cfg_ateccx08a_i2c.atcai2c.bus = i2c_drv & 0xff;

    if ((status = atcab_init(&cfg_ateccx08a_i2c)) != ATCA_SUCCESS) {
        return ERR_IOERROR_EXC;
    }

    return ERR_OK;
}

C_NATIVE(_cryptoauth_set_privatekey_slot) {
    NATIVE_UNWARN();

    PARSE_PY_INT(cryptoauth_hwcrypto_pkeyslot);

    return ERR_OK;
}


#include "atcacert/atcacert_def.h"

#define CRYPTOAUTH_CERT_SLOTS 4

atcacert_def_t *cryptoauth_cert_defs[CRYPTOAUTH_CERT_SLOTS];
uint8_t *cryptoauth_cred_buffers[CRYPTOAUTH_CERT_SLOTS];
uint8_t *cryptoauth_pubca_buffers[CRYPTOAUTH_CERT_SLOTS];
uint32_t cryptoauth_cred_buffer_lens[CRYPTOAUTH_CERT_SLOTS];

C_NATIVE(_cryptoauth_write_certificate) {
    NATIVE_UNWARN();

    uint32_t certificate_slot, certificate_len;
    uint8_t *certificate;

    if (parse_py_args("is", nargs, args, &certificate_slot, &certificate, &certificate_len) != 2)
        return ERR_TYPE_EXC;

    if (certificate_len != 0) {
        // overwrite credentials buffer, but passed buffer MUST respect pre-loaded structure
        cryptoauth_cred_buffers[certificate_slot] = certificate;
        cryptoauth_cred_buffer_lens[certificate_slot] = certificate_len;        
    }

    ATCA_STATUS status = atcacert_write_cert(cryptoauth_cert_defs[certificate_slot], 
                                            cryptoauth_cred_buffers[certificate_slot],
                                            cryptoauth_cred_buffer_lens[certificate_slot]);

    if (status == ATCA_SUCCESS)
        return ERR_OK;
    return ERR_VALUE_EXC;
}

#define DER_CERTIFICATE_MAX_LEN   512
#define PEM_CERTIFICATE_MAX_LEN   1024

C_NATIVE(_cryptoauth_read_certificate) {
    NATIVE_UNWARN();

    ATCA_STATUS status;
    uint32_t certificate_slot;
    uint8_t ca_slot;
    PARSE_PY_INT(certificate_slot);

    // cryptoauth_pubca_buffers MUST, if set, be at least ALIGNED(2)
    if (((uint32_t) cryptoauth_pubca_buffers[certificate_slot]) & ((uint32_t) 0x01)) {
        // not a pointer, must extract from slot
        ca_slot = ((uint32_t) cryptoauth_pubca_buffers[certificate_slot]) >> 1;

        // get public key buffer from next slot
        cryptoauth_pubca_buffers[certificate_slot] = cryptoauth_pubca_buffers[certificate_slot+1];
        status = atcab_read_pubkey(ca_slot, cryptoauth_pubca_buffers[certificate_slot]);

        if (status != ATCA_SUCCESS) {
            return ERR_VALUE_EXC;            
        }
    }

    uint32_t device_cert_size = DER_CERTIFICATE_MAX_LEN;
    uint8_t* device_cert = gc_malloc(DER_CERTIFICATE_MAX_LEN);
    // ca public key passed to derive X509v3 Authority Key Identifier
    status = atcacert_read_cert(cryptoauth_cert_defs[certificate_slot], cryptoauth_pubca_buffers[certificate_slot], 
                                 device_cert, &device_cert_size);

    if (status != ATCA_SUCCESS) {
        gc_free(device_cert);
        return ERR_VALUE_EXC;    
    }

    uint32_t pem_cert_size = PEM_CERTIFICATE_MAX_LEN;
    uint8_t* pem_cert = gc_malloc(PEM_CERTIFICATE_MAX_LEN);

    status = atcacert_encode_pem_cert(device_cert, device_cert_size, pem_cert, &pem_cert_size);
    gc_free(device_cert);

    if (status != ATCA_SUCCESS) {
        gc_free(pem_cert);
        return ERR_VALUE_EXC;
    }

    *res = pstring_new(pem_cert_size + 1, pem_cert);
    ((PString* )*res)->seq[pem_cert_size] = 0;
    gc_free(pem_cert);

    return ERR_OK;
}

#define PUBKEYLEN 64

C_NATIVE(_cryptoauth_write_pubkey) {
    NATIVE_UNWARN();

    ATCA_STATUS status;
    uint32_t pubkey_slot, pubkeylen;
    uint8_t *pubkey;

    if (parse_py_args("is", nargs, args, &pubkey_slot, &pubkey, &pubkeylen) != 2)
        return ERR_TYPE_EXC;

    if (pubkeylen != PUBKEYLEN) {
        return ERR_TYPE_EXC;
    }

    status = atcab_write_pubkey(pubkey_slot, pubkey);

    if (status != ATCA_SUCCESS) {
        return ERR_VALUE_EXC;
    }
    return ERR_OK;
}

C_NATIVE(_cryptoauth_read_pubkey) {
    NATIVE_UNWARN();

    ATCA_STATUS status;
    uint32_t pubkey_slot;
    PARSE_PY_INT(pubkey_slot);

    uint8_t* pubkey = gc_malloc(PUBKEYLEN);
    status = atcab_read_pubkey(pubkey_slot, pubkey);

    if (status != ATCA_SUCCESS) {
        gc_free(pubkey);
        return ERR_VALUE_EXC;
    }

    *res = pbytes_new(PUBKEYLEN, pubkey);
    gc_free(pubkey);

    return ERR_OK;
}

#if defined(ATECCx08A_INCLUDE_JWT)

#include "jwt/atca_jwt.h"

C_NATIVE(_cryptoauth_encode_jwt) {
    NATIVE_UNWARN();

    atca_jwt_t jwt;
    int rv;

    uint32_t iat, exp, aud_len, jwt_buflen;
    uint8_t *aud, *aud_cstring, *jwt_buf;

    iat = INTEGER_VALUE(args[0]);
    exp = INTEGER_VALUE(args[1]);
    args+=2;
    nargs-=2;

    if (parse_py_args("s", nargs, args, &aud, &aud_len) != 1)
        return ERR_TYPE_EXC;    

    jwt_buflen = 512;
    jwt_buf = gc_malloc(jwt_buflen);

    rv = atca_jwt_init(&jwt, jwt_buf, jwt_buflen);
    if(ATCA_SUCCESS != rv)
        goto exit;

    if(ATCA_SUCCESS != (rv = atca_jwt_add_claim_numeric(&jwt, "iat", iat)))
        goto exit;

    if(ATCA_SUCCESS != (rv = atca_jwt_add_claim_numeric(&jwt, "exp", exp)))
        goto exit;

    aud_cstring = gc_malloc(aud_len);
    memcpy(aud_cstring, aud, aud_len);
    aud_cstring[aud_len] = 0;

    if(ATCA_SUCCESS != (rv = atca_jwt_add_claim_string(&jwt, "aud", aud_cstring))) {
        gc_free(aud_cstring);
        goto exit;
    }

    gc_free(aud_cstring);
    rv = atca_jwt_finalize(&jwt, cryptoauth_hwcrypto_pkeyslot);

exit:
    if (ATCA_SUCCESS != rv) {
        gc_free(jwt_buf);
        *res = MAKE_NONE();
        return ERR_VALUE_EXC;
    }

    *res = pstring_new(jwt.cur, jwt_buf);
    gc_free(jwt_buf);

    return ERR_OK;
}

#endif

#if 0
C_NATIVE(_cryptoauth_test) {
    NATIVE_UNWARN();

    printf("> nice test\n");

    ATCA_STATUS status = ATCA_SUCCESS;

    do {
        printf("> try chip init\n");
        /*Initialize interface on enabling any crypto operation */
        if ((status = atcab_init(&cfg_ateccx08a_i2c)) != ATCA_SUCCESS) {
            break;
        }

        printf("> wakeup\n");
        atcab_wakeup(); 

        printf("> get rev\n");
        uint8_t rev[4];
        status = atcab_info(rev);
        printf("> called info: %i\n", status);
        printf("> revision %i %i %i %i\n", rev[0], rev[1], rev[2], rev[3]);

        const char *message = "Is this really me?";

        // Intermediates for signing test
        uint8_t digest_tmp[32];
        uint8_t signature_tmp[64];
        uint8_t public_key[64];
        uint8_t verified;

        status = atcab_get_pubkey(cryptoauth_hwcrypto_pkeyslot, public_key);
        if (status != ATCA_SUCCESS) {
            printf("atcab_read_pubkey error\n %i", status);
            break;
        }

        printf("public key: ");
        for (int i=0; i<64; i++) {
            printf("%i-", public_key[i]);
        }
        printf("\n");

        status = atcab_sha(strlen(message), (const uint8_t *)message, digest_tmp);
        if (status != ATCA_SUCCESS) {
            printf("atcab_sha error %i\n", status);
            break;
        }


        printf("message digest: ");
        for (int i=0; i<32; i++) {
            printf("%x", digest_tmp[i]);
        }
        printf("\n");

        status = atcab_sign(cryptoauth_hwcrypto_pkeyslot/* key # */, digest_tmp, signature_tmp);
        if (status != ATCA_SUCCESS) {
            printf("atcab_sign error %i\n", status);
            break;
        }
        printf("message signature: ");
        for (int i=0; i<64; i++) {
            printf("%x", signature_tmp[i]);
        }
        printf("\n");


        // Verify generated signature is good
        status = atcab_verify_extern(digest_tmp, signature_tmp, public_key, &verified);
        if (status != ATCA_SUCCESS) {
            printf("atcab_verify_extern error %i\n", status);
            break;
        }
        if (verified) {
            printf("TEST 1 PASSED!\n");
        } else {
            printf("TEST 1 FAILED\n");
            break;
        }

        // Modify message and verify signature is NOT good
        digest_tmp[0] ^= 0x11;
        status = atcab_verify_extern(digest_tmp, signature_tmp, public_key, &verified);
        if (status != ATCA_SUCCESS) {
            printf("atcab_verify_extern error %i\n", status);
            break;
        }
        if (!verified) {
            printf("TEST 2 PASSED!\n");
        } else {
            printf("TEST 2 FAILED\n");
            break;
        }

    } while (0);

    printf("> returning...\n");


    return ERR_OK;
}
#endif
