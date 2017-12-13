//
// Created by 朱宇 on 18/08/2017.
//
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <stdlib.h>

// random data
char k[] = {
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
};

//DEMO1_R: 2881437C58CA5BFDFC56B4F7E6B054642454A2495C9425634F1756D3FFCC821D56D05DE863B86C111518EFA65E29B7C7
char r1[] = {
        0x28, 0x81, 0x43, 0x7C, 0x58, 0xCA, 0x5B, 0xFD,
        0xFC, 0x56, 0xB4, 0xF7, 0xE6, 0xB0, 0x54, 0x64,
        0x24, 0x54, 0xA2, 0x49, 0x5C, 0x94, 0x25, 0x63,
        0x4F, 0x17, 0x56, 0xD3, 0xFF, 0xCC, 0x82, 0x1D,
        0x56, 0xD0, 0x5D, 0xE8, 0x63, 0xB8, 0x6C, 0x11,
        0x15, 0x18, 0xEF, 0xA6, 0x5E, 0x29, 0xB7, 0xC7,
};
//DEMO1_S: 7D04F847CC347FBAD79EBACBD59AA8BEF0ED6D6D7520D04F32678805B97D80C7C7550F156008EE67794EAAABAFBAD6E6
char s1[] = {
        0x7D, 0x04, 0xF8, 0x47, 0xCC, 0x34, 0x7F, 0xBA,
        0xD7, 0x9E, 0xBA, 0xCB, 0xD5, 0x9A, 0xA8, 0xBE,
        0xF0, 0xED, 0x6D, 0x6D, 0x75, 0x20, 0xD0, 0x4F,
        0x32, 0x67, 0x88, 0x05, 0xB9, 0x7D, 0x80, 0xC7,
        0xC7, 0x55, 0x0F, 0x15, 0x60, 0x08, 0xEE, 0x67,
        0x79, 0x4E, 0xAA, 0xAB, 0xAF, 0xBA, 0xD6, 0xE6,
};

char digest[] = {
        0x61, 0x66, 0x64, 0x61, 0x64, 0x61,
};

int verify_test(char* file) {
    EVP_PKEY *privkey;
    FILE *fp;
    EC_KEY *eckey;
    const EC_GROUP *group = NULL;
    const EC_POINT *pub_key = NULL;
    const EC_POINT *ec_point = NULL;

    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();


    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    BIGNUM *xg = BN_new();
    BIGNUM *yg = BN_new();
    BIGNUM *order = BN_new();

    BIGNUM *kinv;
    BIGNUM *rp;
    BIGNUM *sp;
    int verity = 0;

    const BIGNUM *priv_key;
    ECDSA_SIG* result;
    ECDSA_SIG* result2;

    result2 = ECDSA_SIG_new();
    privkey = EVP_PKEY_new();

    fp = fopen (file, "r");
    PEM_read_PrivateKey( fp, &privkey, NULL, NULL);
    fclose(fp);

    eckey = EVP_PKEY_get1_EC_KEY(privkey);
    group = EC_KEY_get0_group(eckey);
    pub_key = EC_KEY_get0_public_key(eckey);
    ec_point = EC_GROUP_get0_generator(group);

    printf ("p, a, b: \n");
    if (EC_GROUP_get_curve_GFp(group, p, a, b, NULL)) {
        BN_print_fp(stdout, p);
        putc('\n', stdout);
        BN_print_fp(stdout, a);
        putc('\n', stdout);
        BN_print_fp(stdout, b);
        putc('\n', stdout);
    }
    printf("xp, yp: \n");
    if (EC_POINT_get_affine_coordinates_GFp(group, pub_key, x, y, NULL)) {
        BN_print_fp(stdout, x);
        putc('\n', stdout);
        BN_print_fp(stdout, y);
        putc('\n', stdout);
    }

    printf("xg, yg: \n");
    if (EC_POINT_get_affine_coordinates_GFp(group, ec_point, xg, yg, NULL)) {
        BN_print_fp(stdout, xg);
        putc('\n', stdout);
        BN_print_fp(stdout, yg);
        putc('\n', stdout);
    }

    printf("order: \n");
    if (EC_GROUP_get_order(group, order, NULL)) {
        BN_print_fp(stdout, order);
        putc('\n', stdout);
    }
    kinv = BN_bin2bn((const unsigned char*)k, sizeof(k), NULL);

    //result = ECDSA_do_sign_ex((const unsigned char*)digest, sizeof(digest), NULL, NULL, eckey);
    //BN_print_fp(stdout, result->r);
    //putc('\n', stdout);
    //BN_print_fp(stdout, result->s);
    //putc('\n', stdout);
    //char digist[] = {"fada"};
    //E1E458E048CB9D2FDA9134A6A927C176E6BFFC899165D4FB8AF94E92D2CB275B605E614C078DAF0E93312CF5D5EB4FB7
    //EDED013970DF665B65119F3829C4F79DC50DE63A709A6BA7FD770AC32897B220CA8616C6CE5DCF01D0D3F6578F195DEB
    rp = BN_bin2bn((const unsigned char*)r1, sizeof(r1), NULL);
    sp = BN_bin2bn((const unsigned char*)s1, sizeof(s1), NULL);
    result2->r = rp;
    result2->s = sp;
    printf("new sult:\n");
    BN_print_fp(stdout, result2->r);
    putc('\n', stdout);
    BN_print_fp(stdout, result2->s);
    putc('\n', stdout);
    verity = ECDSA_do_verify((const unsigned char*)digest, sizeof(digest),
                        result2, eckey);
    printf("verify: %d\n", verity);

    return 0;
}



int main()
{

    OpenSSL_add_all_algorithms();
    char cert_filestr[] = "../tools/ssl/server_ecdsa.crt";
    char key_filestr[] = "../tools/ssl/server_ecdsa.key";
    verify_test(key_filestr);
    exit(0);
}
