//
// Created by 朱宇 on 18/08/2017.
//


char r[] = {
        0x43, 0xe3, 0xaf, 0x2a, 0x0d, 0xb9, 0x08, 0x67,
        0x50, 0x97, 0x68, 0x77, 0x65, 0x0f, 0x42, 0x6d,
        0x21, 0x57, 0xa4, 0x5e, 0x10, 0xde, 0x64, 0x6f,
        0xf8, 0x57, 0x19, 0x8b, 0x22, 0x6d, 0xf0, 0xd4,
        0xb2, 0x24, 0x34, 0x08, 0xe0, 0x3b, 0xa7, 0x11,
        0xd9, 0xc3, 0x4c, 0x51, 0xcb, 0x34, 0x44, 0x13,
};


int sign_test(char* file) {
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
    kinv = BN_bin2bn((const unsigned char*)k, sizeof(k), NULL);
    rp = BN_bin2bn((const unsigned char*)r1, sizeof(r1), NULL);
    sp = BN_bin2bn((const unsigned char*)s1, sizeof(s1), NULL);
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

    printf("private: \n");
    priv_key = EC_KEY_get0_private_key(eckey);
    if (priv_key) {
        BN_print_fp(stdout, priv_key);
        putc('\n', stdout);
    }

    char digist[] = {};

    //E1E458E048CB9D2FDA9134A6A927C176E6BFFC899165D4FB8AF94E92D2CB275B605E614C078DAF0E93312CF5D5EB4FB7
    //EDED013970DF665B65119F3829C4F79DC50DE63A709A6BA7FD770AC32897B220CA8616C6CE5DCF01D0D3F6578F195DEB

    //E1E458E048CB9D2FDA9134A6A927C176E6BFFC899165D4FB8AF94E92D2CB275B605E614C078DAF0E93312CF5D5EB4FB7
    //21B2C18EA1D99E282F167858C1D6ACC619CF8FC9C31CD53F121E3CE79F05D81E671BF4F575774032CDC1DA604B21E29C
    result = ECDSA_do_sign_ex((const unsigned char*)digist, sizeof(digist), kinv, rp, eckey);

    BN_print_fp(stdout, result->r);
    putc('\n', stdout);
    BN_print_fp(stdout, result->s);
    putc('\n', stdout);

    result2->r = rp;
    result2->s = sp;
    printf("new sult:\n");
    BN_print_fp(stdout, result2->r);
    putc('\n', stdout);
    BN_print_fp(stdout, result2->s);
    putc('\n', stdout);
    verity = ECDSA_do_verify((const unsigned char*)digist, sizeof(digist),
                             result2, eckey);
    printf("verify: %d\n", verity);

    return 0;
}