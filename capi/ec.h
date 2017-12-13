//
// Created by 朱宇 on 19/08/2017.
//

#ifndef QATCGO_EC_H
#define QATCGO_EC_H

#include <cpa_types.h>
#include <cpa.h>
#include <lac/cpa_cy_ec.h>
#include "utils.h"

//
typedef struct _ec_point {
    Stripe x;
    Stripe y;
}ec_point_t;

//
typedef struct _ec_group {
    // (a, b) elliptic curve coefficient
    Stripe a, b;

    // prime modulus or irreducible polynomial over GF(2^r) 在qat中为q,在openssl中为 field
    Stripe p_or_q;

    //order of the base point G, which shall be prime
    /* Field specification. For curves over GF(p), this is the modulus; for
     * curves over GF(2^m), this is the irreducible polynomial defining the
     * field.
     */
    Stripe order_or_n;

    // EC_POINT_get_affine_coordinates_GF2m or EC_POINT_get_affine_coordinates_GFp
    // (x,y) coordinate of base point G
    Stripe xg, yg;
}ec_group_t;
//
typedef struct ec_key_t {
    /*type of EC curve*/
    CpaCyEcFieldType fieldType;
    // 曲线属性
    ec_group_t group;

    // public key p(X,Y), EC_POINT_get_affine_coordinates_GFp
    ec_point_t pub_key;

    // private key
    Stripe priv_key;
}ec_key_t;

//ec_key_t NewECKey();
#endif //QATCGO_EC_H
