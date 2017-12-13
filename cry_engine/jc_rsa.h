//
// Created by 朱宇 on 04/09/2017.
//

#ifndef CRY_JC_RSA_H
#define CRY_JC_RSA_H

# include <openssl/rsa.h>

/* Qat engine RSA methods declaration */

RSA_METHOD *qat_get_RSA_methods(void);

void qat_free_RSA_methods(void);

#endif //CRY_JC_RSA_H
