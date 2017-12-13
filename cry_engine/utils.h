//
// Created by 朱宇 on 16/09/2017.
//

#ifndef CRY_UTILS_H
#define CRY_UTILS_H

#define DEBUG(fmt_str, ...)                                              \
          fprintf(stderr, "[DEBUG][%s:%d:%s()] " fmt_str, __FILE__, __LINE__, \
                  __func__, ##__VA_ARGS__)

void qat_hex_dump(const char *func, const char *var, const unsigned char p[],
                  int l);
#define DUMPL(var,p,l) qat_hex_dump(__func__,var,p,l);


void dumpPrint(unsigned char * data, int len);

#endif //CRY_UTILS_H
