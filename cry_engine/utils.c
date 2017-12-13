//
// Created by 朱宇 on 16/09/2017.
//

#include "utils.h"
#include <stdio.h>

void dumpPrint(unsigned char * data, int len)
{
    int i;
    printf("total len: %d\n", len);
    for(i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

void qat_hex_dump(const char *func, const char *var, const unsigned char p[],
                  int l)
{
    int i;

    fprintf(stderr, "%s: %s: Length %d, Address %p", func, var, l, p);
    if (NULL != p && l != 0) {
        for (i = 0; i < l; i++) {
            if (i % 16 == 0)
                fputc('\n', stderr);
            else if (i % 8 == 0)
                fputs("- ", stderr);
            fprintf(stderr, "%02x ", p[i]);
        }
    }
    fputc('\n', stderr);
}

