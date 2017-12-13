//
// Created by 朱宇 on 05/09/2017.
//

#ifndef CRY_PROT_H
#define CRY_PROT_H

typedef struct _Buff {
    int size;
    char* data;
} Buff;

typedef struct _Request {
    char sni[4];
    char payload[2048];
} Request;


#endif //CRY_PROT_H
