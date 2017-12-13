//
// Created by 朱宇 on 22/07/2017.
//



#ifndef QATCGO_POLLING_H
#define QATCGO_POLLING_H

#include <cpa_types.h>
#include <cpa.h>

void *timer_poll_func(void *ih);

void *event_poll_func(void *ih);


CpaStatus poll_instance(void);

#endif //QATCGO_POLLING_H
