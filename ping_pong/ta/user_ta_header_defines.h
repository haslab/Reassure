#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include<ping_pong_ta.h>

#define TA_UUID TA_PP_UUID

#define TA_FLAGS 0

#define TA_STACK_SIZE (2*1024)
#define TA_DATA_SIZE (2*1024)

#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "gp.ta.description", USER_TA_PROP_TYPE_STRING, "Ping pong TA" }, \
        {"gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){0x0100} }

#endif
