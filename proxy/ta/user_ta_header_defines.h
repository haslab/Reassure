#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include<proxy_ta.h>

#define TA_UUID TA_KE_UUID

#define TA_FLAGS 0

#define TA_STACK_SIZE (256*1024)
#define TA_DATA_SIZE (256*1024)

#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "gp.ta.description", USER_TA_PROP_TYPE_STRING, "TA for performing an attested key exchange" }, \
        {"gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){0x0100} }

#endif
