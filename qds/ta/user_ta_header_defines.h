#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include<qds_ta.h>

#define TA_UUID TA_QDS_UUID

// Allow one instance to handle multiple instances
#define TA_FLAGS (TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION | TA_FLAG_INSTANCE_KEEP_ALIVE)

#define TA_STACK_SIZE (9*1024)
#define TA_DATA_SIZE (9*1024)

#define TA_CURRENT_TA_EXT_PROPERTIES \
    { "gp.ta.description", USER_TA_PROP_TYPE_STRING, "TA for performing qualified digital signatures" }, \
        {"gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){0x0100} }

#endif
