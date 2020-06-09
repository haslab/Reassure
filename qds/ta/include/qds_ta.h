#ifndef TA_QDS_H
#define TA_QDS_H

#define TA_QDS_UUID {0xced14a59, 0xa522, 0x4088, \
                     {0xba, 0x4f, 0xbd, 0x4b, 0xe1, 0xb3, 0xc0, 0x6d}}

#define TA_QDS_CMD_GEN_CSR 1
#define TA_QDS_CMD_GET_KEY 2
#define TA_QDS_CMD_SIGN 3
#define TA_QDS_CMD_VERIFY 4
#define TA_QDS_GET_DC 5

#define ATTEST_PTA_UUID {0x24391e36, 0xb2e9, 0x4278, \
                         {0xb7, 0xc3, 0x3b, 0xa0, 0xdf, 0x88, 0xa2, 0x3e}}

#define ATTEST_PTA_CMD_SIGN 1
#define ATTEST_PTA_CMD_GET_CERT 2

#endif
