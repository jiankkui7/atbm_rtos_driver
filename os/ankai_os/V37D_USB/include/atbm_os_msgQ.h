#ifndef ATBM_OS_MSGQ_H
#define ATBM_OS_MSGQ_H
#include "rtdef.h"
typedef struct rt_messagequeue atbm_os_msgq;
atbm_int8 atbm_os_MsgQ_Create(atbm_os_msgq *pmsgQ, atbm_uint32 *pstack, atbm_uint32 length);
atbm_int8 atbm_os_MsgQ_Delete(atbm_os_msgq *pmsgQ);
atbm_int8 atbm_os_MsgQ_Recv(atbm_os_msgq *pmsgQ, atbm_void *pbuf, atbm_uint32 val);
atbm_int8 atbm_os_MsgQ_Send(atbm_os_msgq *pmsgQ, atbm_void *pbuf, atbm_uint32 val);

#endif /* ATBM_OS_MSGQ_H */

