/* FullUnlock v4.0 project.
   PolicyEngine implementation.
   
   (C) ultrashot 2012
*/
#ifndef POLICYMSGQUEUE_H
#define POLICYMSGQUEUE_H

typedef enum
{
    ACCESS_DENIED = 0
} FULLUNLOCK_POLICY_MESSAGE_TYPE;

typedef struct
{
    FULLUNLOCK_POLICY_MESSAGE_TYPE type;
    wchar_t userAccount[200];
    wchar_t requestedAccess[500];

} FULLUNLOCK_POLICY_MESSAGE;

#define MSGQUEUE_NAME L"__POLICYMSGQUEUE"
#define MSGQUEUE_EVENT_NAME L"__POLICYMSGQUEUECHANGED"

HANDLE GetPolicyMsgQueue(BOOL writeOrRead);
HANDLE GetPolicyMsgQueueEvent();

void PolicyMsgQueue_Write(FULLUNLOCK_POLICY_MESSAGE msg);

#endif
