/* FullUnlock v4.0 project.
   PolicyEngine implementation.
   
   (C) ultrashot 2012
*/
#include "stdafx.h"
#include "PolicyMsgQueue.h"

#define RUNNING_IN_POLICYENGINE

// queue handle that we won't close so that it can be accessed system-wide.
static HANDLE hPolicyMsgQueue = NULL;
static HANDLE hPolicyMsgQueueEvent = NULL;

/**
 * Create the policy message queue and its event once.
 */
static inline void
EnsureQueueIsCreated()
{
#ifdef RUNNING_IN_POLICYENGINE
    if (hPolicyMsgQueue == NULL)
        hPolicyMsgQueue = GetPolicyMsgQueue(FALSE);
    if (hPolicyMsgQueueEvent == NULL)
        hPolicyMsgQueueEvent = GetPolicyMsgQueueEvent();
#endif
}

/**
 * Return the policy message queue, creating it if needed.
 *
 * @param writeOrRead  TRUE for the writer end, FALSE for the reader end.
 *
 * @return The message queue handle.
 */
HANDLE
GetPolicyMsgQueue(BOOL writeOrRead)
{
    MSGQUEUEOPTIONS opt;
    opt.dwSize = sizeof(MSGQUEUEOPTIONS);
    opt.dwFlags = MSGQUEUE_NOPRECOMMIT | MSGQUEUE_ALLOW_BROKEN;
    opt.dwMaxMessages = 0;
    opt.cbMaxMessage = sizeof(FULLUNLOCK_POLICY_MESSAGE);
    opt.bReadAccess = writeOrRead;
    HANDLE hMsgQueue = CreateMsgQueue(MSGQUEUE_NAME, &opt);
    return hMsgQueue;
}

/**
 * Return the event signalled when a message is queued.
 *
 * @return The event handle.
 */
HANDLE
GetPolicyMsgQueueEvent()
{
    return CreateEvent(NULL, FALSE, FALSE, MSGQUEUE_EVENT_NAME);
}

static FULLUNLOCK_POLICY_MESSAGE previousMsg = {ACCESS_DENIED, L"", L""};

/**
 * Post a policy message, skipping a consecutive duplicate.
 *
 * @param msg  Message to enqueue.
 */
void
PolicyMsgQueue_Write(FULLUNLOCK_POLICY_MESSAGE msg)
{
    /* double-guard */
    if (previousMsg.type != msg.type ||
        wcscmp(previousMsg.userAccount, msg.userAccount) != 0)
    {
        memcpy(&previousMsg, &msg, sizeof(FULLUNLOCK_POLICY_MESSAGE));

        EnsureQueueIsCreated();

        HANDLE hQueue = GetPolicyMsgQueue(FALSE);
        WriteMsgQueue(hQueue, &msg, sizeof(FULLUNLOCK_POLICY_MESSAGE), INFINITE,
                      0);
        CloseHandle(hQueue);
    }
}
