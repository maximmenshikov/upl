#include "stdafx.h"

extern "C" BOOL LVModGetAuthorization(HANDLE hEvent);

/**
 * Forward the policy-rule authorization request to the loader verifier.
 *
 * @param hEvent  Authorization event handle.
 *
 * @return Result of LVModGetAuthorization().
 */
BOOL
PolicyRuleGetAuthorization(HANDLE hEvent)
{
    return LVModGetAuthorization(hEvent);
}
