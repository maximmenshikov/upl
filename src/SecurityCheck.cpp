#include "stdafx.h"
#include "SecurityCheck.h"
#include "PrivilegeCheck.h"
#include "Branches.h"
#include "AccountManager.h"
#include "PolicyMsgQueue.h"
#include "adb7.h"

/**
 * Pre-authorization decision: grant unsigned native DLL loads for
 * privileged accounts and queue denials for the rest.
 *
 * @param accountName     Caller SID name.
 * @param hIri            Resource IRI (may be NULL).
 * @param szIri           Resource IRI as a string (may be NULL).
 * @param hPolicy         Policy object handle.
 * @param policyClass     Policy class string (may be NULL).
 * @param policySubClass  Policy sub-class string (may be NULL).
 * @param callerId        Originating export id.
 * @param processed       Out: set TRUE when this check made the decision.
 *
 * @return TRUE if access is granted.
 */
BOOL
PrePrivilegeCheck(wchar_t *accountName, HIRI hIri, wchar_t *szIri,
                  void *hPolicy, LPCWSTR policyClass, LPCWSTR policySubClass,
                  int callerId, BOOL *processed)
{
    DWORD resultReason = -1;
    BOOL result = FALSE;
#ifdef DEBUG_ENABLED
    int ticks = GetTickCount();
#endif

    HIRI hTempIri = NULL;
    if (szIri)
    {
        HMUTABLEIRI hMiri = NULL;
        if (IriCreateFromString(szIri, IRI_ENCODING_IRI, &hMiri) != S_OK)
            return FALSE;

        if (IriMakeConstantEx(&hMiri, &hTempIri) != S_OK)
            return FALSE;

        if (hMiri)
            IriMutableClose(hMiri);

        hIri = hTempIri;
    }
    else if (policyClass && policySubClass)
    {
        HMUTABLEIRI hMiri = NULL;
        if (IriCreateFromString(L"/RESOURCES", IRI_ENCODING_IRI, &hMiri) !=
            S_OK)
            return FALSE;

        wchar_t str[0x80];
        wcscpy(str, L"GLOBAL");
        LCMapString(0x7F, 0x200, accountName, -1, str, 0x80);
        IriAppendSegment(hMiri, str, 0);
        IriAppendSegment(hMiri, policyClass, 0);
        IriAppendSegment(hMiri, policySubClass, 0);

        if (IriMakeConstantEx(&hMiri, &hTempIri) != S_OK)
            return FALSE;

        if (hMiri)
            IriMutableClose(hMiri);

        hIri = hTempIri;
    }

    if (IsRevokeCertsBranch(hIri) == TRUE)
    {

        RETAILMSG(DEBUGLOG, (L"[%X]\t = revoke certs branch\r\n", ticks));

        resultReason = 3;
        result = FALSE;
        *processed = TRUE;
    }
    else if (IsInThirdPartyGroup(accountName)) // || isMeux)
    {

        RETAILMSG(
            DEBUGLOG,
            (L"[%X] PrePrivilegeCheck(accountName = %ls, hIri = %X, szIri = %ls, hPolicy = %X, policyClass = %ls, policySubClass = %ls, callerId = %X)++ \r\n",
             ticks, accountName, hIri, szIri, hPolicy, policyClass,
             policySubClass, callerId));

        __try
        {
            if (IsUnsignedNativeDllBranch(hIri))
            {
                BOOL priv = GetPrivileged(accountName);
                if (priv)
                {
                    resultReason = 1;
                    result = TRUE;
                }
                else
                {
                    FULLUNLOCK_POLICY_MESSAGE msg;
                    memset(&msg, 0, sizeof(msg));
                    msg.type = ACCESS_DENIED;
                    wcscpy_s(msg.userAccount, 200, accountName);

                    HRESULT hr =
                        IriGetAsString(hIri, 0, IRI_ALL_REMAINING_SEGMENTS, 0,
                                       msg.requestedAccess, 500, NULL);
                    RETAILMSG(
                        DEBUGLOG,
                        (L"[%X]\tIriGetAsString(hIri = %X) = %X, string = \"%ls\"\r\n",
                         ticks, hIri, hr, msg.requestedAccess));
                    if (hr == S_OK)
                        PolicyMsgQueue_Write(msg);
                    resultReason = 2;
                    result = FALSE;
                }
                *processed = TRUE;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            resultReason = 0xFFFF;
            result = FALSE;
            *processed = FALSE;
        }
    }
    else
    {
        resultReason = 0x80000000;
        result = TRUE;
    }
    if (hTempIri)
        IriClose(hTempIri);
    RETAILMSG(
        DEBUGLOG,
        (L"[%X]\tRESULT: PRE access %ls (reason = %X)\r\n", ticks,
         *processed ? (result ? L"GRANTED" : L"DENIED") : L"NOT SPECIFIED",
         resultReason));
    return result;
}

/**
 * Post-authorization decision: apply the wipe, full-trust, AccountManager
 * and ADB-branch rules for third-party accounts.
 *
 * @param accountName     Caller SID name.
 * @param hIri            Resource IRI (may be NULL).
 * @param szIri           Resource IRI as a string (may be NULL).
 * @param hPolicy         Policy object handle.
 * @param policyClass     Policy class string (may be NULL).
 * @param policySubClass  Policy sub-class string (may be NULL).
 * @param callerId        Originating export id.
 * @param processed       Out: set TRUE when this check made the decision.
 *
 * @return TRUE if access is granted.
 */
BOOL
PostPrivilegeCheck(wchar_t *accountName, HIRI hIri, wchar_t *szIri,
                   void *hPolicy, LPCWSTR policyClass, LPCWSTR policySubClass,
                   int callerId, BOOL *processed)
{
    DWORD resultReason = -1;
    BOOL result = FALSE;
#ifdef DEBUG_ENABLED
    int ticks = GetTickCount();
#endif

    if (IsInThirdPartyGroup(accountName))
    {
        HIRI hTempIri = NULL;
        if (szIri)
        {
            HMUTABLEIRI hMiri = NULL;
            if (IriCreateFromString(szIri, IRI_ENCODING_IRI, &hMiri) != S_OK)
                return FALSE;

            if (IriMakeConstantEx(&hMiri, &hTempIri) != S_OK)
                return FALSE;

            if (hMiri)
                IriMutableClose(hMiri);

            hIri = hTempIri;
        }
        else if (policyClass && policySubClass)
        {
            HMUTABLEIRI hMiri = NULL;
            if (IriCreateFromString(L"/RESOURCES", IRI_ENCODING_IRI, &hMiri) !=
                S_OK)
                return FALSE;

            wchar_t str[0x80];
            wcscpy(str, L"GLOBAL");
            LCMapString(0x7F, 0x200, accountName, -1, str, 0x80);
            IriAppendSegment(hMiri, str, 0);
            IriAppendSegment(hMiri, policyClass, 0);
            IriAppendSegment(hMiri, policySubClass, 0);

            if (IriMakeConstantEx(&hMiri, &hTempIri) != S_OK)
                return FALSE;

            if (hMiri)
                IriMutableClose(hMiri);

            hIri = hTempIri;
        }

        RETAILMSG(
            DEBUGLOG,
            (L"[%X] PostPrivilegeCheck(accountName = %ls, hIri = %X, szIri = %ls, hPolicy = %X, policyClass = %ls, policySubClass = %ls, callerId = %X)++ \r\n",
             ticks, accountName, hIri, szIri, hPolicy, policyClass,
             policySubClass, callerId));

        __try
        {
            if (hIri)
            {
                if (IsWipeBranch(hIri) == TRUE)
                {
                    RETAILMSG(DEBUGLOG, (L"[%X]\t = wipe branch\r\n", ticks));
                    resultReason = 2;
                    result = FALSE;
                    goto L_exit;
                }
            }

            if (IsFullTrustModeEnabled() == TRUE)
            {
                RETAILMSG(DEBUGLOG,
                          (L"[%X]\t = full trust enabled\r\n", ticks));
                resultReason = 3;
                result = TRUE;
                goto L_exit;
            }

            if (wcscmp(accountName, ACCID_ACCOUNTMANAGER) == 0)
            {
                RETAILMSG(DEBUGLOG,
                          (L"[%X]\t = AccountManager\r\n", ticks, accountName));
                resultReason = 4;
                result = TRUE;
                goto L_exit;
            }

            result = GetPrivileged(accountName);
            resultReason = 5;
            if (hIri)
            {
                if (result == TRUE)
                {
                    if (IsAdbFunctionBranch(hIri) == TRUE)
                    {
                        RETAILMSG(DEBUGLOG, (L"[%X]\t = adb branch\r\n", ticks,
                                             accountName));
                        resultReason = 6;
                        result = FALSE;
                        goto L_exit;
                    }
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            resultReason = 0xFFFF;
            result = FALSE;
        }
    L_exit:
        if (hTempIri)
            IriClose(hTempIri);
    }
    else
    {
        result = TRUE;
        resultReason = 0x80000000;
    }
    *processed = TRUE;
    RETAILMSG(
        DEBUGLOG,
        (L"[%X]\tRESULT: POST access %ls (reason = %X)\r\n", ticks,
         *processed ? (result ? L"GRANTED" : L"DENIED") : L"NOT SPECIFIED",
         resultReason));
    return result;
}
