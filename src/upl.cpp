/* FullUnlock v4.0 project.
   PolicyEngine implementation.
   
   (C) ultrashot 2012
*/
#include "stdafx.h"
#include "adb7.h"
#include "AccountManager.h"
#include "iri.h"
#include "PolicyMsgQueue.h"
#include "Branches.h"
#include "PrivilegeCheck.h"
#include "PolicyEngine.h"
#include "BuildIri.h"
#include "SecurityCheck.h"

#pragma comment(linker, "/ALIGN:4096")

typedef struct
{
    DWORD functions[36];
} FUNCTIONTABLE;

FUNCTIONTABLE funcTable;

extern "C" HRESULT CeGetOwnerAccount(HANDLE hProcess, PACCTID accountId,
                                     DWORD cbSize);

typedef BOOL (*POLICYCHECKBYCANONICALNAMEDIRECT)(
    __in HIRI hiriCanonicalName, __in HANDLE hSubjectToken,
    __in ACCESS_MASK amAccessRequested, __in_opt DWORD dwFlags,
    __in_opt HANDLE hAdditionalContext);
/**
 * Authorize a subject against a canonical-name IRI, blocking Zune
 * restriction checks and applying the pre-privilege decision.
 *
 * @param hiriCanonicalName   Canonical resource name in IRI form.
 * @param hSubjectToken       Token of the subject requiring access.
 * @param amAccessRequested   Requested access mask.
 * @param dwFlags             Optional request flags.
 * @param hAdditionalContext  Optional additional context handle.
 *
 * @return TRUE if access is allowed, FALSE if denied (GetLastError() is set).
 */
BOOL
PolicyCheckByCanonicalNameDirect(__in HIRI hiriCanonicalName,
                                 __in HANDLE hSubjectToken,
                                 __in ACCESS_MASK amAccessRequested,
                                 __in_opt DWORD dwFlags,
                                 __in_opt HANDLE hAdditionalContext)
{
    POLICYCHECKBYCANONICALNAMEDIRECT old =
        (POLICYCHECKBYCANONICALNAMEDIRECT)funcTable.functions[0x10 / 4];

#ifdef DEBUG_ENABLED
    int ticks = GetTickCount();
#endif

    ACCTID account = 0;
    CeGetOwnerAccount(hSubjectToken, &account, sizeof(HANDLE));

    wchar_t name[200];
    GetAccountName(account, name, 200);

    wchar_t wsIri[500] = {0};
    IriGetAsString(hiriCanonicalName, 0, IRI_ALL_REMAINING_SEGMENTS, 0, wsIri,
                   500, NULL);

    RETAILMSG(
        DEBUGLOG,
        (L"[%X] PolicyCheckByCanonicalNameDirect(10)++ (%ls, %ls, %X)\r\n",
         ticks, wsIri, name, amAccessRequested, dwFlags));

    if (amAccessRequested == 4 && dwFlags == 0 && hAdditionalContext == NULL)
    {
        /* zune fuckup */
        if (IsZuneRestrictedBranch(hiriCanonicalName))
        {
            RETAILMSG(
                1,
                (L"[%X] PolicyCheckByCanonicalNameDirect(10): ZuneBranchCheck: found, disabled\r\n",
                 ticks, name));

            // Yeah, that's Zune! Let's cheat.

            // Seems to be a request we need to work with.
            // Let's disable it.

            SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
            return FALSE;
        }
    }
    RETAILMSG(
        1,
        (L"[%X] PolicyCheckByCanonicalNameDirect(10): ZuneBranchCheck: not found\r\n",
         ticks, name));

    BOOL prePrivCheckProcessed = FALSE;
    BOOL prePrivCheckResult =
        PrePrivilegeCheck(name, hiriCanonicalName, NULL, NULL, NULL, NULL, 0x10,
                          &prePrivCheckProcessed);

    RETAILMSG(
        DEBUGLOG,
        (L"[%X] PolicyCheckByCanonicalNameDirect(10): preProcessed = %d, preCheckResult = %d\r\n",
         ticks, prePrivCheckProcessed, prePrivCheckResult));
    if (prePrivCheckProcessed)
    {
        if (prePrivCheckResult)
            SetLastError(S_OK);
        else
            SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
        return prePrivCheckResult;
    }

    int res = old(hiriCanonicalName, hSubjectToken, amAccessRequested, dwFlags,
                  hAdditionalContext);
    HRESULT hTempError = GetLastError();
    RETAILMSG(
        DEBUGLOG,
        (L"[%X] PolicyCheckByCanonicalNameDirect(10): executed stock handler, res = %d, lasterror = %X\r\n",
         ticks, res, hTempError));

    if (res == FALSE && hTempError == ERROR_ACCESS_DISABLED_BY_POLICY)
    {
        BOOL postPrivCheckProcessed = FALSE;
        BOOL postPrivCheckResult =
            PostPrivilegeCheck(name, hiriCanonicalName, NULL, NULL, NULL, NULL,
                               0x2C, &postPrivCheckProcessed);
        RETAILMSG(
            DEBUGLOG,
            (L"[%X] PolicyCheckByCanonicalNameDirect(10): postProcessed = %d, postCheckResult = %d\r\n",
             ticks, postPrivCheckProcessed, postPrivCheckResult));
        if (postPrivCheckProcessed)
        {
            res = postPrivCheckResult;
            hTempError = res ? S_OK : ERROR_ACCESS_DISABLED_BY_POLICY;
        }
    }
    if (res == TRUE)
        SetLastError(ERROR_SUCCESS);
    else
        SetLastError(hTempError);
L_exit:
    return res;
}

typedef BOOL (*POLICYCHECKBYCANONICALNAME)(__in LPWSTR lpwszCanonicalName,
                                           __in HANDLE hSubjectToken,
                                           __in ACCESS_MASK amAccessRequested,
                                           __in_opt DWORD dwFlags,
                                           __in_opt HANDLE hAdditionalContext);

/**
 * Authorize a subject against a canonical resource name given as a string.
 *
 * @param lpwszCanonicalName  Canonical resource name as a string.
 * @param hSubjectToken       Token of the subject requiring access.
 * @param amAccessRequested   Requested access mask.
 * @param dwFlags             Optional request flags.
 * @param hAdditionalContext  Optional additional context handle.
 *
 * @return TRUE if access is allowed, FALSE if denied (GetLastError() is set).
 */
BOOL
PolicyCheckByCanonicalName(__in LPWSTR lpwszCanonicalName,
                           __in HANDLE hSubjectToken,
                           __in ACCESS_MASK amAccessRequested,
                           __in_opt DWORD dwFlags,
                           __in_opt HANDLE hAdditionalContext)
{
    POLICYCHECKBYCANONICALNAME old =
        (POLICYCHECKBYCANONICALNAME)funcTable.functions[0x14 / 4];
#ifdef DEBUG_ENABLED
    int ticks = GetTickCount();
#endif
    ACCTID account = 0;
    CeGetOwnerAccount(hSubjectToken, &account, sizeof(HANDLE));

    wchar_t name[200];
    GetAccountName(account, name, 200);

    RETAILMSG(DEBUGLOG,
              (L"[%X] PolicyCheckByCanonicalName(14)++ (%ls, %ls, %X)\r\n",
               ticks, lpwszCanonicalName, name, amAccessRequested, dwFlags));

    if (lpwszCanonicalName)
    {
        // Zune pre-check
        if (amAccessRequested == 4 && dwFlags == 0 &&
            hAdditionalContext == NULL)
        {
            HMUTABLEIRI hMiri = NULL;
            HIRI hIri = NULL;

            BOOL found = FALSE;
            if (IriCreateFromString(lpwszCanonicalName, IRI_ENCODING_IRI,
                                    &hMiri) == S_OK)
            {
                if (IriMakeConstantEx(&hMiri, &hIri) == S_OK)
                {
                    /* zune fuckup */
                    if (IsZuneRestrictedBranch(hIri))
                    {
                        RETAILMSG(
                            1,
                            (L"[%X] PolicyCheckByCanonicalName(14): ZuneBranchCheck: found, disabled\r\n",
                             ticks, name));
                        // Seems to be a request we need to work with.
                        // Let's disable it.
                        found = TRUE;
                    }
                    if (hIri)
                        IriClose(hIri);
                }
                if (hMiri)
                    IriMutableClose(hMiri);
            }
            if (found)
            {
                SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
                return FALSE;
            }
        }
    }

    BOOL prePrivCheckProcessed = FALSE;
    BOOL prePrivCheckResult =
        PrePrivilegeCheck(name, NULL, lpwszCanonicalName, NULL, NULL, NULL,
                          0x14, &prePrivCheckProcessed);
    RETAILMSG(
        DEBUGLOG,
        (L"[%X] PolicyCheckByCanonicalName(14): preProcessed = %d, preCheckResult = %d\r\n",
         ticks, prePrivCheckProcessed, prePrivCheckResult));
    if (prePrivCheckProcessed)
    {
        if (prePrivCheckResult)
            SetLastError(S_OK);
        else
            SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
        return prePrivCheckResult;
    }

    RETAILMSG(
        1,
        (L"[%X] PolicyCheckByCanonicalName(14): ZuneBranchCheck: not found\r\n",
         ticks, name));
    BOOL res = old(lpwszCanonicalName, hSubjectToken, amAccessRequested,
                   dwFlags, hAdditionalContext);
    HRESULT hTempError = GetLastError();
    RETAILMSG(
        DEBUGLOG,
        (L"[%X] PolicyCheckByCanonicalName(14): executed stock handler, res = %d, lasterror = %X\r\n",
         ticks, res, hTempError));
    if (res == TRUE)
    {
        SetLastError(S_OK);
        return res;
    }

    RETAILMSG(
        1,
        (L"[%X] PolicyCheckByCanonicalName(14): ZuneBranchCheck 0x14: %ls %ls\r\n",
         ticks, lpwszCanonicalName, name));

    if (hTempError == ERROR_ACCESS_DISABLED_BY_POLICY)
    {
        BOOL postPrivCheckProcessed = FALSE;
        BOOL postPrivCheckResult =
            PostPrivilegeCheck(name, NULL, lpwszCanonicalName, NULL, NULL, NULL,
                               0x14, &postPrivCheckProcessed);

        RETAILMSG(
            DEBUGLOG,
            (L"[%X] PolicyCheckByCanonicalName(14): postProcessed = %d, postCheckResult = %d\r\n",
             ticks, postPrivCheckProcessed, postPrivCheckResult));
        if (postPrivCheckProcessed)
        {
            res = postPrivCheckResult;
            hTempError = res ? S_OK : ERROR_ACCESS_DISABLED_BY_POLICY;
        }
    }

    SetLastError(hTempError);
    return res;
}

typedef BOOL (*POLICYCHECK)(__in ACCTID idOwner, __in_z LPCWSTR pszPolicyClass,
                            __in_z_opt LPCWSTR pszPolicySubClass,
                            __in HANDLE hSubjectToken,
                            __in ACCESS_MASK amAccessRequested,
                            __in_opt DWORD dwFlags,
                            __in_opt HANDLE hAdditionalContext);

/**
 * Authorize a subject for a resource named by policy class and sub-class,
 * applying the pre- and post-privilege decisions.
 *
 * @param idOwner             Owner account of the resource.
 * @param pszPolicyClass      Policy class name.
 * @param pszPolicySubClass   Optional policy sub-class name.
 * @param hSubjectToken       Token of the subject requiring access.
 * @param amAccessRequested   Requested access mask.
 * @param dwFlags             Optional request flags.
 * @param hAdditionalContext  Optional additional context handle.
 *
 * @return TRUE if access is allowed, FALSE if denied (GetLastError() is set).
 */
BOOL
PolicyCheck(__in ACCTID idOwner, __in_z LPCWSTR pszPolicyClass,
            __in_z_opt LPCWSTR pszPolicySubClass, __in HANDLE hSubjectToken,
            __in ACCESS_MASK amAccessRequested, __in_opt DWORD dwFlags,
            __in_opt HANDLE hAdditionalContext)
{
    POLICYCHECK old = (POLICYCHECK)funcTable.functions[0x18 / 4];
#ifdef DEBUG_ENABLED
    int ticks = GetTickCount();
#endif

    wchar_t name[200];
    GetAccountName(idOwner, name, 200);

    RETAILMSG(DEBUGLOG,
              (L"[%X] PolicyCheck(18)++ (%ls, %ls, %X, %ls)\r\n", ticks,
               pszPolicyClass, pszPolicySubClass, amAccessRequested, name));

    BOOL prePrivCheckProcessed = FALSE;
    BOOL prePrivCheckResult =
        PrePrivilegeCheck(name, NULL, NULL, NULL, pszPolicyClass,
                          pszPolicySubClass, 0x18, &prePrivCheckProcessed);
    RETAILMSG(
        DEBUGLOG,
        (L"[%X] PolicyCheck(18): preProcessed = %d, preCheckResult = %d\r\n",
         ticks, prePrivCheckProcessed, prePrivCheckResult));
    if (prePrivCheckProcessed)
    {
        if (prePrivCheckResult)
            SetLastError(S_OK);
        else
            SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
        return prePrivCheckResult;
    }

    BOOL res = old(idOwner, pszPolicyClass, pszPolicySubClass, hSubjectToken,
                   amAccessRequested, dwFlags, hAdditionalContext);

    HRESULT hTempError = GetLastError();
    RETAILMSG(
        DEBUGLOG,
        (L"[%X] PolicyCheck(18): executed stock handler, res = %d, lasterror = %X\r\n",
         ticks, res, hTempError));
    if (res == TRUE)
    {
        SetLastError(hTempError);
        return res;
    }
    if (hTempError == ERROR_ACCESS_DISABLED_BY_POLICY)
    {
        BOOL postPrivCheckProcessed = FALSE;
        BOOL postPrivCheckResult = PostPrivilegeCheck(
            name, NULL, NULL, NULL, pszPolicyClass, pszPolicySubClass, 0x18,
            &postPrivCheckProcessed);
        RETAILMSG(
            DEBUGLOG,
            (L"[%X] PolicyCheck(18): postProcessed = %d, postCheckResult = %d\r\n",
             ticks, postPrivCheckProcessed, postPrivCheckResult));
        if (postPrivCheckProcessed)
        {
            res = postPrivCheckResult;
            hTempError = res ? S_OK : ERROR_ACCESS_DISABLED_BY_POLICY;
        }
    }
L_exit:
    SetLastError(hTempError);
    return res;
}

typedef BOOL (*POLICYCHECKBYHANDLE)(HANDLE hPolicy, HANDLE hSubjectToken,
                                    DWORD dwRequestedAccess, DWORD dwFlags,
                                    HANDLE hAdditionalContext);

/**
 * Authorize a subject against an already opened policy handle.
 *
 * @param hPolicy             Open policy object handle.
 * @param hSubjectToken       Token of the subject requiring access.
 * @param dwRequestedAccess   Requested access mask.
 * @param dwFlags             Optional request flags.
 * @param hAdditionalContext  Optional additional context handle.
 *
 * @return TRUE if access is allowed, FALSE if denied.
 */
BOOL
PolicyCheckByHandle(HANDLE hPolicy, HANDLE hSubjectToken,
                    DWORD dwRequestedAccess, DWORD dwFlags,
                    HANDLE hAdditionalContext)
{
    POLICYCHECKBYHANDLE old =
        (POLICYCHECKBYHANDLE)funcTable.functions[0x28 / 4];

#ifdef DEBUG_ENABLED
    int ticks = GetTickCount();
#endif
    ACCTID account = 0;
    CeGetOwnerAccount(hSubjectToken, &account, sizeof(HANDLE));

    wchar_t name[200];
    GetAccountName(account, name, 200);

    HIRI hIri = NULL;
    ConvertPolicyToIri(hPolicy, &hIri, 0x28);

    RETAILMSG(DEBUGLOG, (L"[%X] PolicyCheckByHandle(28)++ (%ls, %X)\r\n", ticks,
                         name, hIri));
    if (hIri)
    {
        BOOL prePrivCheckProcessed = FALSE;
        BOOL prePrivCheckResult = PrePrivilegeCheck(
            name, hIri, NULL, NULL, NULL, NULL, 0x28, &prePrivCheckProcessed);
        RETAILMSG(
            DEBUGLOG,
            (L"[%X] PolicyCheckByHandle(28): preProcessed = %d, preCheckResult = %d\r\n",
             ticks, prePrivCheckProcessed, prePrivCheckResult));
        if (prePrivCheckProcessed)
        {
            if (prePrivCheckResult)
                SetLastError(S_OK);
            else
                SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
            IriClose(hIri);
            return prePrivCheckResult;
        }
    }
    BOOL res = old(hPolicy, hSubjectToken, dwRequestedAccess, dwFlags,
                   hAdditionalContext);
    HRESULT hTempError = GetLastError();
    RETAILMSG(
        DEBUGLOG,
        (L"[%X] PolicyCheckByHandle(28): executed stock handler, res = %d, lasterror = %X\r\n",
         ticks, res, hTempError));
    if (res == TRUE)
    {
        if (hIri)
            IriClose(hIri);
        SetLastError(hTempError);
        return TRUE;
    }

    if ((hSubjectToken != (HANDLE)2 || dwRequestedAccess != 6) &&
        hTempError == ERROR_ACCESS_DISABLED_BY_POLICY)
    {
        BOOL postPrivCheckProcessed = FALSE;
        BOOL postPrivCheckResult = PostPrivilegeCheck(
            name, hIri, NULL, NULL, NULL, NULL, 0x28, &postPrivCheckProcessed);
        RETAILMSG(
            DEBUGLOG,
            (L"[%X] PolicyCheckByHandle(28): postProcessed = %d, postCheckResult = %d\r\n",
             ticks, postPrivCheckProcessed, postPrivCheckResult));
        if (postPrivCheckProcessed)
        {
            res = postPrivCheckResult;
            hTempError = res ? S_OK : ERROR_ACCESS_DISABLED_BY_POLICY;
        }
    }
    else
    {
        RETAILMSG(
            DEBUGLOG,
            (L"[%X] PolicyCheckByHandle(28): stock handler failed, but no further check\r\n",
             ticks));
    }
    if (hIri)
        IriClose(hIri);

    SetLastError(hTempError);

    return res;
}

typedef BOOL (*POLICYGETACCESSGRANTED)(__in HANDLE hPolicy,
                                       __in HANDLE hSubjectToken,
                                       __out ACCESS_MASK *pamAccessGranted);

/**
 * Return the access mask granted for an open policy handle.
 *
 * @param hPolicy           Open policy object handle.
 * @param hSubjectToken     Token of the subject requiring access.
 * @param pamAccessGranted  Receives the granted access mask.
 *
 * @return TRUE on success, FALSE otherwise.
 */
BOOL
PolicyGetAccessGranted(__in HANDLE hPolicy, __in HANDLE hSubjectToken,
                       __out ACCESS_MASK *pamAccessGranted)
{
    POLICYGETACCESSGRANTED old =
        (POLICYGETACCESSGRANTED)funcTable.functions[0x2C / 4];

#ifdef DEBUG_ENABLED
    int ticks = GetTickCount();
#endif
    ACCTID account = 0;
    CeGetOwnerAccount(hSubjectToken, &account, sizeof(HANDLE));

    wchar_t name[200];
    GetAccountName(account, name, 200);

    HIRI hIri = NULL;
    ConvertPolicyToIri(hPolicy, &hIri, 0x2C);

    RETAILMSG(DEBUGLOG, (L"[%X] PolicyGetAccessGranted(2C)++ (%ls, %X)\r\n",
                         ticks, name, hIri));
    if (hIri)
    {
        BOOL prePrivCheckProcessed = FALSE;
        BOOL prePrivCheckResult = PrePrivilegeCheck(
            name, hIri, NULL, NULL, NULL, NULL, 0x2C, &prePrivCheckProcessed);
        RETAILMSG(
            DEBUGLOG,
            (L"[%X] PolicyGetAccessGranted(2C): preProcessed = %d, preCheckResult = %d\r\n",
             ticks, prePrivCheckProcessed, prePrivCheckResult));
        if (prePrivCheckProcessed)
        {
            if (prePrivCheckResult)
                SetLastError(S_OK);
            else
                SetLastError(ERROR_ACCESS_DISABLED_BY_POLICY);
            IriClose(hIri);
            return prePrivCheckResult;
        }
    }

    BOOL res = old(hPolicy, hSubjectToken, pamAccessGranted);

    HRESULT hTempError = GetLastError();

    // increase access level even if priviledges were granted.
    BOOL postPrivCheckProcessed = FALSE;
    BOOL postPrivCheckResult = PostPrivilegeCheck(
        name, hIri, NULL, NULL, NULL, NULL, 0x2C, &postPrivCheckProcessed);
    RETAILMSG(
        DEBUGLOG,
        (L"[%X] PolicyGetAccessGranted(2C): postProcessed = %d, postCheckResult = %d\r\n",
         ticks, postPrivCheckProcessed, postPrivCheckResult));

    // FALSE result usually means we should disable any access at all.
    // BUT we don't want that in this function since we can accidently
    // decrease access level to trusted apps.
    if (postPrivCheckProcessed && postPrivCheckResult)
    {
        res = postPrivCheckResult;

        hTempError = S_OK;
        if (res)
            *pamAccessGranted = 0xFFFFFFFF;
    }

    if (hIri)
        IriClose(hIri);

    SetLastError(hTempError);

    return res;
}

/**
 * Copy the stock policy function table and patch the authorization entries
 * with the overriding checks.
 *
 * @return Pointer to the patched function table.
 */
void *
GetFunctionTable()
{
    FUNCTIONTABLE *temp = (FUNCTIONTABLE *)extGetFunctionTable();
    memcpy(&funcTable, temp, sizeof(FUNCTIONTABLE));

    temp->functions[0x10 / 4] = (DWORD)PolicyCheckByCanonicalNameDirect;
    temp->functions[0x14 / 4] = (DWORD)PolicyCheckByCanonicalName;
    temp->functions[0x18 / 4] = (DWORD)PolicyCheck;
    temp->functions[0x28 / 4] = (DWORD)PolicyCheckByHandle;
    temp->functions[0x2C / 4] = (DWORD)PolicyGetAccessGranted;
    return (void *)temp;
}

/**
 * Ensure the stock policy engine has been loaded.
 */
void
EnsureLoaded()
{
    LoadPolicyEngine();
}

/**
 * Forward the call to the stock policy engine's PolicyCloseHandle.
 *
 * @param arg1  Opaque argument forwarded unchanged.
 *
 * @return Value returned by the stock policy engine.
 */
int
PolicyCloseHandle(void *arg1)
{
    EnsureLoaded();
    return extPolicyCloseHandle(arg1);
}

/**
 * Forward the call to the stock policy engine's PolicyEngineInit.
 *
 * @param arg1  Opaque argument forwarded unchanged.
 * @param arg2  Opaque argument forwarded unchanged.
 * @param arg3  Opaque argument forwarded unchanged.
 * @param arg4  Opaque argument forwarded unchanged.
 *
 * @return Value returned by the stock policy engine.
 */
int
PolicyEngineInit(void *arg1, void *arg2, void *arg3, void *arg4)
{
    EnsureLoaded();
    return extPolicyEngineInit(arg1, arg2, arg3, arg4);
}

/**
 * Forward the call to the stock policy engine's
 * PolicyRuleAbortTransaction.
 *
 * @param arg1  Opaque argument forwarded unchanged.
 *
 * @return Value returned by the stock policy engine.
 */
int
PolicyRuleAbortTransaction(void *arg1)
{
    EnsureLoaded();
    return extPolicyRuleAbortTransaction(arg1);
}

/**
 * Forward the call to the stock policy engine's PolicyRuleAddRawData.
 *
 * @param arg1  Opaque argument forwarded unchanged.
 * @param arg2  Opaque argument forwarded unchanged.
 * @param arg3  Opaque argument forwarded unchanged.
 * @param arg4  Opaque argument forwarded unchanged.
 *
 * @return Value returned by the stock policy engine.
 */
int
PolicyRuleAddRawData(void *arg1, void *arg2, void *arg3, void *arg4)
{
    EnsureLoaded();
    return extPolicyRuleAddRawData(arg1, arg2, arg3, arg4);
}

/**
 * Forward the call to the stock policy engine's
 * PolicyRuleBeginTransaction.
 *
 * @param arg1  Opaque argument forwarded unchanged.
 *
 * @return Value returned by the stock policy engine.
 */
int
PolicyRuleBeginTransaction(void *arg1)
{
    EnsureLoaded();
    return extPolicyRuleBeginTransaction(arg1);
}

/**
 * Forward the call to the stock policy engine's PolicyRuleBuildRawData.
 *
 * @param arg1  Opaque argument forwarded unchanged.
 * @param arg2  Opaque argument forwarded unchanged.
 * @param arg3  Opaque argument forwarded unchanged.
 * @param arg4  Opaque argument forwarded unchanged.
 * @param arg5  Opaque argument forwarded unchanged.
 * @param arg6  Opaque argument forwarded unchanged.
 *
 * @return Value returned by the stock policy engine.
 */
int
PolicyRuleBuildRawData(void *arg1, void *arg2, void *arg3, void *arg4,
                       void *arg5, void *arg6)
{
    EnsureLoaded();
    return extPolicyRuleBuildRawData(arg1, arg2, arg3, arg4, arg5, arg6);
}

/**
 * Forward the call to the stock policy engine's PolicyRuleCommit.
 *
 * @param arg1  Opaque argument forwarded unchanged.
 * @param arg2  Opaque argument forwarded unchanged.
 *
 * @return Value returned by the stock policy engine.
 */
int
PolicyRuleCommit(void *arg1, void *arg2)
{
    EnsureLoaded();
    return extPolicyRuleCommit(arg1, arg2);
}

/**
 * Forward the call to the stock policy engine's
 * PolicyRuleCommitTransaction.
 *
 * @param arg1  Opaque argument forwarded unchanged.
 *
 * @return Value returned by the stock policy engine.
 */
int
PolicyRuleCommitTransaction(void *arg1)
{
    EnsureLoaded();
    return extPolicyRuleCommitTransaction(arg1);
}

/**
 * Forward the call to the stock policy engine's PolicyRuleCreate.
 *
 * @param arg1  Opaque argument forwarded unchanged.
 * @param arg2  Opaque argument forwarded unchanged.
 * @param arg3  Opaque argument forwarded unchanged.
 * @param arg4  Opaque argument forwarded unchanged.
 *
 * @return Value returned by the stock policy engine.
 */
int
PolicyRuleCreate(void *arg1, void *arg2, void *arg3, void *arg4)
{
    EnsureLoaded();
    return extPolicyRuleCreate(arg1, arg2, arg3, arg4);
}

/**
 * Forward the call to the stock policy engine's PolicyRuleDelete.
 *
 * @param arg1  Opaque argument forwarded unchanged.
 * @param arg2  Opaque argument forwarded unchanged.
 *
 * @return Value returned by the stock policy engine.
 */
int
PolicyRuleDelete(void *arg1, void *arg2)
{
    EnsureLoaded();
    return extPolicyRuleDelete(arg1, arg2);
}
#define REVOKED_CERTS_POLICY_BRANCH L"/LOADERVERIFIER/GLOBAL/REVOKED_CERTS/SHA1/"

/**
 * Forward the call to the stock policy engine's PolicyRuleFindFirst.
 *
 * @param arg1  Opaque argument forwarded unchanged.
 * @param arg2  Opaque argument forwarded unchanged.
 * @param arg3  Opaque argument forwarded unchanged.
 *
 * @return Value returned by the stock policy engine.
 */
HANDLE
PolicyRuleFindFirst(void *arg1, void *arg2, void *arg3)
{
    EnsureLoaded();
    return (HANDLE)extPolicyRuleFindFirst(arg1, arg2, arg3);
}

/**
 * Forward the call to the stock policy engine's PolicyRuleFindNext.
 *
 * @param arg1  Opaque argument forwarded unchanged.
 * @param arg2  Opaque argument forwarded unchanged.
 *
 * @return Value returned by the stock policy engine.
 */
int
PolicyRuleFindNext(void *arg1, void *arg2)
{
    EnsureLoaded();
    return extPolicyRuleFindNext(arg1, arg2);
}

/**
 * Forward a policy-rule information query to the stock engine.
 *
 * @param hPolicyRule      Open policy rule handle.
 * @param pRuleInfo        Optional buffer receiving the rule info.
 * @param pszRuleNameIri   Optional buffer receiving the rule name IRI.
 * @param cchRuleNameIri   Size of @p pszRuleNameIri in characters.
 * @param pcchRuleNameIri  Optional out: required/written IRI length.
 *
 * @return TRUE on success, FALSE otherwise.
 */
BOOL
PolicyRuleGetInfo(__in HANDLE hPolicyRule, __out_opt LPVOID pRuleInfo,
                  __out_ecount_opt(cchRuleNameIri) LPWSTR pszRuleNameIri,
                  __in DWORD cchRuleNameIri, __out_opt LPDWORD pcchRuleNameIri)
{
    EnsureLoaded();
    return extPolicyRuleGetInfo(hPolicyRule, pRuleInfo, pszRuleNameIri,
                                (LPVOID)cchRuleNameIri, pcchRuleNameIri);
}

/**
 * Forward the call to the stock policy engine's PolicyRuleOpen.
 *
 * @param arg1  Opaque argument forwarded unchanged.
 * @param arg2  Opaque argument forwarded unchanged.
 *
 * @return Value returned by the stock policy engine.
 */
int
PolicyRuleOpen(void *arg1, void *arg2)
{
    EnsureLoaded();
    return extPolicyRuleOpen(arg1, arg2);
}

/**
 * Forward the call to the stock policy engine's PolicyRuleParseRawData.
 *
 * @param arg1  Opaque argument forwarded unchanged.
 * @param arg2  Opaque argument forwarded unchanged.
 * @param arg3  Opaque argument forwarded unchanged.
 * @param arg4  Opaque argument forwarded unchanged.
 * @param arg5  Opaque argument forwarded unchanged.
 * @param arg6  Opaque argument forwarded unchanged.
 *
 * @return Value returned by the stock policy engine.
 */
int
PolicyRuleParseRawData(void *arg1, void *arg2, void *arg3, void *arg4,
                       void *arg5, void *arg6)
{
    EnsureLoaded();
    return extPolicyRuleParseRawData(arg1, arg2, arg3, arg4, arg5, arg6);
}

/**
 * Forward the call to the stock policy engine's PolicyRuleReadRawData.
 *
 * @param arg1  Opaque argument forwarded unchanged.
 * @param arg2  Opaque argument forwarded unchanged.
 * @param arg3  Opaque argument forwarded unchanged.
 * @param arg4  Opaque argument forwarded unchanged.
 * @param arg5  Opaque argument forwarded unchanged.
 *
 * @return Value returned by the stock policy engine.
 */
int
PolicyRuleReadRawData(void *arg1, void *arg2, void *arg3, void *arg4,
                      void *arg5)
{
    EnsureLoaded();
    return extPolicyRuleReadRawData(arg1, arg2, arg3, arg4, arg5);
}

/**
 * DLL entry point.
 *
 * @param hModule             Handle to the DLL module.
 * @param ul_reason_for_call  Reason code for the call.
 * @param lpReserved          Reserved.
 *
 * @return TRUE.
 */
BOOL APIENTRY
DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        LoadPolicyEngine();
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        UnloadPolicyEngine();
    }
    return TRUE;
}
