/* FullUnlock v4.0 project.
   PolicyEngine implementation.
   
   (C) ultrashot 2012
*/
#include "stdafx.h"
#include "adb7.h"

extern "C"
{
    HRESULT CeGetProcessAccount(HANDLE hProcess, PACCTID accountId,
                                DWORD cbSize);
}

/**
 * Return the owner account of a process.
 *
 * @param hProcess  Process handle.
 *
 * @return The process account id.
 */
ACCTID
GetAccount(HANDLE hProcess)
{
    ACCTID account;
    CeGetProcessAccount(hProcess, &account, sizeof(ACCTID));
    return account;
}

/**
 * Resolve an account id to its SID name.
 *
 * @param accountID            Account id to resolve.
 * @param lpwszAccountName     Buffer receiving the name.
 * @param dwAccountNameLength  Buffer size in characters.
 *
 * @return TRUE on success, FALSE otherwise.
 */
BOOL
GetAccountName(ACCTID accountID, LPWSTR lpwszAccountName,
               DWORD dwAccountNameLength)
{
    DWORD strSize = dwAccountNameLength;
    ACCTID account = accountID;
    if (ADBNameFromAccountID(&account, lpwszAccountName, &strSize) ==
        ERROR_SUCCESS)
        return TRUE;
    return FALSE;
}

/**
 * Resolve an account id to its normalized SID name.
 *
 * @param accountID            Account id to resolve.
 * @param lpwszAccountName     Buffer receiving the normalized name.
 * @param dwAccountNameLength  Buffer size in characters.
 *
 * @return FALSE (the normalized name is written to @p lpwszAccountName when resolution succeeds).
 */
BOOL
GetNormalizedAccountName(ACCTID accountID, LPWSTR lpwszAccountName,
                         DWORD dwAccountNameLength)
{
    ACCTID account = accountID;

    wchar_t name[500];
    DWORD nameLength = 500;
    if (GetAccountName(account, name, nameLength) == TRUE)
    {
        DWORD strSize = dwAccountNameLength;
        ADBNormalizeAccountName(name, lpwszAccountName, &strSize);
    }
    return FALSE;
}

/**
 * Resolve a SID name to its account id.
 *
 * @param lpwszAccountName  SID name to resolve.
 *
 * @return The account id, or 0 if not found.
 */
ACCTID
Name2AccountID(LPWSTR lpwszAccountName)
{
    ACCTID account = 0;
    ADBAccountIDFromName(lpwszAccountName, &account);
    return account;
}
