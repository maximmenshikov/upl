/* FullUnlock v4.0 project.
   PolicyEngine implementation.
   
   (C) ultrashot 2012
*/
#include "stdafx.h"
#include "adb7.h"

#define FULL_TRUST_GROUP L"S-1-5-112-0-0XFD"

#define THIRD_PARTY_GROUP 0x55555554
#define TRUSTED_GROUP (THIRD_PARTY_GROUP | 0x1)

/**
 * Read the ADB privilege property of an account.
 *
 * @param account  SID string of the account.
 *
 * @return The ADBPROP_PRIVILEGES value, or 0 if it cannot be read.
 */
DWORD
GetAccountSpecialProperty(LPWSTR account)
{
    DWORD dwAccountPropLength = sizeof(DWORD);
    DWORD dwProp = 0;
    ADBGetAccountProperty(account, ADBPROP_PRIVILEGES, &dwAccountPropLength,
                          &dwProp);
    return dwProp;
}

/**
 * Test whether a privilege value marks a third-party account.
 *
 * @param prop  Privilege property value.
 *
 * @return TRUE for the third-party or trusted group value.
 */
inline BOOL
_IsThirdParty(DWORD prop)
{
    if (prop == THIRD_PARTY_GROUP || prop == TRUSTED_GROUP)
        return TRUE;
    return FALSE;
}

/**
 * Test whether a privilege value marks a trusted account.
 *
 * @param prop  Privilege property value.
 *
 * @return TRUE for the trusted group value.
 */
inline BOOL
_IsTrusted(DWORD prop)
{
    if (prop == TRUSTED_GROUP)
        return TRUE;
    return FALSE;
}

/**
 * Decide whether an account may be granted elevated access.
 *
 * @param account  SID string of the account.
 *
 * @return TRUE unless the account is an untrusted third-party account.
 */
BOOL
GetPrivileged(LPWSTR account)
{
    DWORD prop = GetAccountSpecialProperty(account);

    if (_IsThirdParty(prop) == FALSE)
        return TRUE;

    return _IsTrusted(prop);
}

/**
 * Check whether the global full-trust group exists.
 *
 * @return TRUE if the full-trust group account is present.
 */
BOOL
IsFullTrustModeEnabled()
{
    DWORD cbSize = sizeof(DWORD);
    DWORD dwValue = 0xDEADC0DE;
    if (ADBGetAccountProperty(FULL_TRUST_GROUP, ADBPROP_ACCTID, &cbSize,
                              &dwValue) == S_OK)
    {
        return TRUE;
    }
    return FALSE;
}

/**
 * Create or delete the global full-trust group.
 *
 * @param mode  TRUE to create the group, FALSE to delete it.
 */
VOID
SetFullTrustEnabled(BOOL mode)
{
    if (mode)
    {
        ADBCreateAccount(FULL_TRUST_GROUP, ACCT_FLAG_GROUP, 0);
    }
    else
    {
        ADBDeleteAccount(FULL_TRUST_GROUP);
    }
}

/**
 * Mark an account as trusted (privileged).
 *
 * @param account  SID string of the account.
 */
VOID
AddToPrivilegedGroup(LPWSTR account)
{
    if (account)
    {
        DWORD data = TRUSTED_GROUP;
        ADB_BLOB adbBlob;
        adbBlob.propertyId = ADBPROP_PRIVILEGES;
        adbBlob.pData = &data;
        adbBlob.cbData = sizeof(DWORD);
        ADBSetAccountProperties(account, 1, &adbBlob);
    }
}

/**
 * Demote a trusted account back to third-party.
 *
 * @param account  SID string of the account.
 */
VOID
RemoveFromPrivilegedGroup(LPWSTR account)
{
    if (account)
    {
        DWORD prop = GetAccountSpecialProperty(account);
        if (_IsTrusted(prop) == TRUE)
        {
            DWORD data = THIRD_PARTY_GROUP;
            ADB_BLOB adbBlob;
            adbBlob.propertyId = ADBPROP_PRIVILEGES;
            adbBlob.pData = &data;
            adbBlob.cbData = sizeof(DWORD);
            ADBSetAccountProperties(account, 1, &adbBlob);
        }
    }
}

/**
 * Mark an unclassified account as third-party.
 *
 * @param account  SID string of the account.
 */
VOID
AddToThirdPartyGroup(LPWSTR account)
{
    if (account)
    {
        DWORD prop = GetAccountSpecialProperty(account);
        if (_IsThirdParty(prop) == FALSE)
        {
            DWORD data = THIRD_PARTY_GROUP;
            ADB_BLOB adbBlob;
            adbBlob.propertyId = ADBPROP_PRIVILEGES;
            adbBlob.pData = &data;
            adbBlob.cbData = sizeof(DWORD);
            ADBSetAccountProperties(account, 1, &adbBlob);
        }
    }
}

/**
 * Clear the third-party marking from an account.
 *
 * @param account  SID string of the account.
 */
VOID
RemoveFromThirdPartyGroup(LPWSTR account)
{
    if (account)
    {
        DWORD prop = GetAccountSpecialProperty(account);
        if (_IsThirdParty(prop) == TRUE)
        {
            DWORD data = 0;
            ADB_BLOB adbBlob;
            adbBlob.propertyId = ADBPROP_PRIVILEGES;
            adbBlob.pData = &data;
            adbBlob.cbData = sizeof(DWORD);
            ADBSetAccountProperties(account, 1, &adbBlob);
        }
    }
}

/**
 * Check whether an account is in the third-party group.
 *
 * @param account  SID string of the account.
 *
 * @return TRUE if third-party; FALSE for the AccountManager identity.
 */
BOOL
IsInThirdPartyGroup(LPWSTR account)
{
    if (wcscmp(
            account,
            L"S-1-5-112-0-0X80-0X7B37393445423641452D423246392D344246422D393237372D3431363145344439453346357D") ==
        0)
        return FALSE;

    DWORD prop = GetAccountSpecialProperty(account);
    return _IsThirdParty(prop);
}
