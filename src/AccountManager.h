/* FullUnlock v4.0 project.
   PolicyEngine implementation.
   
   (C) ultrashot 2012
*/
#ifndef ACCOUNTMANAGER_H
#define ACCOUNTMANAGER_H

#include "adb7.h"

#define ACCID_ACCOUNTMANAGER                                                   \
    L"S-1-5-112-0-0X80-0X7B37393445423641452D423246392D344246422D393237372D3431363145344439453346357D"

/* returns TRUE if account is privileged */
BOOL GetPrivileged(LPWSTR account);

/* Add account to privileged group */
VOID AddToPrivilegedGroup(LPWSTR account);

/* Removes account from privileged group */
VOID RemoveFromPrivilegedGroup(LPWSTR account);

/* returns TRUE if full trust mode is enabled */
BOOL IsFullTrustModeEnabled();

/* Changes full trust mode settings */
VOID SetFullTrustEnabled(BOOL mode);

/* Adds account to third party app group */
VOID AddToThirdPartyGroup(LPWSTR account);

/* Removes account from third party app group */
VOID RemoveFromThirdPartyGroup(LPWSTR account);

/* Checks if account is in third-party app group */
BOOL IsInThirdPartyGroup(LPWSTR account);

#endif
