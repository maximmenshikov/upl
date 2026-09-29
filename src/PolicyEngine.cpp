/* FullUnlock v4.0 project.
   PolicyEngine implementation.
   
   (C) ultrashot 2012
*/
#include "stdafx.h"

typedef void *(*GETFUNCTIONTABLE)();
typedef int (*POLICYCLOSEHANDLE)(void *arg1);
typedef int (*POLICYENGINEINIT)(void *arg1, void *arg2, void *arg3, void *arg4);
typedef int (*POLICYRULEABORTTRANSACTION)(void *arg1);
typedef int (*POLICYRULEADDRAWDATA)(void *arg1, void *arg2, void *arg3,
                                    void *arg4);
typedef int (*POLICYRULEBEGINTRANSACTION)(void *arg1);
typedef int (*POLICYRULEBUILDRAWDATA)(void *arg1, void *arg2, void *arg3,
                                      void *arg4, void *arg5, void *arg6);
typedef int (*POLICYRULECOMMIT)(void *arg1, void *arg2);
typedef int (*POLICYRULECOMMITTRANSACTION)(void *arg1);
typedef int (*POLICYRULECREATE)(void *arg1, void *arg2, void *arg3, void *arg4);
typedef int (*POLICYRULEDELETE)(void *arg1, void *arg2);
typedef int (*POLICYRULEFINDFIRST)(void *arg1, void *arg2, void *arg3);
typedef int (*POLICYRULEFINDNEXT)(void *arg1, void *arg2);
typedef BOOL (*POLICYRULEGETINFO)(void *arg1, void *arg2, void *arg3,
                                  void *arg4, void *arg5);
typedef int (*POLICYRULEOPEN)(void *arg1, void *arg2);
typedef int (*POLICYRULEPARSERAWDATA)(void *arg1, void *arg2, void *arg3,
                                      void *arg4, void *arg5, void *arg6);
typedef int (*POLICYRULEREADRAWDATA)(void *arg1, void *arg2, void *arg3,
                                     void *arg4, void *arg5);

GETFUNCTIONTABLE extGetFunctionTable = NULL;
POLICYCLOSEHANDLE extPolicyCloseHandle = NULL;
POLICYENGINEINIT extPolicyEngineInit = NULL;
POLICYRULEABORTTRANSACTION extPolicyRuleAbortTransaction = NULL;
POLICYRULEADDRAWDATA extPolicyRuleAddRawData = NULL;
POLICYRULEBEGINTRANSACTION extPolicyRuleBeginTransaction = NULL;
POLICYRULEBUILDRAWDATA extPolicyRuleBuildRawData = NULL;
POLICYRULECOMMIT extPolicyRuleCommit = NULL;
POLICYRULECOMMITTRANSACTION extPolicyRuleCommitTransaction = NULL;
POLICYRULECREATE extPolicyRuleCreate = NULL;
POLICYRULEDELETE extPolicyRuleDelete = NULL;
POLICYRULEFINDFIRST extPolicyRuleFindFirst = NULL;
POLICYRULEFINDNEXT extPolicyRuleFindNext = NULL;
POLICYRULEGETINFO extPolicyRuleGetInfo = NULL;
POLICYRULEOPEN extPolicyRuleOpen = NULL;
POLICYRULEPARSERAWDATA extPolicyRuleParseRawData = NULL;
POLICYRULEREADRAWDATA extPolicyRuleReadRawData = NULL;

extern "C" HMODULE LoadKernelLibrary(wchar_t *libraryName);

#define POLICYENGINE hLibrary

HMODULE hLibrary = NULL;
int isReady = false;

/**
 * Load the stock policy engine and resolve its function table once.
 */
void
LoadPolicyEngine()
{
    if (isReady == false)
    {
        RETAILMSG(DEBUGLOG,
                  (L"[K][PolicyEngine] Loading stock policy engine\n"));
        hLibrary = LoadKernelLibrary(L"policyengine");

        extGetFunctionTable =
            (GETFUNCTIONTABLE)GetProcAddressA(POLICYENGINE, "GetFunctionTable");
        extPolicyCloseHandle = (POLICYCLOSEHANDLE)GetProcAddressA(
            POLICYENGINE, "PolicyCloseHandle");
        extPolicyEngineInit =
            (POLICYENGINEINIT)GetProcAddressA(POLICYENGINE, "PolicyEngineInit");
        extPolicyRuleAbortTransaction =
            (POLICYRULEABORTTRANSACTION)GetProcAddressA(
                POLICYENGINE, "PolicyRuleAbortTransaction");
        extPolicyRuleAddRawData = (POLICYRULEADDRAWDATA)GetProcAddressA(
            POLICYENGINE, "PolicyRuleAddRawData");

        extPolicyRuleBeginTransaction =
            (POLICYRULEBEGINTRANSACTION)GetProcAddressA(
                POLICYENGINE, "PolicyRuleBeginTransaction");
        extPolicyRuleBuildRawData = (POLICYRULEBUILDRAWDATA)GetProcAddressA(
            POLICYENGINE, "PolicyRuleBuildRawData");
        extPolicyRuleCommit =
            (POLICYRULECOMMIT)GetProcAddressA(POLICYENGINE, "PolicyRuleCommit");
        extPolicyRuleCommitTransaction =
            (POLICYRULECOMMITTRANSACTION)GetProcAddressA(
                POLICYENGINE, "PolicyRuleCommitTransaction");
        extPolicyRuleCreate =
            (POLICYRULECREATE)GetProcAddressA(POLICYENGINE, "PolicyRuleCreate");

        extPolicyRuleDelete =
            (POLICYRULEDELETE)GetProcAddressA(POLICYENGINE, "PolicyRuleDelete");
        extPolicyRuleFindFirst = (POLICYRULEFINDFIRST)GetProcAddressA(
            POLICYENGINE, "PolicyRuleFindFirst");
        extPolicyRuleFindNext = (POLICYRULEFINDNEXT)GetProcAddressA(
            POLICYENGINE, "PolicyRuleFindNext");
        extPolicyRuleGetInfo = (POLICYRULEGETINFO)GetProcAddressA(
            POLICYENGINE, "PolicyRuleGetInfo");
        extPolicyRuleOpen =
            (POLICYRULEOPEN)GetProcAddressA(POLICYENGINE, "PolicyRuleOpen");

        extPolicyRuleParseRawData = (POLICYRULEPARSERAWDATA)GetProcAddressA(
            POLICYENGINE, "PolicyRuleParseRawData");
        extPolicyRuleReadRawData = (POLICYRULEREADRAWDATA)GetProcAddressA(
            POLICYENGINE, "PolicyRuleReadRawData");

        isReady = true;
    }
}

/**
 * Release the stock policy engine.
 */
void
UnloadPolicyEngine()
{
    if (hLibrary)
    {
        FreeLibrary(hLibrary);
        hLibrary = NULL;
        isReady = false;
    }
}