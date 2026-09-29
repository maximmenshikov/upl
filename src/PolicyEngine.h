#ifndef POLICYENGINE_H
#define POLICYENGINE_H

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
typedef int (*POLICYRULEGETINFO)(void *arg1, void *arg2, void *arg3, void *arg4,
                                 void *arg5);
typedef int (*POLICYRULEOPEN)(void *arg1, void *arg2);
typedef int (*POLICYRULEPARSERAWDATA)(void *arg1, void *arg2, void *arg3,
                                      void *arg4, void *arg5, void *arg6);
typedef int (*POLICYRULEREADRAWDATA)(void *arg1, void *arg2, void *arg3,
                                     void *arg4, void *arg5);

extern GETFUNCTIONTABLE extGetFunctionTable;
extern POLICYCLOSEHANDLE extPolicyCloseHandle;
extern POLICYENGINEINIT extPolicyEngineInit;
extern POLICYRULEABORTTRANSACTION extPolicyRuleAbortTransaction;
extern POLICYRULEADDRAWDATA extPolicyRuleAddRawData;
extern POLICYRULEBEGINTRANSACTION extPolicyRuleBeginTransaction;
extern POLICYRULEBUILDRAWDATA extPolicyRuleBuildRawData;
extern POLICYRULECOMMIT extPolicyRuleCommit;
extern POLICYRULECOMMITTRANSACTION extPolicyRuleCommitTransaction;
extern POLICYRULECREATE extPolicyRuleCreate;
extern POLICYRULEDELETE extPolicyRuleDelete;
extern POLICYRULEFINDFIRST extPolicyRuleFindFirst;
extern POLICYRULEFINDNEXT extPolicyRuleFindNext;
extern POLICYRULEGETINFO extPolicyRuleGetInfo;
extern POLICYRULEOPEN extPolicyRuleOpen;
extern POLICYRULEPARSERAWDATA extPolicyRuleParseRawData;
extern POLICYRULEREADRAWDATA extPolicyRuleReadRawData;

void LoadPolicyEngine();
void UnloadPolicyEngine();

#endif
