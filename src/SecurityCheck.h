#ifndef SECURITYCHECK_H
#define SECURITYCHECK_H

#include "iri.h"

// all-in-one function checking security
BOOL PrePrivilegeCheck(wchar_t *accountName, HIRI hIri, wchar_t *szIri,
                       void *hPolicy, LPCWSTR policyClass,
                       LPCWSTR policySubClass, int callerId, BOOL *processed);

// all-in-one function checking security
BOOL PostPrivilegeCheck(wchar_t *accountName, HIRI hIri, wchar_t *szIri,
                        void *hPolicy, LPCWSTR policyClass,
                        LPCWSTR policySubClass, int callerId, BOOL *processed);

#endif
