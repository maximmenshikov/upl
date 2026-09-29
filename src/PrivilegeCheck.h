#ifndef PRIVILEGECHECK_H
#define PRIVILEGECHECK_H

#include "iri.h"
BOOL IsAccessGranted(HANDLE hToken, LPCWSTR policyClass, LPCWSTR policySubClass,
                     HIRI hIri, int callerId);
BOOL IsAccessGranted(HANDLE hToken, LPCWSTR policyClass, LPCWSTR policySubClass,
                     LPWSTR szIri, int callerId);

#endif
