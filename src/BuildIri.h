#ifndef BUILDIRI_H
#define BUILDIRI_H

#include "iri.h"

void BuildIri(void *IRIBase, HMUTABLEIRI *hOutMiri);
void ConvertPolicyToIri(HANDLE hPolicy, HIRI *hOutIri, DWORD funcNum);

#endif
