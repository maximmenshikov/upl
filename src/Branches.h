#ifndef BRANCHES_H
#define BRANCHES_H

#include "iri.h"

BOOL IsAccmanRegistryBranch(HIRI hIri);
BOOL IsAdbFunctionBranch(HIRI hIri);
BOOL IsWipeBranch(HIRI hIri);
BOOL IsRevokeCertsBranch(HIRI hIri);
BOOL IsZuneRestrictedBranch(HIRI hIri);
BOOL IsUnsignedNativeDllBranch(HIRI hIri);
BOOL IsLoaderVerifierBranch(HIRI hIri);

#endif
