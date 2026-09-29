/* FullUnlock v4.0 project.
   PolicyEngine implementation.
   
   (C) ultrashot 2012
*/
#include "stdafx.h"
#include "iri.h"

/**
 * Test whether the IRI names the Account Manager registry branch.
 *
 * @param hIri  Canonical resource IRI.
 *
 * @return TRUE if it matches.
 */
BOOL
IsAccmanRegistryBranch(HIRI hIri)
{
    if (hIri)
    {
        static HIRI hAccmanIri = NULL;
        if (hAccmanIri == NULL)
        {
            HMUTABLEIRI hmi = NULL;
            IriCreateFromString(L"/REGISTRY/HKLM/SOFTWARE/OEM/ACCMAN",
                                IRI_ENCODING_IRI, &hmi);
            IriMakeConstantEx(&hmi, &hAccmanIri);
        }
        DWORD commonSegment = 0;
        IriFindLastCommonSegment(hIri, hAccmanIri, IRI_COMPARE_NORMAL,
                                 IRI_COMPONENT_SCHEME | IRI_COMPONENT_QUERY |
                                     IRI_COMPONENT_FRAGMENT,
                                 &commonSegment);
        if (commonSegment >= 4)
            return TRUE;
    }
    return FALSE;
}

/**
 * Test whether the IRI names an ADB function branch.
 *
 * @param hIri  Canonical resource IRI.
 *
 * @return TRUE if it matches.
 */
BOOL
IsAdbFunctionBranch(HIRI hIri)
{
    if (hIri)
    {
        static HIRI hAdbIri = NULL;
        if (hAdbIri == NULL)
        {
            HMUTABLEIRI hmi = NULL;
            IriCreateFromString(L"/RESOURCES/GLOBAL/ADB/FUNCTIONS",
                                IRI_ENCODING_IRI, &hmi);
            IriMakeConstantEx(&hmi, &hAdbIri);
            if (hmi)
                IriMutableClose(hmi);
        }
        DWORD commonSegment = 0;
        IriFindLastCommonSegment(hIri, hAdbIri, IRI_COMPARE_NORMAL,
                                 IRI_COMPONENT_QUERY | IRI_COMPONENT_FRAGMENT,
                                 &commonSegment);
        if (commonSegment >= 3)
            return TRUE;
    }
    return FALSE;
}

/**
 * Test whether the IRI names the device wipe branch.
 *
 * @param hIri  Canonical resource IRI.
 *
 * @return TRUE if it matches.
 */
BOOL
IsWipeBranch(HIRI hIri)
{
    if (hIri)
    {
        static HIRI hWipeIri = NULL;
        if (hWipeIri == NULL)
        {
            HMUTABLEIRI hmi = NULL;
            IriCreateFromString(L"/RESOURCES/GLOBAL/SHELL/SHWipeDevice",
                                IRI_ENCODING_IRI, &hmi);
            IriMakeConstantEx(&hmi, &hWipeIri);
            if (hmi)
                IriMutableClose(hmi);
        }
        DWORD commonSegment = 0;
        IriFindLastCommonSegment(hIri, hWipeIri, IRI_COMPARE_NORMAL,
                                 IRI_COMPONENT_QUERY | IRI_COMPONENT_FRAGMENT,
                                 &commonSegment);
        if (commonSegment >= 3)
        {
            return TRUE;
        }
    }
    return FALSE;
}

/**
 * Test whether the IRI names the revoked-certificates branch.
 *
 * @param hIri  Canonical resource IRI.
 *
 * @return TRUE if it matches.
 */
BOOL
IsRevokeCertsBranch(HIRI hIri)
{
    if (hIri)
    {
        static HIRI hWipeIri = NULL;
        if (hWipeIri == NULL)
        {
            HMUTABLEIRI hmi = NULL;
            IriCreateFromString(L"/LOADERVERIFIER/GLOBAL/REVOKED_CERTS/SHA1",
                                IRI_ENCODING_IRI, &hmi);
            IriMakeConstantEx(&hmi, &hWipeIri);
            if (hmi)
                IriMutableClose(hmi);
        }
        DWORD commonSegment = 0;
        IriFindLastCommonSegment(hIri, hWipeIri, IRI_COMPARE_NORMAL, 0,
                                 &commonSegment);
        if (commonSegment >= 3)
        {
            return TRUE;
        }
    }
    return FALSE;
}

/**
 * Test whether the IRI names a Zune-restricted branch.
 *
 * @param hIri  Canonical resource IRI.
 *
 * @return TRUE if it matches.
 */
BOOL
IsZuneRestrictedBranch(HIRI hIri)
{
    if (hIri)
    {
        static HIRI hIri1;
        static HIRI hIri2;
        if (hIri1 == NULL)
        {
            HMUTABLEIRI hmi = NULL;
            IriCreateFromString(
                L"/LOADERVERIFIER/GLOBAL/AUTHORIZATION/UNSIGNEDNATIVEDLL_AUTHZ",
                IRI_ENCODING_IRI, &hmi);
            IriMakeConstantEx(&hmi, &hIri1);
            if (hmi)
                IriMutableClose(hmi);
        }
        if (hIri2 == NULL)
        {
            HMUTABLEIRI hmi = NULL;
            IriCreateFromString(
                L"/LOADERVERIFIER/GLOBAL/AUTHORIZATION/UNSIGNEDMANAGEDDLL_AUTHZ",
                IRI_ENCODING_IRI, &hmi);
            IriMakeConstantEx(&hmi, &hIri2);
            if (hmi)
                IriMutableClose(hmi);
        }
        DWORD commonSegment = 0;
        IriFindLastCommonSegment(hIri, hIri1, IRI_COMPARE_NORMAL, 0,
                                 &commonSegment);
        if (commonSegment >= 3)
        {
            return TRUE;
        }
        commonSegment = 0;
        IriFindLastCommonSegment(hIri, hIri2, IRI_COMPARE_NORMAL, 0,
                                 &commonSegment);
        if (commonSegment >= 3)
        {
            return TRUE;
        }
    }
    return FALSE;
}

/**
 * Test whether the IRI names an unsigned native DLL load.
 *
 * @param hIri  Canonical resource IRI.
 *
 * @return TRUE if it matches.
 */
BOOL
IsUnsignedNativeDllBranch(HIRI hIri)
{
    if (hIri)
    {
        static HIRI hUNativeIri = NULL;
        if (hUNativeIri == NULL)
        {
            HMUTABLEIRI hmi = NULL;
            IriCreateFromString(
                L"/LOADERVERIFIER/GLOBAL/AUTHORIZATION/UNSIGNEDNATIVEDLL_AUTHZ",
                IRI_ENCODING_IRI, &hmi);
            IriMakeConstantEx(&hmi, &hUNativeIri);
            if (hmi)
                IriMutableClose(hmi);
        }
        DWORD commonSegment = 0;
        IriFindLastCommonSegment(hIri, hUNativeIri, IRI_COMPARE_NORMAL, 0,
                                 &commonSegment);
        if (commonSegment >= 3)
        {
            return TRUE;
        }
    }
    return FALSE;
}

/**
 * Test whether the IRI names a loader-verifier branch.
 *
 * @param hIri  Canonical resource IRI.
 *
 * @return TRUE if it matches.
 */
BOOL
IsLoaderVerifierBranch(HIRI hIri)
{
    if (hIri)
    {
        static HIRI hLvIri = NULL;
        if (hLvIri == NULL)
        {
            HMUTABLEIRI hmi = NULL;
            IriCreateFromString(L"/LOADERVERIFIER/GLOBAL", IRI_ENCODING_IRI,
                                &hmi);
            IriMakeConstantEx(&hmi, &hLvIri);
            if (hmi)
                IriMutableClose(hmi);
        }
        DWORD commonSegment = 0;
        IriFindLastCommonSegment(hIri, hLvIri, IRI_COMPARE_NORMAL, 0,
                                 &commonSegment);
        if (commonSegment >= 1)
        {
            return TRUE;
        }
    }
    return FALSE;
}
