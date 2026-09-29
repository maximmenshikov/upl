/* FullUnlock v4.0 project.
   PolicyEngine implementation.
   
   (C) ultrashot 2012
*/
#include "stdafx.h"
#include "debug.h"
#include "BuildIri.h"

// special symbols
static wchar_t plus[8] = {0x10, 0xE0, 0x2B, 0x00, 0x11, 0xE0, 0x00, 0x00};
static wchar_t star[8] = {0x10, 0xE0, 0x2A, 0x00, 0x11, 0xE0, 0x00, 0x00};

/**
 * Reconstruct a mutable IRI from a raw policy resource structure.
 *
 * @param IRIBase   Pointer to the resource's segment table.
 * @param hOutMiri  Receives the built mutable IRI handle.
 */
void
BuildIri(void *IRIBase, HMUTABLEIRI *hOutMiri)
{
#ifdef DEBUG_ENABLED
    int ticks = GetTickCount();
#endif
    if (hOutMiri == NULL)
    {
        RETAILMSG(DEBUGLOG, (L"[%X] BuildIri - hOutMiri = NULL\r\n", ticks));
        return;
    }
    DWORD *dwBase = (DWORD *)IRIBase;
    DWORD dwBaseOff4 = dwBase[1];
    DWORD dwSegmentCount = ((DWORD *)dwBase[1])[1];
    RETAILMSG(DEBUGLOG, (L"[%X] BuildIri - segment count = %d\r\n", ticks,
                         dwSegmentCount));
    if (dwSegmentCount == 0)
    {
        return;
    }
    wchar_t str[0x12C];
    memset(str, 0, sizeof(str));
    str[0] = 0x2F;
    str[1] = 0;
    wcscat_s(str, 0x12C, (wchar_t *)(dwBaseOff4 + ((dwSegmentCount + 1) << 4)));

    RETAILMSG(DEBUGLOG, (L"[%X] BuildIri - str (%ls)\r\n", ticks, str));
    HMUTABLEIRI hmIri = NULL;
    if (IriCreateFromString(str, IRI_ENCODING_IRI, &hmIri) != S_OK)
    {
        RETAILMSG(DEBUGLOG, (L"[%X] BuildIri - Create failed\r\n", ticks));
        return;
    }
    if (dwSegmentCount == 1)
    {
        *hOutMiri = hmIri;
        return;
    }

    for (int i = 1; i < dwSegmentCount; ++i)
    {
        wchar_t *temp = NULL;
        wchar_t *segment = NULL;
        DWORD segmentEncoding = 0;
        if (i)
        {

            DWORD r2 = dwBaseOff4 + ((dwSegmentCount + 1) << 4);
            if (i < dwSegmentCount)
            {
                DWORD r3 = ((DWORD *)(dwBaseOff4 + (i << 4)))[2];
                temp = (wchar_t *)(r2 + (r3 << 1));
            }
            else
            {

                RETAILMSG(
                    DEBUGLOG,
                    (L"[%X] BuildIri - i >= dwSegmentCount!!!\r\n", ticks));
                return;
            }
        }
        else
        {
            temp = (wchar_t *)(dwBaseOff4 + ((dwSegmentCount + 1) << 4));
        }
        segmentEncoding = IRI_ENCODING_CUSTOMBLOCK;
        if (wcscmp(temp, star) == 0)
            temp = L"(*)";
        else if (wcscmp(temp, plus) == 0)
            temp = L"(+)";
        else
            segmentEncoding = IRI_ENCODING_NONE;
        if (FAILED(IriAppendSegment(hmIri, temp, segmentEncoding)))
        {
            RETAILMSG(DEBUGLOG,
                      (L"[%X] BuildIri - IriAppendSegment failed\r\n", ticks));
            return;
        }
    }
    *hOutMiri = hmIri;
}

/**
 * Build a constant IRI describing a policy object.
 *
 * @param hPolicy  Policy object handle.
 * @param hOutIri  Receives the constant IRI handle.
 * @param funcNum  Policy function index (used for logging).
 */
void
ConvertPolicyToIri(HANDLE hPolicy, HIRI *hOutIri, DWORD funcNum)
{
    if (hOutIri)
        *hOutIri = NULL;
    if (hPolicy)
    {
#ifdef DEBUG_ENABLED
        int ticks = GetTickCount();
#endif
        RETAILMSG(DEBUGLOG,
                  (L"[%X] ConvertPolicyToIri(hPolicy = %X, funcNum = %X)\r\n",
                   ticks, hPolicy, funcNum));
        HMUTABLEIRI hMiri = NULL;
        BuildIri((LPVOID)((DWORD)hPolicy + 0x18 + 0x8 + 0x4), &hMiri);
        if (hMiri)
        {
            RETAILMSG(DEBUGLOG, (L"[%X] hMiri = %X\r\n", ticks, hMiri));
            HIRI hIri = NULL;
            if (IriMakeConstantEx(&hMiri, &hIri) == S_OK)
            {
                *hOutIri = hIri;
                wchar_t str[500] = {0};
                HRESULT hr = IriGetAsString(hIri, 0, IRI_ALL_REMAINING_SEGMENTS,
                                            0, str, 500, NULL);
                RETAILMSG(DEBUGLOG, (L"[%X] Iri = %ls\r\n", ticks, str));
            }
            if (hMiri)
                IriMutableClose(hMiri);
        }
    }
}
