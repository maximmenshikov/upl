//
// Copyright (c) Microsoft Corporation.  All rights reserved.
//
//
// Use of this sample source code is subject to the terms of the Microsoft
// license agreement under which you licensed this sample source code. If
// you did not accept the terms of the license agreement, you are not
// authorized to use this sample source code. For the terms of the license,
// please see the license agreement between you and Microsoft or, if applicable,
// see the LICENSE.RTF on your install media or the root of your tools installation.
// THE SAMPLE SOURCE CODE IS PROVIDED "AS IS", WITH NO WARRANTIES OR INDEMNITIES.
//
//
// Copyright (c) Microsoft Corporation.  All rights reserved.
//

#ifndef _IRI_H_
#define _IRI_H_

#if (_MSC_VER >= 1000)
#pragma once
#endif

#include <windows.h>

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

// The IRI helper library supports a sub-set of RFC 3987 (International
// Resource Identifiers). The following types of IRIs are supported:
// 1. Absolute IRIs (e.g. foo:/seg1/seg2)
// 2. Relative IRIs (e.g. foo:seg1/seg2)
// 3. Schemeless IRIs (e.g. /seg1/seg2 or seg1/seg2).
//
// Both types of IRI may optionally contain a query portion
// (e.g. foo:/seg1/seg2?querystring) and/or a fragment
// (i.e. foo:/seg1/seg2#fragment).
//

// The library does not support authority-based IRIs (i.e. foo://host/seg1)
// [note the double / after the scheme name].

// Handle representing an IRI. Objects represented by this handle are 
// immutable - they cannot be edited in-place. 
// Hungarian Tag: hiri
DECLARE_HANDLE(HIRI);

// Handle representing a mutable IRI - object's represented by this handle
// can be modified in-place. 
// Hugarian Tag: hmiri
DECLARE_HANDLE(HMUTABLEIRI);

// The library reserves the following 2 characters to delimit a custom
// block. The string within the block may be interpreted specially (for
// example, the policy engine IRIs use this to delimit wild-cards in
// rules). To include either of these characters as a literal (i.e. without
// its special meaning, they must be % encoded). 
// For example, given the following IRIs (which use policy engine wildcards):
//   1. policy:/registry/hkcr/*
//   2. policy:/registry/hkcr/(*) 
//   3. policy:/registry/hkcr/%28*%29
//
// Calling IRIGetSegment(2) on each of the above IRIs would return the following 
// strings (using C notation to represent Unicode characters):
//   1. "*"
//   2. "\xE010*\xE011"
//   3. "(*)"
// 
// If the above IRIs were being interpreted by the policy engine, then they'd 
// have the following semantics:
//
// (1) is an IRI containing a literal '*' (i.e. it matches the registry key "HKCR\*"). 
// (2) is an IRI containing a wild-card * (i.e. it matches all the entire sub-tree under
//     HKCR). 
// (3) is an IRI containing the literal string '(*)' (i.e. it matches the registry key 
//     "HKCR\(*)"). 
#define IRI_CUSTOMBLOCK_START_ENCODING  L'('
#define IRI_CUSTOMBLOCK_END_ENCODING    L')'

// The following two code-points are part of the Private Use range by the Unicode 
// standard. The IRI library uses these to allow clients to identify the start
// and end-range of a custom block when they retrieve a segment. In the string
// representation of any entire IRI (rather than just a single segment), they
// will be replaced with the IRI_CUSTOMBLOCK_*_ENCODING characters. 
#define IRI_CUSTOMBLOCK_START   L'\xE010'
#define IRI_CUSTOMBLOCK_END     L'\xE011'

#define IRI_ALL_REMAINING_SEGMENTS  (0xFFFFFFFF)

/// <summary>
///   This enumeration is used to indicate various attributes about an IRI. 
///   It can be a combination of the following values. 
/// </summary>
/// <list type="table">
///   <listheader>
///     <term>Value</term>
///     <description>Description</description>
///   </listheader>
///   <item>
///     <term>IRI_METADATA_NONE</term>
///     <description>
///       This flag indicates that there are no special attributes associated 
///       with the IRI ?all other flags override this value. 
///     </description>
///   </item>
///   <item>
///     <term>IRI_METADATA_ABSOLUTE</term>
///     <description>
///       If this bit is set, then the IRI is an absolute IRI, i.e. it starts 
///       with a leading /. For example /segment/segment2 would have this bit 
///       set, but segment/segment2 would not. 
///     </description>
///   </item>
///   <item>
///     <term>IRI_METADATA_CUSTOMBLOCK</term>
///     <description>
///       If this bit is set, then the IRI contains one or more segments that 
///       contain custom blocks. 
///     </description>
///   </item>
/// </list>

enum IRI_METADATA
{
    IRI_METADATA_NONE           = 0,
    IRI_METADATA_ABSOLUTE       = 0x1,
    IRI_METADATA_CUSTOMBLOCK    = 0x2,
};


/// <summary>
///   This enumeration is used to indicate which components of an IRI are 
///   present. It can be a combination of the following values.
/// </summary>
/// <list type="table">
///   <listheader>
///     <term>Value</term>
///     <description>Description</description>
///   </listheader>
///   <item>
///     <term>IRI_COMPONENT_NONE</term>
///     <description>
///       This indicates that the IRI contains none of the other possible 
///       components. If any other flag is combined with this flag, those 
///       flags take precedence. 
///     </description>
///   </item>
///   <item>
///     <term>IRI_COMPONENT_SCHEME</term>
///     <description>
///       If this bit is set, then the IRI object includes a scheme.
///     </description>
///   </item>
///   <item>
///     <term>IRI_COMPONENT_QUERY</term>
///     <description>
///       If this bit is set, then the IRI object includes a query-string.
///     </description>
///   </item>
///   <item>
///     <term>IRI_COMPONENT_FRAGMENT</term>
///     <description>
///       If this bit is set, then the IRI object includes a fragment string. 
///     </description>
///   </item>
/// </list>

enum IRI_COMPONENT
{
    IRI_COMPONENT_NONE      = 0,
    IRI_COMPONENT_SCHEME    = 0x1,
    IRI_COMPONENT_QUERY     = 0x2,
    IRI_COMPONENT_FRAGMENT  = 0x4,
};


/// <summary>
///   Specifies the encoding used in the string representation or an IRI or 
///   IRI component. It be a combination of the following values.
/// </summary>
/// <list type="table">
///   <listheader>
///     <term>Value</term>
///     <description>Description</description>
///   </listheader>
///   <item>
///     <term>IRI_ENCODING_NONE</term>
///     <description>
///       The string is not IRI encoded. If any other flag is combined with 
///       this flag, those flags take precedence. 
///     </description>
///   </item>
///   <item>
///     <term>IRI_ENCODING_IRI</term>
///     <description>
///       The string is already IRI encoded. This flag is mutually exclusive 
///       with the IRI_ENCODING_URL flag: only one them may be specified at 
///       any time. 
///     </description>
///   </item>
///   <item>
///     <term>IRI_ENCODING_URL</term>
///     <description>
///       The string is URI encoded (i.e. UTF-8 encoded and then % escaped).
///       This flag is mutually exclusive with the IRI_ENCODING_IRI flag: only 
///       one them may be specified at any time. 
///     </description>
///   </item>
///   <item>
///     <term>IRI_ENCODING_CUSTOMBLOCK</term>
///     <description>
///       The string is custom-block encoded. 
///     </description>
///   </item>
/// </list>

enum IRI_ENCODING
{
    IRI_ENCODING_NONE           = 0,
    IRI_ENCODING_IRI            = 0x1,  
    IRI_ENCODING_URL            = 0x2,
    IRI_ENCODING_CUSTOMBLOCK    = 0x4,
};


/// <summary>
///   Controls how IRIs are compared. It can be a combination of the following values.
/// </summary>
/// <list type="table">
///   <listheader>
///     <term>Value</term>
///     <description>Description</description>
///   </listheader>
///   <item>
///     <term>IRI_COMPARE_NORMAL</term>
///     <description>
///       All portions of the IRI will be examined using a case insensitive 
///       compare. If any other flags are combined with this flag, those flags 
///       take precedence. 
///     </description>
///   </item>
///   <item>
///     <term>IRI_COMPARE_CASESENSITIVE</term>
///     <description>
///       Perform a case-sensitive comparison of the IRI. 
///     </description>
///   </item>
/// </list>
enum IRI_COMPARE
{
    IRI_COMPARE_NORMAL          = 0,
    IRI_COMPARE_CASESENSITIVE   = 0x1,
};

//==============================================================================
// Error Codes

#define FACILITY_IRI            (0x300)

// The scheme for the IRI isn't valid.
#define IRI_E_BADSCHEME             MAKE_HRESULT(SEVERITY_ERROR, FACILITY_IRI, 0x0001)

// The escape sequence (%xx) contains invalid characters.
#define IRI_E_BADESCAPE             MAKE_HRESULT(SEVERITY_ERROR, FACILITY_IRI, 0x0002)

// One of the segments in the IRI contains an illegal character (for example,
// Unicode Private Use characters cannot be part of a segment). 
#define IRI_E_BADSEGMENT            MAKE_HRESULT(SEVERITY_ERROR, FACILITY_IRI, 0x0003)

// The query string for the IRI is malformed.
#define IRI_E_BADQUERY              MAKE_HRESULT(SEVERITY_ERROR, FACILITY_IRI, 0x0004)

// The fragment for the IRI is malformed.
#define IRI_E_BADFRAGMENT           MAKE_HRESULT(SEVERITY_ERROR, FACILITY_IRI, 0x0005)

// The IRI contains an illegal custom block
#define IRI_E_BADCUSTOMBLOCK        MAKE_HRESULT(SEVERITY_ERROR, FACILITY_IRI, 0x0006)

// The two IRIs do not have any segments in common. 
#define IRI_E_NOCOMMONSEGMENTS      MAKE_HRESULT(SEVERITY_ERROR, FACILITY_IRI, 0x0007)


#if !defined(E_INSUFFICIENT_BUFFER)
#define E_INSUFFICIENT_BUFFER   HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)
#endif // E_INSUFFICIENT_BUFFER


//==============================================================================
// Creating IRIs

/// <summary>
///   Creates an IRI object from a string. 
/// </summary>
/// <param name="pszIri">
///   Specifies the string to create the IRI object from.
/// </param>
/// <param name="grfEncoding">
///   Specifies how pszIRI is encoded. This parameter can be either
///   IRI_ENCODING_URL or IRI_ENCODING_IRI: other values from the IRI_ENCODING
///   enumeration are not valid for this function. 
/// </param>
/// <param name="phmiri">
///   A pointer to a variable that receives a handle to the created IRI object. 
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK. 
///   If pszIRI or phmiri were NULL, the return value is E_POINTER.
///   If grfEncoding contains invalid values, the return value is E_INVALIDARG.
///   If the function fails due to insufficient memory, the return value is 
///   E_OUTOFMEMORY. 
///   If the string can not be parsed as an IRI, the return value will be one 
///   of IRI_E_BADSCHEME, IRI_E_BADESCAPE, IRI_E_BADSEGMENT, IRI_E_BADQUERY or
///   IRI_BADFRAGMENT.
/// </returns>

HRESULT WINAPI IriCreateFromString(
    __in LPCWSTR        pszIri, 
    DWORD               grfEncoding,
    __out HMUTABLEIRI*  phmiri
);


/// <summary>
///   Closes a handle to the specified IRI.
/// </summary>
/// <param name="hiri">
///   A handle to the IRI object to close. 
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK.
///   If the function fails, the return value is E_FAIL.
/// </returns>

HRESULT WINAPI IriClose(
    __in HIRI hiri
);


/// <summary>
///   Closes a handle to the specified mutable IRI.
/// </summary>
/// <param name="hmiri">
///   A handle to the mutable IRI object to be closed. 
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK.
///   If the function fails, the return value is E_FAIL.
/// </returns>

HRESULT WINAPI IriMutableClose(
    __in HMUTABLEIRI hmiri
);


/// <summary>
///   Converts a mutable IRI object into a constant IRI object. 
/// </summary>
/// <param name="hmiri">
///   A handle to a mutable IRI object. If the function succeeds, this handle 
///   will be invalidated. 
/// </param>
/// <param name="phiri">
///   A pointer to a variable that receives the handle of the non-mutable IRI. 
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK.
///   If hmiri is NULL, the return value is E_HANDLE. 
///   If phiri is NULL, the return value is E_POINTER.
/// </returns>

HRESULT WINAPI IriMakeConstant(
    __in HMUTABLEIRI    hmiri,
    __out HIRI*         phiri
);

/// <summary>
///   Converts a mutable IRI object into a constant IRI object. 
/// </summary>
/// <param name="hmiri">
///   A handle to a mutable IRI object. If the function succeeds, this handle 
///   will be invalidated. 
/// </param>
/// <param name="phiri">
///   A pointer to a variable that receives the handle of the non-mutable IRI. 
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK.
///   If hmiri is NULL, the return value is E_HANDLE. 
///   If phiri is NULL, the return value is E_POINTER.
/// </returns>

HRESULT WINAPI IriMakeConstantEx(
    __in HMUTABLEIRI*    hmiri,
    __out HIRI*         phiri
);


/// <summary>
///   Creates a modifiable copy of an IRI.
/// </summary>
/// <param name="hiri">
///   A handle to the IRI object to be copied. 
/// </param>
/// <param name="idwStartSegment">
///   The 0-based index of the first segment in hIRI that will be included 
///   in the copied IRI.
/// </param>
/// <param name="idwEndSegment">
///   0-based index of the first segment to that should not be included in the
///   returned IRI. To include all the segments, set this parameter to the
///   number of segments in the IRI (or pass in the constant
///   IRI_ALL_REMAINING_SEGMENTS). This parameter's value must be greater
///   than or equal to idwStartSegment. 
/// </param>    
/// <param name="grfDestinationComponents">
///   Specifies which components of the source IRI will be included in the new 
///   IRI object returned by this API. This parameter can take any combination of 
///   values from the IRI_COMPONENT enumeration. 
/// </param>
/// <param name="phmiri">
///   A pointer to a variable that receives the handle of the copied IRI. 
///   The handle returned by this function represents a mutable IRI, which 
///   can be modified. 
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK.
///   If hiri is NULL, the return value is E_HANDLE. 
///   If phmiri is NULL, the return value is E_POINTER. 
///   If grfDestinationComponents, idwStartSegment or idwEndSegment  contains
///   invalid values, the return value is E_INVALIDARG.
///   If the function fails due to insufficient memory, the return value 
///   is E_OUTOFMEMORY. 
/// </returns>

HRESULT WINAPI IriCopy(
    __in HIRI           hiri,
    DWORD               idwStartSegment,
    DWORD               idwEndSegment,
    DWORD               grfDestinationComponents,
    __out HMUTABLEIRI*  phmiri
);


/// <summary>
///   Splits an IRI at the specified segment and returns two new mutable 
///   IRI objects containing the results of the split. 
/// </summary>
/// <param name="hiri">
///   A handle to the IRI object to be copied. 
/// </param>
/// <param name="idwSplitSegment">
///   0-based index of the first segment to be included in phmiriTail. 
///   If this parameter  equals the IRI’s segment count, then phmiriHead 
///   will contain the entire IRI, but phmiriTail will be empty 
///   (i.e., IRIGetSegmentCount(*phmiriTail) returns 0).  
/// </param>
/// <param name="grfDestinationComponents">
///   Specifies whether or not the handle returned in phmiriHead will 
///   include any query or fragment that is present in the source IRI (hiri). 
///   This parameter can be a combination values from the IRI_COMPONENTS 
///   enumeration. IRI_COMPONENT_SCHEME applies to both phmiriHead and 
///   phmiriTail - all other values in the enumeration apply to phmiriTail. 
/// </param>
/// <param name="phmiriHead">
///   A pointer to a variable that receives the beginning portion of 
///   the source IRI (up to, but not including idwSplitSegment). 
///   This parameter may be NULL. 
/// </param>
/// <param name="phmiriTail">
///   A pointer to a variable that receives the trailing portion of 
///   the source IRI (starting at idwSegment). This parameter may be NULL.
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK.
///   If hiri is NULL, the return value is E_HANDLE.
///   If idwSplitSegment or grfDestinationComponents contains an invalid value, 
///   the return value is E_INVALIDARG.
///   If both phmiriHead and phmiriTail are NULL, the return value is E_POINTER.
///   If the function fails due to insufficient memory, the return value is 
///   E_OUTOFMEMORY. 
/// </returns>

HRESULT WINAPI IriSplitIntoMutableIris(
    __in HIRI               hiri, 
    DWORD                   idwSplitSegment, 
    DWORD                   grfDestinationComponents,
    __out_opt HMUTABLEIRI*  phmiriHead, 
    __out_opt HMUTABLEIRI*  phmiriTail
);


//==============================================================================
// Querying IRIs

/// <summary>
///   Returns a portion of an IRI as a string in canonical form. 
/// </summary>
/// <param name="hiri">
///   A handle to an IRI object.
/// </param>
/// <param name="idwStartSegment">
///   0-based index of the first segment to be included in the returned 
///   string.
/// </param>
/// <param name="idwEndSegment">
///   0-based index of the first segment to that should not be included in the
///   returned string. To include all the segments, set this parameter to the
///   number of segments in the IRI  (or pass in the constant
///   IRI_ALL_REMAINING_SEGMENTS). This parameter's value must be greater
///   than or equal to idwStartSegment. 
/// </param>    
/// <param name="grfDestinationComponents">
///   Specifies which components of the IRI will be included in the returned 
///   string. This parameter can be a combination values from the IRI_COMPONENT 
///   enumeration. 
/// </param>
/// <param name="pszRelativeIRI">
///   Pointer to a buffer that will receive the canonical representation of 
///   the IRI. This parameter may be NULL.
/// </param>
/// <param name="cchRelativeIRI">
///   Specifies the size in characters of the buffer that pszRelativeIRI points 
///   to (including the NULL terminator). This parameter is ignored if 
///   pszRelativeIRI is NULL. 
/// </param>
/// <param name="pcchRelativeIRI">
///   On exit, this parameter will contain the required size of the pszIRI 
///   buffer in characters (including the NULL terminator). This parameter may 
///   be NULL if pszRelativeIRI is not NULL. 
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK.
///   If hiri is NULL, the return value is E_HANDLE.
///   If both pszRelativeIRI and pcchRelativeIRI are NULL, the return 
///   value is E_POINTER.
///   If idwStartSegment, idwEndSegment or grfDestinationComponents contains
///   an invalid value, the return value is E_INVALIDARG.
///   If the function fails because pszIRI is too small, the return value is 
///   E_INSUFFICIENT_BUFFER. 
/// </returns>

HRESULT WINAPI IriGetAsString(
    __in HIRI                               hiri, 
    DWORD                                   idwStartSegment,
    DWORD                                   idwEndSegment,
    DWORD                                   grfDestinationComponents, 
    __out_ecount_opt(cchRelativeIRI) LPWSTR pszRelativeIRI,
    __in DWORD                              cchRelativeIRI,
    __out_opt DWORD*                        pcchRelativeIRI
);


/// <summary>
///   Returns a portion of an IRI as a new IRI object. 
/// </summary>
/// <param name="hiri">
///   A handle to an IRI object.
/// </param>
/// <param name="idwSegment">
///   0-based index of the first segment to be included in the returned IRI.
/// </param>
/// <param name="idwEndSegment">
///   0-based index of the first segment to that should not be included in the
///   returned IRI. To include all the segments, set this parameter to the
///   number of segments in the IRI  (or pass in the constant
///   IRI_ALL_REMAINING_SEGMENTS). This parameter's value must be greater
///   than or equal to idwStartSegment. 
/// </param>    
/// <param name="grfDestinationComponents">
///   Specifies which components of the IRI will be included in the returned
///   object. This parameter can be a combination of values from the 
///   IRI_COMPONENT enumeration.
/// </param>
/// <param name="phiriRelative">
///   A pointer to a variable that will receive the handle to the IRI object 
///   returned by this function.
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK.
///   If hiri is NULL, the return value is E_HANDLE. 
///   If phiriRelative is NULL, the return value is E_POINTER.
///   If idwSegment or grfDestinationComponents contains an invalid value, 
///   the return value is E_INVALIDARG.
///   If the function fails due to insufficient memory, the return value 
///   is E_OUTOFMEMORY. 
/// </returns>
/// <remarks>
///   This function does not need to copy the underlying data representing 
///   the IRI, so it is not an expensive operation. 
/// </remarks>

HRESULT WINAPI IriGetRelative(
    __in HIRI   hiri, 
    DWORD       idwStartSegment,
    DWORD       idwEndSegment,
    DWORD       grfDestinationComponents,
    __out HIRI* phiriRelative
);

/// <summary>
///   Creates a constant copy of an IRI.
/// </summary>
/// <param name="hiri">
///   A handle to the IRI object to be copied. 
/// </param>
/// <param name="idwStartSegment">
///   The 0-based index of the first segment in hIRI that will be included 
///   in the copied IRI.
/// </param>
/// <param name="idwEndSegment">
///   0-based index of the first segment to that should not be included in the
///   returned IRI. To include all the segments, set this parameter to the
///   number of segments in the IRI (or pass in the constant
///   IRI_ALL_REMAINING_SEGMENTS). This parameter's value must be greater
///   than or equal to idwStartSegment. 
/// </param>    
/// <param name="grfDestinationComponents">
///   Specifies which components of the source IRI will be included in the new 
///   IRI object returned by this API. This parameter can take any combination of 
///   values from the IRI_COMPONENT enumeration. 
/// </param>
/// <param name="phmiri">
///   A pointer to a variable that receives the handle of the copied IRI. 
///   The handle returned by this function represents a mutable IRI, which 
///   can be modified. 
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK.
///   If hiri is NULL, the return value is E_HANDLE. 
///   If phmiri is NULL, the return value is E_POINTER. 
///   If grfDestinationComponents, idwStartSegment or idwEndSegment  contains
///   invalid values, the return value is E_INVALIDARG.
///   If the function fails due to insufficient memory, the return value 
///   is E_OUTOFMEMORY. 
/// </returns>

FORCEINLINE
HRESULT WINAPI IriCopyConstant(
    __in HIRI   hiri, 
    DWORD       idwStartSegment,
    DWORD       idwEndSegment,
    DWORD       grfDestinationComponents,
    __out HIRI* phiriRelative
)
{
    return IriGetRelative(
                hiri,
                idwStartSegment,
                idwEndSegment,
                grfDestinationComponents,
                phiriRelative
                );
}


/// <summary>
///   Splits an IRI at the specified segment and returns two new IRI objects 
///   containing the results of the split.
/// </summary>
/// <param name="hiri">
///   A handle to an IRI object.
/// </param>
/// <param name="idwSplitSegment">
///   0-based index of the first segment to be included in phiriTail. 
///   If this parameter  equals the IRI’s segment count, then phiriHead 
///   will contain the entire IRI, but phmiriTail will be empty 
///   (i.e., IRIGetSegmentCount(*phiriTail) returns 0).  
/// </param>
/// <param name="grfDestinationComponents">
///   Specifies whether or not the handle returned in phmiriHead will 
///   include any query or fragment that is present in the source IRI (hiri). 
///   This parameter can be a combination values from the IRI_COMPONENTS 
///   enumeration. IRI_COMPONENT_SCHEME applies to both phmiriHead and 
///   phmiriTail - all other values in the enumeration apply to phiriTail. 
/// </param>
/// <param name="phiriHead">
///   A pointer to a variable that receives the beginning portion of 
///   the source IRI (up to, but not including idwSplitSegment). 
///   This parameter may be NULL. 
/// </param>
/// <param name="phiriTail">
///   A pointer to a variable that receives the trailing portion of 
///   the source IRI (starting at idwSegment). This parameter may be NULL.
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK.
///   If hiri is NULL, the return value is E_HANDLE.
///   If idwSegment or grfDestinationComponents contains an invalid value, 
///   the return value is E_INVALIDARG.
///   If both phiriHead and phiriTail are NULL, the return value is E_POINTER.
///   If the function fails due to insufficient memory, the return value 
///   is E_OUTOFMEMORY. 
/// </returns>

HRESULT WINAPI IriSplit(
    __in HIRI       hiri, 
    DWORD           idwSplitSegment, 
    DWORD           grfDestinationComponents,
    __out_opt HIRI* phiriHead, 
    __out_opt HIRI* phiriTail
);


/// <summary>
///   Returns the attributes of a given IRI object.
/// </summary>
/// <param name="hiri">
///   A handle to an IRI object.
/// </param>
/// <param name="pgrfIRIMetadata">
///   A pointer to a variable that receives the metadata flags for the IRI. 
///   This parameter will be a combination of values from the IRI_METADATA 
///   enumeration.
/// </param>
/// <param name="pgrfComponentsPresent">
///   A pointer to a variable that receives the component presence flags 
///   for the IRI. This parameter will be a combination of values from the 
///   IRI_COMPONENT enumeration.
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK.
///   If hiri is NULL, the return value is E_HANDLE.
///   If both pgrfIRIMetadata and pgrfComponentsPresent are NULL, the return 
///   value is E_INVALIDARG. 
/// </returns>

HRESULT WINAPI IriGetAttributeFlags(
    __in HIRI           hiri, 
    __out_opt DWORD*    pgrfIRIMetadata,
    __out_opt DWORD*    pgrfComponentsPresent
);


/// <summary>
///   Returns a pointer to a component string of the IRI.
/// </summary>
/// <param name="hiri">
///   A handle to an IRI object.
/// </param>
/// <param name="grfComponent">
///   Indicates which component should be returned. This parameter can be one 
///   of the values from the IRI_COMPONENT enumeration.
/// </param>
/// <param name="ppszComponent">
///   A pointer to a variable that receives a pointer to the requested 
///   component of  the IRI. If the IRI does not contain the specified 
///   component, then this will be an empty string. 
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK.
///   If hiri is NULL, the return value is E_HANDLE.
///   If ppszComponent is NULL, the return value is E_POINTER.
///   If grfComponent contains invalid values, the return value is E_INVALIDARG.
/// </returns>
/// <remarks>
///   The pointer returned in ppwszComponent  is not a copy of the string and 
///   the caller must not free or modify the string in any way. 
///   The returned component will not include the component delimiter 
///   (i.e. the scheme does not include ":"; the query does not include "?" and 
///   the fragment does not include "#").
/// </remarks>

HRESULT WINAPI IriGetComponent(
    __in HIRI       hiri, 
    DWORD           grfComponent,
    __out LPCWSTR*  ppszComponent
);


/// <summary>
///  Returns a pointer to the specified segment in the IRI. 
/// </summary>
/// <param name="hiri">
///   A handle to an IRI object.
/// </param>
/// <param name="idwSegment">
///   0-based index of the segment to return. 
/// </param>
/// <param name="ppszSegment">
///   A pointer to a variable that receives a pointer to the 
///   specified segment in the IRI. 
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK.
///   If hiri is NULL, the return value is E_HANDLE.
///   If ppszSegment is NULL, the return value is E_POINTER.
///   If idwSegment contains an invalid value, the return value is E_INVALIDARG. 
/// </returns>
/// <remarks>
///   The pointer returned in ppwszSegment is not a copy of the string and the 
///   caller must not free or modify the string in any way. 
///   The "/" that separate segments in the IRI are not considered part of the 
///   segment and are not included in the segment string. 
/// </remarks>

HRESULT WINAPI IriGetSegment(
    __in HIRI       hiri, 
    DWORD           idwSegment, 
    __out LPCWSTR*  ppszSegment
);


/// <summary>
///   Compares two IRI objects and returns a result of the comparison that 
///   is compatible with the return value of CompareString. 
/// </summary>
/// <param name="hiriFirst">
///   A handle to an IRI object.
/// </param>
/// <param name="hiriSecond">
///   A handle to an IRI object.
/// </param>
/// <param name="grfCompare">
///   Specifies options that control how the comparison of the two IRI 
///   objects is performed. It may be a combination of values from the 
///   IRI_COMPARE_FLAGS enumeration. 
/// </param>
/// <param name="grfComponents">
///   Specifies which components of the IRI (other than the path) should 
///   be considered during the comparison. It may be a combination of values 
///   from the IRI_COMPONENT enumeration. 
/// </param>
/// <param name="pnCompare">
///   A pointer to a variable that receives the result of the comparison of 
///   the two IRI objects. This value is compatible with the return value of 
///   CompareString (i.e. 0 is returned if the two objects are the same, 
///   &lt;0 if hiriFirst is "less than" hiriSecond, and >0 if hiriFirst
///   is "greater than" hiriSecond). 
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK.
///   If hiriFirst or hiriSecond are NULL, the return value is E_HANDLE.
///   If pnCompare is NULL, the return value is E_POINTER.
///   If grfCompare or grfComponents contain invalid values, the return value
///   is E_INVALIDARG.
/// </returns>

HRESULT WINAPI IriCompare(
    __in HIRI  hiriFirst, 
    __in HIRI  hiriSecond, 
    DWORD      grfCompare,
    DWORD      grfComponents,
    __out int* pnCompare
);


/// <summary>
///   Returns the segment index of the last segment that two IRIs have in common.
/// </summary>
/// <param name="hiriFirst">
///   A handle to an IRI object.
/// </param>
/// <param name="hiriSecond">
///   A handle to an IRI object.
/// </param>
/// <param name="grfCompare">
///   Specifies options that control how the comparison of the two IRI objects 
///   is performed. It may be a combination of values from the IRI_COMPARE_FLAGS 
///   enumeration. 
/// </param>
/// <param name="grfComponents">
///   Specifies which components of the IRI (other than the path) should be 
///   considered during the comparison. It may be a combination of values from the 
///   IRI_COMPONENT enumeration. 
/// </param>
/// <param name="pdwCommonSegment">
///   A pointer to a variable that receives 0-based index of the last segment that 
///   the two IRIs have in common. If the IRIs have no segments in common (or they 
///   have different significant components [grfComponents]) then 
///   IRI_E_NOCOMMONSEGMENTS will be returned. 
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK.
///   If hiriFirst or hiriSecond are NULL, the return value is E_HANDLE.
///   If pdwCommonSegment is NULL, the return value is E_POINTER.
///   If grfCompare or grfComponents contain invalid values, the return value
///   is E_INVALIDARG.
///   If the IRIs contain no segments in common, or they have different 
///   significant components (specified by setting flags in grfComponents), 
///   the return value is IRI_E_NOCOMMONSEGMENTS.
/// </returns>

HRESULT WINAPI IriFindLastCommonSegment(
    __in HIRI       hiriFirst, 
    __in HIRI       hiriSecond, 
    DWORD           grfCompare,
    DWORD           grfComponents,
    __out DWORD*    pdwCommonSegment
);


/// <summary>
///   Returns the number of segments in the IRI. 
/// </summary>
/// <param name="hiri">
///   A handle to an IRI object.
/// </param>
/// <param name="pcdwSegments">
///   A pointer to a variable that receives the number of segments in the IRI.
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK.
///   If hiri is NULL, the return value is E_HANDLE.
///   If pcdwSegments is NULL, the return value is E_POINTER.
/// </returns>

HRESULT WINAPI IriGetSegmentCount(
    __in HIRI       hiri, 
    __out DWORD*    pcdwSegments
);


//==============================================================================
// Modifying IRIs

/// <summary>
///   Sets a component of an IRI.
/// </summary>
/// <param name="hmiri">
///   A handle to a mutable IRI object.
/// </param>
/// <param name="grfComponent">
///   Indicates which component will be set. This parameter can be one of the 
///   values from the IRI_COMPONENT enumeration.
/// </param>
/// <param name="pszComponent">
///   The new value of the component for the IRI. 
/// </param>
/// <param name="grfEncoding">
///   Specifies the encoding used by pszComponent. This parameter can be a 
///   combination of values from the IRI_ENCODING enumeration. If the component
///   being modified is the scheme (IRI_COMPONENT_SCHEME) then this parameter 
///   must be set to IRI_ENCODING_NONE. 
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK.
///   If hmiri is NULL, the return value is E_HANDLE. 
///   If pszComponent are NULL, the return value is E_POINTER.
///   If grfComponent or grfEncoding contains invalid values, the return value 
///   is E_INVALIDARG.
///   If pszComponent contains a string that isn’t legal for the component type, 
///   the return value is E_INVALIDARG. 
/// </returns>

HRESULT WINAPI IriSetComponent(
    __in HMUTABLEIRI    hmiri, 
    DWORD               grfComponent,
    __in LPCWSTR        pszComponent,
    DWORD               grfEncoding
);


/// <summary>
///   Appends a new segment to a mutable IRI.
/// </summary>
/// <param name="hmiri">
///   A handle to the a mutable IRI.
/// </param>
/// <param name="pszSegment">
///   The segment to be appended to the IRI.
/// </param>
/// <param name="grfEncoding">
///   Specifies how the segment string (pszSegment) is encoded. 
///   This parameter can be a combination of values from the IRI_ENCODING 
///   enumeration. 
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK.
///   If hmiri is NULL, the return value is E_HANDLE.
///   If pszSegment is NULL, the return value is E_POINTER.
///   If grfEncoding contains invalid values, the return value is E_INVALIDARG.
///   If the function fails because memory is exhausted, the return value is 
///   E_OUTOFMEMORY.
/// </returns>

HRESULT WINAPI IriAppendSegment(
    __in HMUTABLEIRI    hmiri, 
    __in LPCWSTR        pszSegment, 
    DWORD               grfEncoding
);


/// <summary>
///   Appends a portion of an IRI object to a mutable IRI. 
/// </summary>
/// <param name="hmiri">
///   A handle to a mutable IRI object.
/// </param>
/// <param name="hiriToAppend">
///   A handle to an IRI object.  
/// </param>
/// <param name="idwSegment">
///   0-based index of the first segment in hiriToAppend that will be 
///   appended to the IRI.
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK.
///   If hmiri or hiriToAppend are NULL, the return value is E_HANDLE.
///   If idwSegment contains an invalid value, the return value is E_INVALIDARG.
///   If the function fails because memory is exhausted, the return value is E_OUTOFMEMORY.
/// </returns>

HRESULT WINAPI IriAppendRelativeIri(
    __in HMUTABLEIRI    hmiri, 
    __in HIRI           hiriToAppend, 
    DWORD               idwSegment
);


/// <summary>
///   Sets the metadata for the mutable IRI.
/// </summary>
/// <param name="hmiri">
///   A handle to a mutable IRI object.
/// </param>
/// <param name="grMetadata">
///   A variable that has the new metadata settings for the mutable IRI. This
///   parameter can be the following values from the IRI_METADATA enumeration:
///   IRI_METADATA_NONE or IRI_METADATA_ABSOLUTE. 
/// </param>
/// <returns>
///   If the function succeeds, the return value is S_OK.
///   If hmiri is NULL, the return value is E_HANDLE.
///   If grfMetadata contains an invalid value, the return value is
///   E_INVALIDARG.
///   If the IRI doesn't contain any segments and grfMetadata is set to
///   IRI_METADATA_ABSOLUTE, the return value is IRI_E_BADSEGMENT.
/// </returns>

HRESULT WINAPI IriSetMetadata(
    __in HMUTABLEIRI    hmiri,
    DWORD               grfMetadata
);

#ifdef __cplusplus
}
#endif // __cplusplus
    
#endif // _IRI_H_

