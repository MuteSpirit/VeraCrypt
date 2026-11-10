/*
 * Stub Strsafe.h for embedded builds (no Windows String Safe APIs)
 */

#ifndef TC_STUB_STRSAFE_H
#define TC_STUB_STRSAFE_H

#if defined(_WIN32)
#include <strsafe.h>
#else

#include <string.h>
#include <wchar.h>

#ifndef ARRAYSIZE
#define ARRAYSIZE(x) (sizeof(x)/sizeof((x)[0]))
#endif

/* Stub implementations - not used in embedded builds */
static inline HRESULT StringCchCopyW(wchar_t* pszDest, size_t cchDest, const wchar_t* pszSrc)
{
    if (pszSrc) {
        size_t len = wcslen(pszSrc);
        if (len >= cchDest) return STRSAFE_E_INSUFFICIENT_BUFFER;
        memcpy(pszDest, pszSrc, (len + 1) * sizeof(wchar_t));
    } else {
        *pszDest = L'\0';
    }
    return S_OK;
}

static inline HRESULT StringCchCatW(wchar_t* pszDest, size_t cchDest, const wchar_t* pszSrc)
{
    size_t lenDest = wcslen(pszDest);
    size_t lenSrc = wcslen(pszSrc);
    if (lenDest + lenSrc >= cchDest) return STRSAFE_E_INSUFFICIENT_BUFFER;
    memcpy(pszDest + lenDest, pszSrc, (lenSrc + 1) * sizeof(wchar_t));
    return S_OK;
}

#endif /* _WIN32 */
#endif /* TC_STUB_STRSAFE_H */
