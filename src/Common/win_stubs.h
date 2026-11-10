/*
 * Comprehensive stub headers for embedded builds (no Windows/PC/SC)
 */

#ifndef TC_STUB_WINDOWS_HEADERS_H
#define TC_STUB_WINDOWS_HEADERS_H

#if defined(_WIN32)
/* Real Windows headers - include them */
#include <windows.h>
#include <strsafe.h>
#include <io.h>
#include <pkcs11.h>
#include <Winternl.h>
#else

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

/* Basic types */
typedef int BOOL;
typedef uint8_t BYTE;
typedef int8_t CHAR;
typedef uint16_t WORD;
typedef int16_t SHORT;
typedef uint32_t DWORD;
typedef uint32_t ULONG;
typedef int32_t LONG;
typedef uint64_t ULONGLONG;
typedef int64_t LONGLONG;
typedef uint32_t DWORD_PTR;
typedef void* HANDLE;
typedef void* HINSTANCE;
typedef void* HWND;
typedef void* HDC;
typedef void* HMODULE;
typedef void* HFONT;
typedef void* HBITMAP;
typedef void* HIMAGELIST;
typedef void* HKEY;
typedef void* HMENU;
typedef void* LPVOID;
typedef void* PVOID;
typedef const void* LPCVOID;
typedef char* LPSTR;
typedef const char* LPCSTR;
typedef wchar_t* LPWSTR;
typedef const wchar_t* LPCWSTR;
typedef char TCHAR;
typedef const char* LPCTSTR;
// NOTE: WCHAR must be WORD (uint16_t), not wchar_t: the FatFs module
// ("ffdef.h", included after this stub by the CredsHolder sources) typedefs
// WCHAR as WORD as well, and conflicting typedefs would break the build.
// Nothing in the reduced VeraCrypt configuration uses WCHAR as wchar_t.
typedef WORD WCHAR;
typedef unsigned char UCHAR;
typedef unsigned short USHORT;
typedef unsigned long ULONG_PTR;
typedef size_t SIZE_T;
typedef unsigned int UINT;
typedef ULONG* PULONG;
typedef DWORD* LPDWORD;

/* Windows constants */
#define TRUE 1
#define FALSE 0
#ifndef NULL
#define NULL 0
#endif
#define INVALID_HANDLE_VALUE ((HANDLE)(long)-1)
#define S_OK 0
#define WINAPI
#define WINAPIV
#define CALLBACK
#define STDMETHODCALLTYPE
#define STDAPICALLTYPE
#define STDAPI
#define MAX_PATH 260
#define ARRAYSIZE(x) (sizeof(x)/sizeof((x)[0]))

/* HRESULT */
typedef LONG HRESULT;
#define HRESULT_FROM_WIN32(x) ((HRESULT)(x) <= 0 ? ((HRESULT)(x)) : ((HRESULT) (((x) & 0x0000FFFF) | (FACILITY_WIN32 << 16) | 0x80000000)))
#define FACILITY_WIN32 7
#define STRSAFE_E_INSUFFICIENT_BUFFER 0x80004005L

/* Error codes */
#define ERROR_SUCCESS 0
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_PATH_NOT_FOUND 3

/* String safe stubs */
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

// NOTE: there are no "_open/_close/_read/_write/_lseek/_isatty/_unlink" stubs
// here on purpose: nothing in the CREDS_HOLDER build references them (the
// <io.h> include in "Common/Volumes.c" is excluded by
// "#if !defined(CREDS_HOLDER)"), while the nRF5 Arduino core provides its own
// _write() retarget in "cores/nRF5/main.cpp" - a static inline stub here
// would be a conflicting redefinition in the same translation unit (chdefs.h
// is force-included for every device translation unit).

/* Windows structs used by API stubs below */
typedef struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union {
        struct {
            DWORD Offset;
            DWORD OffsetHigh;
        };
        PVOID Pointer;
    };
    HANDLE hEvent;
} OVERLAPPED, *LPOVERLAPPED;

typedef struct _LARGE_INTEGER {
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME, *PFILETIME;

typedef struct _BY_HANDLE_FILE_INFORMATION {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD dwVolumeSerialNumber;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD nNumberOfLinks;
    DWORD nFileIndexHigh;
    DWORD nFileIndexLow;
} BY_HANDLE_FILE_INFORMATION, *PBY_HANDLE_FILE_INFORMATION;

/* pkcs11.h stubs - minimal PKCS#11 types */
typedef unsigned long CK_ULONG;
typedef CK_ULONG* CK_ULONG_PTR;
typedef unsigned char CK_BYTE;
typedef CK_BYTE* CK_BYTE_PTR;
typedef char CK_CHAR;
typedef CK_CHAR* CK_CHAR_PTR;
typedef void* CK_VOID_PTR;
typedef struct CK_OBJECT_HANDLE__* CK_OBJECT_HANDLE;
typedef struct CK_SESSION_HANDLE__* CK_SESSION_HANDLE;
typedef struct CK_FUNCTION_LIST__* CK_FUNCTION_LIST_PTR;

/* Winternl.h stubs */
typedef LONG NTSTATUS;
typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemCodeIntegrityInformation = 0x67
} SYSTEM_INFORMATION_CLASS;
typedef NTSTATUS (WINAPI *NtQuerySystemInformationFn)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

/* PC/SC stubs */
typedef int SCARDCONTEXT;
typedef SCARDCONTEXT* LPSCARDCONTEXT;
typedef int SCARDHANDLE;
typedef SCARDHANDLE* LPSCARDHANDLE;
typedef int SCARD_READERSTATE;
typedef int SCARD_IO_REQUEST;

/* Windows API stubs */
static inline BOOL FileExists(const wchar_t* path) { (void)path; return FALSE; }
static inline HANDLE CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPVOID lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{ (void)lpFileName; (void)dwDesiredAccess; (void)dwShareMode; (void)lpSecurityAttributes;
  (void)dwCreationDisposition; (void)dwFlagsAndAttributes; (void)hTemplateFile; return INVALID_HANDLE_VALUE; }
static inline BOOL ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) { (void)hFile; (void)lpBuffer; (void)nNumberOfBytesToRead;
    (void)lpNumberOfBytesRead; (void)lpOverlapped; return FALSE; }
static inline BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) { (void)hFile; (void)lpBuffer; (void)nNumberOfBytesToWrite;
    (void)lpNumberOfBytesWritten; (void)lpOverlapped; return FALSE; }
static inline BOOL CloseHandle(HANDLE hObject) { (void)hObject; return FALSE; }
static inline DWORD GetLastError(void) { return ERROR_SUCCESS; }
static inline BOOL SetFilePointerEx(HANDLE hFile, LONGLONG liDistanceToMove, PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod)
{ (void)hFile; (void)liDistanceToMove; (void)lpNewFilePointer; (void)dwMoveMethod; return FALSE; }
static inline BOOL GetFileInformationByHandle(HANDLE hFile, BY_HANDLE_FILE_INFORMATION lpFileInformation)
{ (void)hFile; (void)lpFileInformation; return FALSE; }

/* GUI stubs */
static inline HWND CreateWindowExW(DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName,
    DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu,
    HINSTANCE hInstance, LPVOID lpParam) { (void)dwExStyle; (void)lpClassName; (void)lpWindowName;
    (void)dwStyle; (void)X; (void)Y; (void)nWidth; (void)nHeight; (void)hWndParent; (void)hMenu;
    (void)hInstance; (void)lpParam; return NULL; }
static inline int MessageBoxW(HWND hwnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{ (void)hwnd; (void)lpText; (void)lpCaption; (void)uType; return 0; }
#define MB_ICONHAND 0x10
#define MB_YESNO 0x4
#define WM_APP 0x00008000

/* Memory protection */
static inline BOOL VirtualLock(LPVOID lpAddress, SIZE_T dwSize) { (void)lpAddress; (void)dwSize; return TRUE; }
static inline BOOL VirtualUnlock(LPVOID lpAddress, SIZE_T dwSize) { (void)lpAddress; (void)dwSize; return TRUE; }

/* Misc */
static inline void ZeroMemory(void* dst, size_t len) { memset(dst, 0, len); }
static inline void* memcpy_s(void* dest, size_t destSize, const void* src, size_t count)
{ (void)destSize; return memcpy(dest, src, count); }
static inline HRESULT StringCchCopyA(char* pszDest, size_t cchDest, const char* pszSrc)
{ if (pszSrc) { size_t len = strlen(pszSrc); if (len >= cchDest) return STRSAFE_E_INSUFFICIENT_BUFFER;
    memcpy(pszDest, pszSrc, len + 1); } else { *pszDest = '\0'; } return S_OK; }

#endif /* _WIN32 */
#endif /* TC_STUB_WINDOWS_HEADERS_H */
