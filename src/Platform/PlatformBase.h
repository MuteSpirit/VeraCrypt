/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2026 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Platform_PlatformBase
#define TC_HEADER_Platform_PlatformBase

#include <cstddef>
#include <typeinfo>

// ETL has no <locale> analog so use it together with both ETL and STL
#include <locale>

#if !defined(ETL_NO_STL)

#include <list>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <sstream>

using namespace std;

#else // !ETL_NO_STL

#include <Embedded_Template_Library.h>
#include <etl/list.h>
#include <etl/map.h>
#include <etl/memory.h>
#include <etl/string.h>
#include <etl/wstring.h>
#include <etl/vector.h>
#include <etl/string_stream.h>
#include <etl/wstring_stream.h>

template <typename T, size_t N = 64>
using list = etl::list<T, N>;

template <typename K, typename V, size_t N = 32>
using map = etl::map<K, V, N>;

// Alias templates cannot be used without an explicit argument list (CTAD is
// not applicable to them in C++14/17), but VeraCrypt sources use the bare
// "string"/"wstring" names, so define them as concrete fixed-capacity types
// (the same default capacity the previous alias templates provided)
typedef etl::string<128> string;
typedef etl::wstring<128> wstring;

template <typename T, size_t N = 64>
using vector = etl::vector<T, N>;

using stringstream = etl::string_stream;
using wstringstream = etl::wstring_stream;

// VeraCrypt Platform headers (StringConverter.h, SerializerFactory.h, ...)
// use type_info and exception unqualified, as provided by "using namespace std"
// in the STL branch above; declare the std names explicitly here to keep
// them resolvable without clashing with the ETL aliases above
using std::bad_alloc;
using std::exception;
using std::type_info;

#endif // !ETL_NO_STL

//
// Common defines/using
//
using std::locale;

#ifndef _MSC_VER
#include <inttypes.h>
#endif

#ifdef nullptr
#undef nullptr
#endif

#if !(defined(_MSC_VER) && _MSC_VER >= 1600)
#define nullptr 0
#endif

namespace VeraCrypt
{
#ifdef _MSC_VER
#	ifndef TC_INT_TYPES_DEFINED
	typedef __int8 int8;
	typedef __int16 int16;
	typedef __int32 int32;
	typedef __int64 int64;
	typedef unsigned __int8 uint8;
	typedef unsigned __int16 uint16;
	typedef unsigned __int32 uint32;
	typedef unsigned __int64 uint64;
#	endif
#else
	typedef int8_t int8;
	typedef int16_t int16;
	typedef int32_t int32;
	typedef int64_t int64;
	typedef uint8_t uint8;
	typedef uint16_t uint16;
	typedef uint32_t uint32;
	typedef uint64_t uint64;
#endif
}

#if (defined(_WIN32) || defined(_WIN64)) && !defined(TC_WINDOWS)
#	define TC_WINDOWS
#endif

#if defined(_DEBUG) && !defined(DEBUG)
#	define DEBUG
#endif

#ifndef TC_TO_STRING
#	define TC_TO_STRING2(n) #n
#	define TC_TO_STRING(n) TC_TO_STRING2(n)
#endif

#define TC_JOIN_ARGS(a,b) a##b
#define TC_JOIN(a,b) TC_JOIN_ARGS(a,b)

#ifdef __GNUC__
	template <class T> string GetFunctionName (T pos)
	{
		string s (pos);
		size_t p = s.find ('(');
		if (p == string::npos)
			return s;
		s = s.substr (0, p);
		p = s.find_last_of (" ");
		if (p == string::npos)
			return s;
		return s.substr (p + 1);
	}
#	define SRC_POS (GetFunctionName (__PRETTY_FUNCTION__) += ":" TC_TO_STRING(__LINE__))
#	define TC_UNUSED_VAR __attribute__ ((unused))
#else
#	define SRC_POS (__FUNCTION__ ":" TC_TO_STRING(__LINE__))
#	define TC_UNUSED_VAR
#endif

#ifdef trace_point
#	undef trace_point
#endif

#ifdef trace_msg
#	undef trace_msg
#endif

#ifdef DEBUG
#	define if_debug(...) __VA_ARGS__

#	ifdef TC_WINDOWS
#		define trace_point OutputDebugStringA ((string (SRC_POS) + "\n").c_str())
#		define trace_msg(stream_args) do { stringstream s; s << (SRC_POS) << ": " << stream_args << endl; OutputDebugStringA (s.str().c_str()); } while (0)
#		define trace_msgw(stream_args) do { wstringstream s; s << (SRC_POS) << L": " << stream_args << endl; OutputDebugStringW (s.str().c_str()); } while (0)
#	else
#		include <iostream>
#		define trace_point cerr << (SRC_POS) << endl
#		define trace_msg(stream_args) cerr << (SRC_POS) << ": " << stream_args << endl
#		define trace_msgw(stream_args) cerr << (SRC_POS); wcerr << L": " << stream_args << endl
#	endif

#	include "Platform/SystemLog.h"
#	define trace_log_point SystemLog::WriteError (SRC_POS)
#	define trace_log_msg(stream_args) do { stringstream s; s << (SRC_POS) << ": " << stream_args; SystemLog::WriteError (s.str()); } while (0)

#else
#	define if_debug(...)
#	define trace_point
#	define trace_msg(...)
#	define trace_msgw(...)
#	define trace_log_point
#	define trace_log_msg(...)
#endif

#define trace_val(VAL) trace_msg (#VAL << '=' << (VAL));

#define array_capacity(arr) (sizeof (arr) / sizeof ((arr)[0]))

#endif // TC_HEADER_Platform_PlatformBase
