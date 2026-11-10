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

#ifndef TC_HEADER_Platform_Exception
#define TC_HEADER_Platform_Exception

#include "PlatformBase.h"
#include "LibMacros.h"

// CREDS_HOLDER build compiles VeraCrypt with -fno-exceptions and does not use
// the Serializable / SerializerFactory / StringConverter machinery at all, so
// all declarations and definitions related to the Serializable,
// SerializerFactory or Exception classes are compiled out for it
// (see VERACRYPT_CPP_SRCS notes in the CredsHolder Makefile).
#if !defined(CREDS_HOLDER)

// Include Serializable.h unconditionally - the include guard prevents
// circular inclusion when Serializable.h includes Exception.h
#include "Serializable.h"

#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
#include <exception>

namespace VeraCrypt
{
#define TC_SERIALIZABLE_EXCEPTION(TYPE) TC_SERIALIZABLE (TYPE); \
	virtual Exception *CloneNew () { return new TYPE (*this); } \
	virtual void Throw () const { throw *this; }

	struct Exception : public exception, public Serializable
	{
	public:
		Exception () { }
		Exception (const string &message) : Message (message) { }
		Exception (const string &message, const wstring &subject) : Message (message), Subject (subject) { }
		virtual ~Exception () throw () { }

		TC_SERIALIZABLE_EXCEPTION (Exception);

		virtual const char *what () const throw () { return Message.c_str(); }
		virtual const wstring &GetSubject() const { return Subject; }

	protected:
		string Message;
		wstring Subject;
	};

	struct ExecutedProcessFailed : public Exception
	{
		ExecutedProcessFailed () { }
		ExecutedProcessFailed (const string &message, const string &command, int exitCode, const string &errorOutput)
			: Exception (message), Command (command), ExitCode (exitCode), ErrorOutput (errorOutput) { }
		virtual ~ExecutedProcessFailed () throw () { }

		TC_SERIALIZABLE_EXCEPTION (ExecutedProcessFailed);

		string GetCommand () const { return Command; }
		int64 GetExitCode () const { return ExitCode; }
		string GetErrorOutput () const { return ErrorOutput; }

	protected:
		string Command;
		int64 ExitCode;
		string ErrorOutput;
	};

} // namespace VeraCrypt

#else // // defined(__cpp_exceptions) || defined(__EXCEPTIONS)

namespace VeraCrypt
{
    class Exception : public Serializable
    {
    public:
        Exception() = default;
        Exception(const string &) {};
        Exception(const string &, const wstring &) {};

        virtual ~Exception() {};

        // No-op implementations for no-exceptions mode
        virtual void DeserializeData (shared_ptr <Stream>) { }
        virtual void SerializeData (shared_ptr <Stream>) const { }
    };

 // The TC_* exception machinery is usable only in exceptions-enabled builds:
 // with exceptions disabled LIB_THROW() expands to std::abort() and discards
 // its argument, so no exception type is ever constructed and TC_EXCEPTION_SET
 // must not expand (it would reference Serializable otherwise).
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)

#define TC_EXCEPTION_DECL(NAME,BASE) \
 struct NAME  : public BASE \
 { \
  NAME () { } \
  NAME (const string &message) : BASE (message) { } \
  NAME (const string &message, const wstring &subject) : BASE (message, subject) { } \
  virtual Exception *CloneNew () { return new NAME (*this); } \
  static Serializable *GetNewSerializable () { return new NAME (); } \
  virtual void Throw () const { } \
 }

#define TC_EXCEPTION_NODECL(dummy) //
#define TC_EXCEPTION(NAME) TC_EXCEPTION_DECL(NAME,Exception)

#ifdef TC_EXCEPTION_SET
#undef TC_EXCEPTION_SET
#endif
#define TC_EXCEPTION_SET \
	TC_EXCEPTION_NODECL (Exception); \
	TC_EXCEPTION_NODECL (ExecutedProcessFailed); \
	TC_EXCEPTION (AlreadyInitialized); \
	TC_EXCEPTION (AssertionFailed); \
	TC_EXCEPTION (DeviceSectorSizeMismatch); \
	TC_EXCEPTION (ExternalException); \
	TC_EXCEPTION (InsufficientData); \
	TC_EXCEPTION (NotApplicable); \
	TC_EXCEPTION (NotImplemented); \
	TC_EXCEPTION (NotInitialized); \
	TC_EXCEPTION (ParameterIncorrect); \
	TC_EXCEPTION (ParameterTooLarge); \
	TC_EXCEPTION (PartitionDeviceRequired); \
	TC_EXCEPTION (StringConversionFailed); \
	TC_EXCEPTION (TerminalNotFound); \
	TC_EXCEPTION (TestFailed); \
	TC_EXCEPTION (TimeOut); \
	TC_EXCEPTION (UnknownException); \
	TC_EXCEPTION (UserAbort); \
	TC_EXCEPTION (MountPointBlocked); \
	TC_EXCEPTION (MountPointNotAllowed)

	TC_EXCEPTION_SET;

#undef TC_EXCEPTION

#endif // defined(__cpp_exceptions) || defined(__EXCEPTIONS)
} // namespace VeraCrypt

#endif // defined(__cpp_exceptions) || defined(__EXCEPTIONS)

#endif // !defined(CREDS_HOLDER)

#ifdef assert
#	undef assert
#endif

#if defined(DEBUG) && (defined(__cpp_exceptions) || defined(__EXCEPTIONS))
#	define assert(condition) do { if (!(condition)) throw AssertionFailed (SRC_POS); } while (false)
#else
#	define assert(condition) ((void) 0)
#endif

#endif // TC_HEADER_Platform_Exception
