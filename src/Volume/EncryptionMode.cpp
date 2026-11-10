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

#include "EncryptionMode.h"
#include "EncryptionModeXTS.h"
#ifdef WOLFCRYPT_BACKEND
#include "EncryptionModeWolfCryptXTS.h"
#endif
#ifndef CREDS_HOLDER
// CredsHolder: the thread pool is neither used nor built for this
// single-threaded target (see DecryptSectors/EncryptSectors below),
// so do not even include its header.
#include "EncryptionThreadPool.h"
#endif

namespace VeraCrypt
{
	EncryptionMode::EncryptionMode () : KeySet (false), SectorOffset (0)
	{
	}

	EncryptionMode::~EncryptionMode ()
	{
	}

	// CredsHolder: this target is single-threaded (embedded device without
	// EncryptionThreadPool), so process sectors in the calling thread.
	// Do NOT use EncryptionThreadPool::DoWork() here, it pulls pthreads and
	// the whole thread pool into the build.
	void EncryptionMode::DecryptSectors (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		DecryptSectorsCurrentThread (data, sectorIndex, sectorCount, sectorSize);
	}

	void EncryptionMode::EncryptSectors (uint8 *data, uint64 sectorIndex, uint64 sectorCount, size_t sectorSize) const
	{
		EncryptSectorsCurrentThread (data, sectorIndex, sectorCount, sectorSize);
	}

	EncryptionModeList EncryptionMode::GetAvailableModes ()
	{
		EncryptionModeList l;

            #ifdef WOLFCRYPT_BACKEND
		l.push_back (shared_ptr <EncryptionMode> (new EncryptionModeWolfCryptXTS ()));
            #else
		l.push_back (shared_ptr <EncryptionMode> (new EncryptionModeXTS ()));
            #endif

		return l;
	}

	void EncryptionMode::ValidateState () const
	{
		if (!KeySet || Ciphers.size() < 1)
			LIB_THROW(NotInitialized (SRC_POS));
	}

	void EncryptionMode::ValidateParameters (uint8 *data, uint64 length) const
	{
		if ((Ciphers.size() > 0 && (length % Ciphers.front()->GetBlockSize()) != 0))
			LIB_THROW(ParameterIncorrect (SRC_POS));
	}

	void EncryptionMode::ValidateParameters (uint8 *data, uint64 sectorCount, size_t sectorSize) const
	{
		if (sectorCount == 0 || sectorSize == 0 || (sectorSize % EncryptionDataUnitSize) != 0)
			LIB_THROW(ParameterIncorrect (SRC_POS));
	}
}
