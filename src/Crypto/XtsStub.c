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
///
/// @file XtsStub.c
///
/// Linker stubs for the C entry points which are referenced by the reduced
/// ("TC_WINDOWS_BOOT") VeraCrypt C crypto layer but are never called on this
/// target, plus the real C XTS implementation for the ones which are:
///
/// 1. wolfCrypt XTS backend entry points ("xts_*", see "Crypto/wolfCrypt.c")
///    - referenced by the CipherAES vtable when WOLFCRYPT_BACKEND is forced
///    by "src/veracrypt/chdefs.h". The whole XTS layer is provided by the
///    C++ VeraCrypt::EncryptionModeXTS (see "src/veracrypt/Volume/"), which
///    builds XTS on top of plain AES block operations, so these wolf-mode
///    functions are never called.
/// 2. AES-NI hardware entry points ("aes_hw_cpu_*") - referenced by the
///    boot-style EncipherBlock()/DecipherBlock()/EnableHwEncryption(). The
///    real implementations live in "Crypto/Aes_hw_cpu.asm", which is not
///    built for this target, and AES-NI is disabled by CRYPTOPP_DISABLE_AESNI,
///    so IsAesHwCpuSupported() always returns FALSE and these stubs are
///    unreachable at runtime.
///
/// 3. C XTS entry points ("EncryptBufferXTS"/"DecryptBufferXTS") - referenced
///    by the boot-style EncryptBuffer()/DecryptBuffer()/...DataUnits() and
///    therefore by the boot-mode ReadVolumeHeader() ("Common/Volumes.c"),
///    which decrypts and verifies the volume header through them (and by
///    VeraCryptIoImpl::format(), see "veracrypt_io.cpp", which encrypts the
///    freshly created volume header the same way). The implementation below
///    is taken from the upstream "Common/Xts.c" variant for platforms without
///    native 64-bit data types (TC_NO_COMPILER_INT64): it relies only on the
///    single block primitives EncipherBlock()/DecipherBlock() provided by the
///    boot-mode "Common/Crypto.c" (the 64-bit upstream variant would need the
///    cascade helpers EncipherBlocks()/DecipherBlocks() which are excluded
///    from the boot-mode configuration). It works for both the 32-bit device
///    build (nRF52840) and the 64-bit host build.
///

// The upstream "Common/Xts.c" provides two code paths: a full 64-bit one and
// a portable 32-bit one (TC_NO_COMPILER_INT64). Only the 32-bit variant is
// pulled into this reduced build, hence the define below. It affects this
// translation unit only:
//   * UINT64_STRUCT keeps its layout (union of {LowPart, HighPart} and
//     uint64 Value), so pointers exchanged with the other translation units
//     stay compatible;
//   * the entry points have C linkage, so the width difference of the
//     "length" parameter (TC_LARGEST_COMPILER_UINT: 64-bit in the host
//     callers, 32-bit here) is harmless on both supported little-endian
//     platforms: the value arrives in the argument register and the callee
//     reads its low 32 bits, which is exact for every length below 4 GiB.
#define TC_NO_COMPILER_INT64

#include <memory.h>
#include "Aes.h"
#include "Common/Tcdefs.h"
#include "Common/Xts.h"
#include "Aes_hw_cpu.h"

#ifdef WOLFCRYPT_BACKEND
#include <stdlib.h>

AES_RETURN xts_encrypt_key256(const unsigned char *key, aes_encrypt_ctx cx[1])
{
    (void)key;
    (void)cx;
#if defined(AES_ERR_CHK)
    return EXIT_FAILURE;
#endif
}

AES_RETURN xts_decrypt_key256(const unsigned char *key, aes_decrypt_ctx cx[1])
{
    (void)key;
    (void)cx;
#if defined(AES_ERR_CHK)
    return EXIT_FAILURE;
#endif
}

#ifdef WOLFCRYPT_BACKEND
// word64 is declared by Aes.h only for the wolfCrypt backend declarations,
// so these stubs must be compiled only together with them
AES_RETURN xts_encrypt(const unsigned char *in, unsigned char *out, word64 length, word64 sector, const aes_encrypt_ctx cx[1])
{
    (void)in;
    (void)out;
    (void)length;
    (void)sector;
    (void)cx;
#if defined(AES_ERR_CHK)
    return EXIT_FAILURE;
#endif
}

AES_RETURN xts_decrypt(const unsigned char *in, unsigned char *out, word64 length, word64 sector, const aes_decrypt_ctx cx[1])
{
    (void)in;
    (void)out;
    (void)length;
    (void)sector;
    (void)cx;
#if defined(AES_ERR_CHK)
    return EXIT_FAILURE;
#endif
}
#endif // WOLFCRYPT_BACKEND
#endif // WOLFCRYPT_BACKEND

//
// C XTS entry points - upstream "Common/Xts.c" (TC_NO_COMPILER_INT64 variant)
//

/* ---- The following code is to be used only when native 64-bit data types are not available. ---- */

#if BYTE_ORDER == BIG_ENDIAN
#error The TC_NO_COMPILER_INT64 version of the XTS code is not compatible with big-endian platforms
#endif


// Converts a 64-bit unsigned integer (passed as two 32-bit integers for compatibility with non-64-bit
// environments/platforms) into a little-endian 16-byte array.
static void Uint64ToLE16ByteArray (unsigned __int8 *byteBuf, unsigned __int32 highInt32, unsigned __int32 lowInt32)
{
	unsigned __int32 *bufPtr32 = (unsigned __int32 *) byteBuf;

	*bufPtr32++ = lowInt32;
	*bufPtr32++ = highInt32;

	// We're converting a 64-bit number into a little-endian 16-byte array so we can zero the last 8 bytes
	*bufPtr32++ = 0;
	*bufPtr32 = 0;
}


// Encrypts or decrypts all blocks in the buffer in XTS mode. For descriptions of the input parameters,
// see the 64-bit version of EncryptBufferXTS() in the upstream "Common/Xts.c".
static void EncryptDecryptBufferXTS32 (const unsigned __int8 *buffer,
							TC_LARGEST_COMPILER_UINT length,
							const UINT64_STRUCT *startDataUnitNo,
							unsigned int startBlock,
							unsigned __int8 *ks,
							unsigned __int8 *ks2,
							int cipher,
							BOOL decryption)
{
	TC_LARGEST_COMPILER_UINT blockCount;
	UINT64_STRUCT dataUnitNo;
	unsigned int block;
	unsigned int endBlock;
	unsigned __int8 byteBufUnitNo [BYTES_PER_XTS_BLOCK];
	unsigned __int8 whiteningValue [BYTES_PER_XTS_BLOCK];
	unsigned __int32 *bufPtr32 = (unsigned __int32 *) buffer;
	unsigned __int32 *whiteningValuePtr32 = (unsigned __int32 *) whiteningValue;
	unsigned __int8 finalCarry;
	unsigned __int32 *const finalDwordWhiteningValuePtr = whiteningValuePtr32 + sizeof (whiteningValue) / sizeof (*whiteningValuePtr32) - 1;

	// Store the 64-bit data unit number in a way compatible with non-64-bit environments/platforms
	dataUnitNo.HighPart = startDataUnitNo->HighPart;
	dataUnitNo.LowPart = startDataUnitNo->LowPart;

	blockCount = length / BYTES_PER_XTS_BLOCK;

	// Convert the 64-bit data unit number into a little-endian 16-byte array.
	// (Passed as two 32-bit integers for compatibility with non-64-bit environments/platforms.)
	Uint64ToLE16ByteArray (byteBufUnitNo, dataUnitNo.HighPart, dataUnitNo.LowPart);

	// Generate whitening values for all blocks in the buffer
	while (blockCount > 0)
	{
		if (blockCount < BLOCKS_PER_XTS_DATA_UNIT)
			endBlock = startBlock + (unsigned int) blockCount;
		else
			endBlock = BLOCKS_PER_XTS_DATA_UNIT;

		// Encrypt the data unit number using the secondary key (in order to generate the first
		// whitening value for this data unit)
		memcpy (whiteningValue, byteBufUnitNo, BYTES_PER_XTS_BLOCK);
		EncipherBlock (cipher, whiteningValue, ks2);

		// Generate (and apply) subsequent whitening values for blocks in this data unit and
		// encrypt/decrypt all relevant blocks in this data unit
		for (block = 0; block < endBlock; block++)
		{
			if (block >= startBlock)
			{
				whiteningValuePtr32 = (unsigned __int32 *) whiteningValue;

				// Whitening
				*bufPtr32++ ^= *whiteningValuePtr32++;
				*bufPtr32++ ^= *whiteningValuePtr32++;
				*bufPtr32++ ^= *whiteningValuePtr32++;
				*bufPtr32 ^= *whiteningValuePtr32;

				bufPtr32 -= BYTES_PER_XTS_BLOCK / sizeof (*bufPtr32) - 1;

				// Actual encryption/decryption
				if (decryption)
					DecipherBlock (cipher, bufPtr32, ks);
				else
					EncipherBlock (cipher, bufPtr32, ks);

				whiteningValuePtr32 = (unsigned __int32 *) whiteningValue;

				// Whitening
				*bufPtr32++ ^= *whiteningValuePtr32++;
				*bufPtr32++ ^= *whiteningValuePtr32++;
				*bufPtr32++ ^= *whiteningValuePtr32++;
				*bufPtr32++ ^= *whiteningValuePtr32;
			}

			// Derive the next whitening value

			finalCarry = 0;

			for (whiteningValuePtr32 = finalDwordWhiteningValuePtr;
				whiteningValuePtr32 >= (unsigned __int32 *) whiteningValue;
				whiteningValuePtr32--)
			{
				if (*whiteningValuePtr32 & 0x80000000)	// If the following shift results in a carry
				{
					if (whiteningValuePtr32 != finalDwordWhiteningValuePtr)	// If not processing the highest double word
					{
						// A regular carry
						*(whiteningValuePtr32 + 1) |= 1;
					}
					else
					{
						// The highest byte shift will result in a carry
						finalCarry = 135;
					}
				}

				*whiteningValuePtr32 <<= 1;
			}

			whiteningValue[0] ^= finalCarry;
		}

		blockCount -= endBlock - startBlock;
		startBlock = 0;

		// Increase the data unit number by one
		if (!++dataUnitNo.LowPart)
		{
			dataUnitNo.HighPart++;
		}

		// Convert the 64-bit data unit number into a little-endian 16-byte array.
		Uint64ToLE16ByteArray (byteBufUnitNo, dataUnitNo.HighPart, dataUnitNo.LowPart);
	}

	FAST_ERASE64 (whiteningValue, sizeof (whiteningValue));
}


// For descriptions of the input parameters, see the 64-bit version of EncryptBufferXTS() in the
// upstream "Common/Xts.c".
void EncryptBufferXTS (unsigned __int8 *buffer,
					   TC_LARGEST_COMPILER_UINT length,
					   const UINT64_STRUCT *startDataUnitNo,
					   unsigned int startCipherBlockNo,
					   unsigned __int8 *ks,
					   unsigned __int8 *ks2,
					   int cipher)
{
	// Encrypt all plaintext blocks in the buffer
	EncryptDecryptBufferXTS32 (buffer, length, startDataUnitNo, startCipherBlockNo, ks, ks2, cipher, FALSE);
}


// For descriptions of the input parameters, see the 64-bit version of EncryptBufferXTS() in the
// upstream "Common/Xts.c".
void DecryptBufferXTS (unsigned __int8 *buffer,
					   TC_LARGEST_COMPILER_UINT length,
					   const UINT64_STRUCT *startDataUnitNo,
					   unsigned int startCipherBlockNo,
					   unsigned __int8 *ks,
					   unsigned __int8 *ks2,
					   int cipher)
{
	// Decrypt all ciphertext blocks in the buffer
	EncryptDecryptBufferXTS32 (buffer, length, startDataUnitNo, startCipherBlockNo, ks, ks2, cipher, TRUE);
}

//
// AES-NI hardware entry points (the real implementations live in
// "Crypto/Aes_hw_cpu.asm", which is not built for this target)
//
void aes_hw_cpu_enable_sse ()
{
}

void aes_hw_cpu_encrypt (const uint8 *ks, uint8 *data)
{
    (void)ks;
    (void)data;
}

void aes_hw_cpu_decrypt (const uint8 *ks, uint8 *data)
{
    (void)ks;
    (void)data;
}

uint8 is_aes_hw_cpu_supported ()
{
    // AES-NI is disabled by CRYPTOPP_DISABLE_AESNI (see "chdefs.h"), so
    // report no hardware AES support - same behaviour as for the absent
    // "Crypto/Aes_hw_cpu.asm" implementations stubbed above
    return 0;
}
