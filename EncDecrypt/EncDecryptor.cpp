#include "EncDecryptor.h"

#include <aescommon.h>
#include <windows.h>
#include <process.h>
#include <iostream>

namespace EncDec
{
	constexpr auto ASCII_NULL = 0x00;

	static char aeskey[17];
	static HMODULE m_ModuleHandle;
	static bool m_IsLoaded = false;
	/*
	#define tgcry_cipher_open           fgcry_cipher_open
	#define tgcry_cipher_close          fgcry_cipher_close
	#define tgcry_cipher_encrypt        fgcry_cipher_encrypt
	#define tgcry_cipher_decrypt        fgcry_cipher_decrypt
	#define tgcry_cipher_ctl            fgcry_cipher_ctl
	#define tgcry_strerror              fgcry_strerror
	#define tgcry_randomize             fgcry_randomize
	#define tgcry_check_version         fgcry_check_version
	*/
	void setkey(const char *key, int keysize)
	{
		memset(aeskey, 0, 17);
		memcpy(aeskey, key, keysize);
	}

	int loadfuncs()
	{
		std::cout << "EncDecryptor::loadfuncs()" << std::endl;

#ifdef _WIN32

		m_ModuleHandle = LoadLibrary("libgcrypt.dll");

		std::cout << "cipher library load handle: " << m_ModuleHandle << std::endl;

		if (!m_ModuleHandle)
		{
			std::cout << "EncDecryptor::loadfuncs() -> unable to load ecnryption library (libgcrypt.dll)" << std::endl;
			return 0;
		}

		fgcry_cipher_close = (tgcry_cipher_close)GetProcAddress(m_ModuleHandle, "gcry_cipher_close");

		fgcry_cipher_encrypt = (tgcry_cipher_encrypt)GetProcAddress(m_ModuleHandle, "gcry_cipher_encrypt");

		fgcry_cipher_decrypt = (tgcry_cipher_decrypt)GetProcAddress(m_ModuleHandle, "gcry_cipher_decrypt");

		fgcry_cipher_ctl = (tgcry_cipher_ctl)GetProcAddress(m_ModuleHandle, "gcry_cipher_ctl");

		fgcry_check_version = (tgcry_check_version)GetProcAddress(m_ModuleHandle, "gcry_check_version");

		fgcry_randomize = (tgcry_randomize)GetProcAddress(m_ModuleHandle, "gcry_randomize");

		fgcry_strerror = (tgcry_strerror)GetProcAddress(m_ModuleHandle, "gcry_strerror");

		fgcry_cipher_open = (tgcry_cipher_open)GetProcAddress(m_ModuleHandle, "gcry_cipher_open");

#else

#endif //_WIN32

		m_IsLoaded = true;

		return 1;
	}

	void unloadfuncs()
	{
		std::cout << "EncDecryptor::unloadfuncs()" << std::endl;

#ifdef _WIN32
		FreeLibrary(m_ModuleHandle);
		m_ModuleHandle = NULL;

		fgcry_cipher_open = NULL;
		fgcry_cipher_close = NULL;

		fgcry_cipher_encrypt = NULL;
		fgcry_cipher_decrypt = NULL;

		fgcry_cipher_ctl = NULL;

		fgcry_strerror = NULL;

		fgcry_randomize = NULL;
		fgcry_check_version = NULL;
#endif

		// m_IsLoaded = false;
	}

#define Mfgcry_strerror(a) "crypt error"

	int decrypt(unsigned char * outbuf, int outlen, const unsigned char * crypted, int cryptedlen, const char *ciphername)
	{
		std::cout << "EncDecryptor::decrypt()" << std::endl;

		int rc;
		int cipher = GCRY_CIPHER_DES;
		int keylength = 16;
		gcry_error_t err;
		gcry_cipher_hd_t hd;
		unsigned char iv[33];
		char *lkey;
		char des_key[9], aes_key[17];

		//std::cout << "aes_ecb_decrypt( " << outbuf << ", " << crypted << ", " << cryptedlen << ")" << std::endl;

		memset(iv, ASCII_NULL, 33);

		if (!m_IsLoaded)
		{
			rc = loadfuncs();

			std::cout << "EncDecryptor::decrypt() -> loadfuncs() Return Code = " << rc << std::endl;
			if (rc != 1) return EC_GCRYPT_LOAD_ERROR;
		}

		if (strcmp(ciphername, AES_STANDARD_NAME) == 0) {
			cipher = GCRY_CIPHER_AES;
			keylength = 16;
			lkey = aes_key;
		}
		else if (strcmp(ciphername, DES_STANDARD_NAME) == 0) {
			cipher = GCRY_CIPHER_DES;
			keylength = 8;
			lkey = des_key;

		}

		memset(lkey, 0, keylength + 1);
		memcpy(lkey, aeskey, keylength);
		err = fgcry_cipher_open(&hd, cipher, GCRY_CIPHER_MODE_ECB, 0);
		if (err)
		{
			std::cout << "EncDecryptor::decrypt() -> Failed opening AES cipher: " << Mfgcry_strerror(err) << std::endl;
			if (lkey != 0) {
				delete lkey;
			}
			return EC_ENCRYPT_DECRYPT;
		}

		err = fgcry_cipher_setkey(hd, lkey, keylength);
		if (err)
		{
			std::cout << "EncDecryptor::decrypt() -> Failed setkey: " << Mfgcry_strerror(err) << std::endl;
			return EC_ENCRYPT_DECRYPT;
		}

		err = fgcry_cipher_setiv(hd, iv, keylength);
		if (err)
		{
			std::cout << "EncDecryptor::decrypt() -> Failed setiv: " << Mfgcry_strerror(err) << std::endl;
			return EC_ENCRYPT_DECRYPT;
		}

		err = fgcry_cipher_decrypt(hd, outbuf, outlen, crypted, cryptedlen);
		if (err)
		{
			std::cout << "EncDecryptor::decrypt() -> Failed decrypt: " << Mfgcry_strerror(err) << std::endl;
			return EC_ENCRYPT_DECRYPT;
		}

		fgcry_cipher_close(hd);

		return EC_SUCCESS;
	}


	int encrypt(unsigned char * outbuf, int outlen, const unsigned char * plain, int plainlen, const char *ciphername)
	{
		std::cout << "EncDecryptor::encrypt()" << std::endl;
		int rc;
		gcry_error_t err;
		gcry_cipher_hd_t hd;
		int cipher = GCRY_CIPHER_DES;
		int keylength = 16;
		char *lkey;
		char des_key[9], aes_key[17];
		unsigned char iv[33];

		//std::cout << "aes_ecb_encrypt( " << outbuf << ", " << plain << ", " << plainlen << ")" << std::endl;

		if (m_IsLoaded == 0)
		{
			rc = loadfuncs();

			std::cout << "EncDecryptor::encrypt() -> loadfuncs() Return Code = " << rc << std::endl;
			if (rc != 1) return EC_GCRYPT_LOAD_ERROR;
		}
		if (strcmp(ciphername, AES_STANDARD_NAME) == 0) {
			cipher = GCRY_CIPHER_AES;
			keylength = 16;
			lkey = aes_key;
		}
		else if (strcmp(ciphername, DES_STANDARD_NAME) == 0) {
			cipher = GCRY_CIPHER_DES;
			keylength = 8;
			lkey = des_key;
		}
		memset(lkey, 0, keylength + 1);
		memcpy(lkey, aeskey, keylength);
		memset(iv, ASCII_NULL, 33);

		err = fgcry_cipher_open(&hd, cipher, GCRY_CIPHER_MODE_ECB, 0);
		if (err)
		{
			std::cout << "EncDecryptor::encrypt() -> Failed opening AES cipher: " << Mfgcry_strerror(err) << std::endl;
			return EC_ENCRYPT_DECRYPT;
		}

		err = fgcry_cipher_setkey(hd, lkey, keylength);
		if (err)
		{
			std::cout << "EncDecryptor::encrypt() -> Failed setkey: " << Mfgcry_strerror(err) << std::endl;
			return EC_ENCRYPT_DECRYPT;
		}

		err = fgcry_cipher_setiv(hd, iv, keylength);
		if (err)
		{
			std::cout << "EncDecryptor::encrypt() -> Failed setiv(initialization vector): " << Mfgcry_strerror(err) << std::endl;
			return EC_ENCRYPT_DECRYPT;
		}

		err = fgcry_cipher_encrypt(hd, outbuf, outlen, plain, plainlen);
		if (err)
		{
			std::cout << "EncDecryptor::encrypt() -> Failed encrypt: " << Mfgcry_strerror(err) << std::endl;
			return EC_ENCRYPT_DECRYPT;
		}

		fgcry_cipher_close(hd);


		return EC_SUCCESS;
	}
}