#ifndef _ENC_DEC_RYPTOR_
#define _ENC_DEC_RYPTOR_

/*@author  Ali Yavuz Kahveci aliyavuzkahveci@gmail.com
* @version 1.0
* @since   26-07-2018
* @Purpose: Provides functionality to encrypt/decrypt data with the selected algorithm
*/

extern "C" {
#include "gcrypt.h"
}

#include "EncDec_Util.h"

namespace EncDec
{
#ifdef _WIN32

	typedef gcry_error_t(*tgcry_cipher_open)(gcry_cipher_hd_t *handle, int algo, int mode, unsigned int flags);

	typedef void(*tgcry_cipher_close)(gcry_cipher_hd_t h);

	typedef gcry_error_t(*tgcry_cipher_encrypt)
		(gcry_cipher_hd_t h, void *out, size_t outsize, const void *in, size_t inlen);

	typedef gcry_error_t(*tgcry_cipher_decrypt)
		(gcry_cipher_hd_t h, void *out, size_t outsize, const void *in, size_t inlen);

	typedef gcry_error_t(*tgcry_cipher_ctl)
		(gcry_cipher_hd_t h, int cmd, void *buffer, size_t buflen);

	typedef char *          (*tgcry_strerror)             (gpg_error_t err);

	typedef void(*tgcry_randomize)
		(void *buffer, size_t length, enum gcry_random_level level);

	typedef const char *    (*tgcry_check_version)        (const char *req_version);

	static tgcry_cipher_open          fgcry_cipher_open;
	static tgcry_cipher_close         fgcry_cipher_close;

	static tgcry_cipher_encrypt       fgcry_cipher_encrypt;
	static tgcry_cipher_decrypt       fgcry_cipher_decrypt;

	static tgcry_cipher_ctl           fgcry_cipher_ctl;

	static tgcry_strerror             fgcry_strerror;

	static tgcry_randomize            fgcry_randomize;
	static tgcry_check_version        fgcry_check_version;

#else

#define fgcry_cipher_open gcry_cipher_open
#define fgcry_cipher_close gcry_cipher_close

#define fgcry_cipher_encrypt gcry_cipher_encrypt
#define fgcry_cipher_decrypt gcry_cipher_decrypt

#define fgcry_cipher_ctl gcry_cipher_ctl

#define fgcry_strerror gcry_strerror

#define fgcry_randomize gcry_randomize
#define fgcry_check_version gcry_check_version

#endif //else _WIN32

	ENCDEC_DLL void setkey(const char *key, int keysize = 16);

	ENCDEC_DLL int decrypt(unsigned char * outbuf, int outlen, const unsigned char * crypted, int cryptedlen, const char * ciphername);

	/**
	* Encrypts a buffer using AES/DES ECB.
	* @param outbuf Pointer to the output buffer to store the result.
	* @param outlen The length in bytes of the output buffer.
	* @param plain The input buffer containing the plain data.
	* The input data length has to multiple of 16 bytes for AES.
	* @param plainlen The length of the plain data in the input buffer.
	* @return Returns EC_SUCCESS on success, EC_GCRYPT_LOAD_ERROR
	* if there was a problem loading libgcrypt.dll, or EC_ENCRYPT_DECRYPT
	* on other encryption errors.
	*/
	ENCDEC_DLL int encrypt(unsigned char * outbuf, int outlen, const unsigned char * plain, int plainlen, const char * ciphername);
#define fgcry_cipher_setkey(h,k,l) \
   fgcry_cipher_ctl( (h), GCRYCTL_SET_KEY, (char*)(k), (l) )

	// Set initialization vector K of length L for the cipher handle H.
#define fgcry_cipher_setiv(h,k,l)  \
   fgcry_cipher_ctl( (h), GCRYCTL_SET_IV, (char*)(k), (l) )
}

#endif
