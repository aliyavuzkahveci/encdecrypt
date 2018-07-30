#ifndef _BASE64_H
#define _BASE64_H

/*@author  Ali Yavuz Kahveci aliyavuzkahveci@gmail.com
* @version 1.0
* @since   26-07-2018
* @Purpose: Provides functionality to encode or decode a data stream on a base64 basis
*/

#include <string>

#include "EncDec_Util.h"

namespace EncDec
{
	class ENCDEC_DLL Base64 final
	{
	public:
		static std::string Encode(const unsigned char* plainData, unsigned int dataLength);
		static std::string Decode(const std::string& encodedStr);

		virtual ~Base64() {}

	private:
		Base64() {} //to prevent creating the class instance!
		/*to protect the class from being copied*/
		Base64(const Base64&) = delete;
		Base64& operator=(const Base64&) = delete;
		Base64(Base64&&) = delete;
		/*to protect the class from being copied*/
	};
}

#endif
