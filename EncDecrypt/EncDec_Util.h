#ifndef _ENC_DEC_UTIL_
#define _ENC_DEC_UTIL_

/*
@author  Ali Yavuz Kahveci aliyavuzkahveci@gmail.com
* @version 1.0
* @since   26-07-2018
* @Purpose: defines DLL and constant expresssions
*/

namespace EncDec
{
#if defined(_WIN32)
#   define DECLSPEC_EXPORT __declspec(dllexport)
#   define DECLSPEC_IMPORT __declspec(dllimport)
	//
	//  HAS_DECLSPEC_IMPORT_EXPORT defined only for compilers with distinct
	//  declspec for IMPORT and EXPORT
#   define HAS_DECLSPEC_IMPORT_EXPORT
#elif defined(__GNUC__)
#   define DECLSPEC_EXPORT __attribute__((visibility ("default")))
#   define DECLSPEC_IMPORT __attribute__((visibility ("default")))
#elif defined(__SUNPRO_CC)
#   define DECLSPEC_EXPORT __global
#   define DECLSPEC_IMPORT /**/
#else
#   define DECLSPEC_EXPORT /**/
#   define DECLSPEC_IMPORT /**/
#endif

#ifndef ENCDEC_DLL
#   ifdef ENCDEC_DLL_IMPORTS
#       define ENCDEC_DLL ENCDEC_DECLSPEC_IMPORT
#   elif defined(ENCDEC_STATIC_LIBS)
#       define ENCDEC_DLL /**/
#   else
#       define ENCDEC_DLL DECLSPEC_EXPORT
#   endif
#endif

}

#endif
