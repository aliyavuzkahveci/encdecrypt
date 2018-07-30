// EncDecTest.cpp : Defines the entry point for the console application.
//

#include <iostream>
#include <string>

#include <EncDecryptor.h>
#include <Base64.h>
#include <aescommon.h>

constexpr auto AES = "AES";
constexpr auto DES = "DES";

constexpr auto AES_KEY_LENGTH = 16;
constexpr auto DES_KEY_LENGTH = 8;

constexpr auto HELP = "-h";
constexpr auto ENC = "-enc";
constexpr auto DEC = "-dec";
constexpr auto KEY = "-key";
constexpr auto DATA = "-data";

using namespace EncDec;

std::string handleEncryption(const char* alg, const unsigned char* plainData, const unsigned int dataLength, const unsigned char* key, const unsigned int keyLength)
{	//NOTE: Encryption will be handled in ECB mode with PKCS5 padding and iv=0x00!!!
	std::cout << "handleEncryption()" << std::endl;
	std::string encryptedText("");
	char* algorithm;
	unsigned char* plainBuf;
	unsigned char* encryptedBuf;
	unsigned char* pad;
	int plainDataLength = dataLength;
	const int DEFAULT_BLOCKSIZE = 8192;
	int padblock = 16;

	if (plainData == nullptr || dataLength == 0)
	{
		std::cout << "handleEncryption() -> NO data to encrypt! NULL pointer received!" << std::endl;
		return encryptedText;
	}

	if (key == nullptr || keyLength == 0)
	{
		std::cout << "handleEncryption() -> NO key to utilize in encryption! NULL pointer received!" << std::endl;
		return encryptedText;
	}

	if (std::strcmp(alg, AES) == 0)
	{
		algorithm = AES_STANDARD_NAME;
		padblock = 16;
	}
	else if (std::strcmp(alg, DES) == 0)
	{
		algorithm = DES_STANDARD_NAME;
		padblock = 8;
	}
	else
	{
		std::cout << "handleEncryption() -> UNsupported encryption algorithm provided!" << std::endl;
		return encryptedText;
	}

	plainBuf = new unsigned char[DEFAULT_BLOCKSIZE + padblock];
	encryptedBuf = new unsigned char[DEFAULT_BLOCKSIZE + padblock];
	pad = new unsigned char[padblock];

	EncDec::setkey((const char*)key, padblock); //setting the encryption key
	memcpy(plainBuf, plainData, dataLength);

	/*padding in case of plain data size is not the multiple of 16(AES) OR 8(DES)*/
	int padLength = padblock - plainDataLength % padblock;
	memset(pad, padLength, padblock);
	memcpy(plainBuf + plainDataLength, pad, padLength);
	plainDataLength += padLength;
	/*padding in case of plain data is not the multiple of 16(AES) OR 8(DES)*/

	int ret = EncDec::encrypt(encryptedBuf, plainDataLength, plainBuf, plainDataLength, algorithm);

	if (ret == EC_SUCCESS)
	{	//encryption is successful!
		std::cout << "handleEncryption() -> encryption successful!" << std::endl;
		encryptedText = Base64::Encode(encryptedBuf, plainDataLength);
	}
	else
	{	//encryption failed!
		std::cout << "handleEncryption() -> encryption failed!" << std::endl;
	}
	delete[] plainBuf;
	delete[] encryptedBuf;
	delete[] pad;

	return encryptedText;
}

std::string handleDecryption(const char* alg, const unsigned char* encryptedData, const unsigned int dataLength, const unsigned char* key, const unsigned int keyLength)
{	//NOTE: Decryption will be handled in ECB mode with PKCS5 padding and iv=0x00!!!
	std::string plainText("");
	char* algorithm;
	unsigned char* plainBuf;
	unsigned char* encryptedBuf;
	int padblock = 16;

	if (encryptedData == nullptr || dataLength == 0)
	{
		std::cout << "handleDecryption() -> NO data to encrypt! NULL pointer received!" << std::endl;
		return plainText;
	}

	if (key == nullptr || keyLength == 0)
	{
		std::cout << "handleDecryption() -> NO key to utilize in encryption! NULL pointer received!" << std::endl;
		return plainText;
	}

	if (std::strcmp(alg, AES) == 0)
	{
		algorithm = AES_STANDARD_NAME;
		padblock = 16;
	}
	else if (std::strcmp(alg, DES) == 0)
	{
		algorithm = DES_STANDARD_NAME;
		padblock = 8;
	}
	else
	{
		std::cout << "handleDecryption() -> UNsupported encryption algorithm provided!" << std::endl;
		return plainText;
	}

	if (dataLength % padblock != 0) //encrypted data is not the multiple of padblock!!!
	{
		std::cout << "handleDecryption() -> provided encrypted data should be the multiple of 16(AES) or 8(DES) block size!" << std::endl;
		return plainText;
	}

	plainBuf = new unsigned char[dataLength];
	encryptedBuf = new unsigned char[dataLength];

	EncDec::setkey((const char*)key, padblock); //setting the encryption key
	memcpy(encryptedBuf, encryptedData, dataLength);	

	int ret = EncDec::decrypt(plainBuf, dataLength, encryptedBuf, dataLength, algorithm);

	if (ret == EC_SUCCESS)
	{	//decryption is successful!
		std::cout << "handleDecryption() -> decryption successful!" << std::endl;

		int padLength = plainBuf[dataLength - 1];
		plainText = std::string((char*)plainBuf, dataLength-padLength);
	}
	else
	{	//decryption failed!
		std::cout << "handleDecryption() -> decryption failed!" << std::endl;
	}
	delete[] plainBuf;
	delete[] encryptedBuf;

	return plainText;
}

int main(int argc, char* argv[])
{
	int returnValue = 0;
	bool isEncryption = false;

	if (argc == 2 && std::strcmp(argv[1], HELP) == 0)
	{
		returnValue = 1; //HELP requested!
	}
	else if (argc == 7 && std::strcmp(argv[3], KEY) == 0 && std::strcmp(argv[5], DATA) == 0)
	{
		if (std::strcmp(argv[1], ENC) == 0) //-enc
		{	//encryption
			isEncryption = true;
		}
		else if (std::strcmp(argv[1], DEC) == 0) //-dec
		{	//decryption
			isEncryption = false;
		}
		else
		{
			std::cout << "Operation type (encryption | decryption) is not declared correctly!" << std::endl;
			returnValue = -2;
		}

		if (std::strcmp(argv[2], AES) != 0 && std::strcmp(argv[2], DES) != 0) //AES | DES
		{
			std::cout << "Algorithm type (AES | DES) is not declared correctly!" << std::endl;
			returnValue = -3;
		}
	}
	else
	{
		std::cout << "You have entered wrong inputs..." << std::endl;
		returnValue = -1;
	}


	if (returnValue != 0)
	{
		std::cout << "There 2 formats for the correct execution of the program:" << std::endl;
		std::cout << "	1. EncDecTest.exe -enc AES -key ~keyString~ -data ~plainString~" << std::endl;
		std::cout << "	2. EncDecTest.exe -dec AES -key ~keyString~ -data ~encryptedString{Base64 Encoded}~" << std::endl;
		std::cout << "	3. EncDecTest.exe -enc DES -key ~keyString~ -data ~plainString~" << std::endl;
		std::cout << "	4. EncDecTest.exe -dec DES -key ~keyString~ -data ~encryptedString{Base64 Encoded}~" << std::endl;
	}
	else //Starting the execution of the real program!
	{
		if (isEncryption)
		{
			std::string encryptedStr = handleEncryption(argv[2], 
				(const unsigned char*)argv[6], std::strlen(argv[6]), 
				(const unsigned char*)argv[4], std::strlen(argv[4]));

			if (encryptedStr.size())
				std::cout << "Encrypted Data: " << encryptedStr << std::endl;
		}
		else
		{
			//first decode then call decrypt!!!
			std::string decodedEncryptedData = Base64::Decode(std::string(argv[6]));
			std::string plainStr = handleDecryption(argv[2], 
				(const unsigned char*)decodedEncryptedData.c_str(), decodedEncryptedData.size(), 
				(const unsigned char*)argv[4], std::strlen(argv[4]));

			if (plainStr.size())
				std::cout << "Plain Data: " << plainStr << std::endl;
		}
	}
    return returnValue;
}

