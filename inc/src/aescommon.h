/*
################################################################################
#                                                                              #
# AUTHOR           : Andrew Fleming                                            #
#                                                                              #
# CREATION DATE    : 11 Feb 2008                                               #
#                                                                              #
# SHORT DESCRIPTION: AES Encryption/decryption standalone Tool                 #
#                                                                              #
# (c) Lufthansa Systems Infratec 2002 - 2008                                   #
#                                                                              #
#------------------------------------------------------------------------------#
# File name        : $RCSfile: aescommon.h,v $
# Location         : $Source: /cutefuture/home/cutecvs/repository/cvs/development/cutefuture/tools/aesutility_standalone/EDS/aescommon.h,v $
# Last edited by   : $Author: dietrich $
# Last Checkin     : $Date: 2009/09/15 16:52:32 $
# Revision         : $Revision: 1.1 $
#------------------------------------------------------------------------------#
# rules:
#
# Please do not change this file otherwise told by cute@lhsystems.com
################################################################################
*/
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#define NONE_LOGLVL		0
#define ERROR_LOGLVL	1
#define WARN_LOGLVL		2
#define INFO_LOGLVL		3
#define DEBUG_LOGLVL	4

const int EC_SUCCESS = 0;

const int EC_ENCRYPT_DECRYPT                 = 0x00000001;
const int EC_GCRYPT_LOAD_ERROR               = 0x00000002;
const int EC_UNKNOWN_MODE				     = 0x00000004;
const int EC_INPUTFILE_DOESNOTEXIST          = 0x00000008;
const int EC_OUTPUTFILE_ALREADY_EXISTS       = 0x00000010;
const int EC_INPUTFILE_NAME_MISSING			 = 0x00000020;
const int EC_OUTPUTFILE_NAME_MISSING		 = 0x00000040;
const int EC_MODE_MISSING				     = 0x00000080;

const int EC_KEY_MISSING					 = 0x00000100;
const int EC_INCORRECT_SIZE				     = 0x00000200;
const int EC_NO_CIPHER_SET                   = 0x00000400;

#define AES_STANDARD_NAME                    "AES"
#define DES_STANDARD_NAME                    "DES"


extern int logging;
extern int loadfuncs();
extern void unloadfuncs();
extern void setkey(char *key, int keysize=16);
