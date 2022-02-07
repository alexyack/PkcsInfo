/************************************************************************
JaCarta SDK

ARDS (www.aladdin-rd.ru)

Пример получения информации о библиотеке, слоте и токене

Расширенный и дополненый (Alex)

************************************************************************/

#include <Windows.h>

#include <stdlib.h>
#include <stdio.h>
#include <memory.h>

#include "cryptoki.h"

#ifndef CKA_COPYABLE
#define CKA_COPYABLE					0x00000171
#endif // CKA_COPYABLE

#ifndef CKA_DESTROYABLE
#define CKA_DESTROYABLE					0x00000172
#endif // CKA_DESTROYABLE

#ifndef CKA_NAME_HASH_ALGORITHM
#define CKA_NAME_HASH_ALGORITHM         0x0000008C
#endif // CKA_NAME_HASH_ALGORITHM

#ifndef CKK_GOSTR3410_512
#define CKK_GOSTR3410_512				(0x80000000 | 0x54321000 | 0x003)
#endif // CKK_GOSTR3410_512

#ifndef CKK_KUZNECHIK
#define CKK_KUZNECHIK					(0x80000000 | 0x54321000 | 0x004)
#endif // CKK_KUZNECHIK

#ifndef CK_CERTIFICATE_CATEGORY_UNSPECIFIED
#define CK_CERTIFICATE_CATEGORY_UNSPECIFIED		0x00000000
#endif // CK_CERTIFICATE_CATEGORY_UNSPECIFIED

#ifndef CK_CERTIFICATE_CATEGORY_TOKEN_USER
#define CK_CERTIFICATE_CATEGORY_TOKEN_USER		0x00000001
#endif // CK_CERTIFICATE_CATEGORY_TOKEN_USER

#ifndef CK_CERTIFICATE_CATEGORY_AUTHORITY
#define CK_CERTIFICATE_CATEGORY_AUTHORITY		0x00000002
#endif // CK_CERTIFICATE_CATEGORY_AUTHORITY

#ifndef CK_CERTIFICATE_CATEGORY_OTHER_ENTITY
#define CK_CERTIFICATE_CATEGORY_OTHER_ENTITY	0x00000003
#endif // CK_CERTIFICATE_CATEGORY_OTHER_ENTITY

CK_C_GetFunctionList pGetFunctionList;
CK_FUNCTION_LIST_PTR pFunctionList;

#pragma comment(lib, "crypt32.lib")

#include "info.h"

/************************************************************************
Функция выводит на экран название функции где произошла ошибка и ее код
************************************************************************/
void PrintError(char* func, int retCode)
{
	char* retCodeString;

	switch(retCode)
	{
	case CKR_CANCEL : retCodeString = "CKR_CANCEL"; break;
	case CKR_HOST_MEMORY : retCodeString = "CKR_HOST_MEMORY"; break;
	case CKR_SLOT_ID_INVALID : retCodeString = "CKR_SLOT_ID_INVALID"; break;

	case CKR_GENERAL_ERROR : retCodeString = "CKR_GENERAL_ERROR"; break;
	case CKR_FUNCTION_FAILED : retCodeString = "CKR_FUNCTION_FAILED"; break;

	case CKR_ARGUMENTS_BAD : retCodeString = "CKR_ARGUMENTS_BAD"; break;
	case CKR_NO_EVENT : retCodeString = "CKR_NO_EVENT"; break;
	case CKR_NEED_TO_CREATE_THREADS : retCodeString = "CKR_NEED_TO_CREATE_THREADS"; break;
	case CKR_CANT_LOCK : retCodeString = "CKR_CANT_LOCK"; break;

	case CKR_ATTRIBUTE_READ_ONLY : retCodeString = "CKR_ATTRIBUTE_READ_ONLY"; break;
	case CKR_ATTRIBUTE_SENSITIVE : retCodeString = "CKR_ATTRIBUTE_SENSITIVE"; break;
	case CKR_ATTRIBUTE_TYPE_INVALID : retCodeString = "CKR_ATTRIBUTE_TYPE_INVALID"; break;
	case CKR_ATTRIBUTE_VALUE_INVALID : retCodeString = "CKR_ATTRIBUTE_VALUE_INVALID"; break;
	case CKR_DATA_INVALID : retCodeString = "CKR_DATA_INVALID"; break;
	case CKR_DATA_LEN_RANGE : retCodeString = "CKR_DATA_LEN_RANGE"; break;
	case CKR_DEVICE_ERROR : retCodeString = "CKR_DEVICE_ERROR"; break;
	case CKR_DEVICE_MEMORY : retCodeString = "CKR_DEVICE_MEMORY"; break;
	case CKR_DEVICE_REMOVED : retCodeString = "CKR_DEVICE_REMOVED"; break;
	case CKR_ENCRYPTED_DATA_INVALID : retCodeString = "CKR_ENCRYPTED_DATA_INVALID"; break;
	case CKR_ENCRYPTED_DATA_LEN_RANGE : retCodeString = "CKR_ENCRYPTED_DATA_LEN_RANGE"; break;
	case CKR_FUNCTION_CANCELED : retCodeString = "CKR_FUNCTION_CANCELED"; break;
	case CKR_FUNCTION_NOT_PARALLEL : retCodeString = "CKR_FUNCTION_NOT_PARALLEL"; break;

	case CKR_FUNCTION_NOT_SUPPORTED : retCodeString = "CKR_FUNCTION_NOT_SUPPORTED"; break;
	case CKR_KEY_HANDLE_INVALID : retCodeString = "CKR_KEY_HANDLE_INVALID"; break;
	case CKR_KEY_SIZE_RANGE : retCodeString = "CKR_KEY_SIZE_RANGE"; break;
	case CKR_KEY_TYPE_INCONSISTENT : retCodeString = "CKR_KEY_TYPE_INCONSISTENT"; break;

	case CKR_KEY_NOT_NEEDED : retCodeString = "CKR_KEY_NOT_NEEDED"; break;
	case CKR_KEY_CHANGED : retCodeString = "CKR_KEY_CHANGED"; break;
	case CKR_KEY_NEEDED : retCodeString = "CKR_KEY_NEEDED"; break;
	case CKR_KEY_INDIGESTIBLE : retCodeString = "CKR_KEY_INDIGESTIBLE"; break;
	case CKR_KEY_FUNCTION_NOT_PERMITTED : retCodeString = "CKR_KEY_FUNCTION_NOT_PERMITTED"; break;
	case CKR_KEY_NOT_WRAPPABLE : retCodeString = "CKR_KEY_NOT_WRAPPABLE"; break;
	case CKR_KEY_UNEXTRACTABLE : retCodeString = "CKR_KEY_UNEXTRACTABLE"; break;

	case CKR_MECHANISM_INVALID : retCodeString = "CKR_MECHANISM_INVALID"; break;
	case CKR_MECHANISM_PARAM_INVALID : retCodeString = "CKR_MECHANISM_PARAM_INVALID"; break;

	case CKR_OBJECT_HANDLE_INVALID : retCodeString = "CKR_OBJECT_HANDLE_INVALID"; break;
	case CKR_OPERATION_ACTIVE : retCodeString = "CKR_OPERATION_ACTIVE"; break;
	case CKR_OPERATION_NOT_INITIALIZED : retCodeString = "CKR_OPERATION_NOT_INITIALIZED"; break;
	case CKR_PIN_INCORRECT : retCodeString = "CKR_PIN_INCORRECT"; break;
	case CKR_PIN_INVALID : retCodeString = "CKR_PIN_INVALID"; break;
	case CKR_PIN_LEN_RANGE : retCodeString = "CKR_PIN_LEN_RANGE"; break;

	case CKR_PIN_EXPIRED : retCodeString = "CKR_PIN_EXPIRED"; break;
	case CKR_PIN_LOCKED : retCodeString = "CKR_PIN_LOCKED"; break;

	case CKR_SESSION_CLOSED : retCodeString = "CKR_SESSION_CLOSED"; break;
	case CKR_SESSION_COUNT : retCodeString = "CKR_SESSION_COUNT"; break;
	case CKR_SESSION_HANDLE_INVALID : retCodeString = "CKR_SESSION_HANDLE_INVALID"; break;
	case CKR_SESSION_PARALLEL_NOT_SUPPORTED : retCodeString = "CKR_SESSION_PARALLEL_NOT_SUPPORTED"; break;
	case CKR_SESSION_READ_ONLY : retCodeString = "CKR_SESSION_READ_ONLY"; break;
	case CKR_SESSION_EXISTS : retCodeString = "CKR_SESSION_EXISTS"; break;

	case CKR_SESSION_READ_ONLY_EXISTS : retCodeString = "CKR_SESSION_READ_ONLY_EXISTS"; break;
	case CKR_SESSION_READ_WRITE_SO_EXISTS : retCodeString = "CKR_SESSION_READ_WRITE_SO_EXISTS"; break;

	case CKR_SIGNATURE_INVALID : retCodeString = "CKR_SIGNATURE_INVALID"; break;
	case CKR_SIGNATURE_LEN_RANGE : retCodeString = "CKR_SIGNATURE_LEN_RANGE"; break;
	case CKR_TEMPLATE_INCOMPLETE : retCodeString = "CKR_TEMPLATE_INCOMPLETE"; break;
	case CKR_TEMPLATE_INCONSISTENT : retCodeString = "CKR_TEMPLATE_INCONSISTENT"; break;
	case CKR_TOKEN_NOT_PRESENT : retCodeString = "CKR_TOKEN_NOT_PRESENT"; break;
	case CKR_TOKEN_NOT_RECOGNIZED : retCodeString = "CKR_TOKEN_NOT_RECOGNIZED"; break;
	case CKR_TOKEN_WRITE_PROTECTED : retCodeString = "CKR_TOKEN_WRITE_PROTECTED"; break;
	case CKR_UNWRAPPING_KEY_HANDLE_INVALID : retCodeString = "CKR_UNWRAPPING_KEY_HANDLE_INVALID"; break;
	case CKR_UNWRAPPING_KEY_SIZE_RANGE : retCodeString = "CKR_UNWRAPPING_KEY_SIZE_RANGE"; break;
	case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT : retCodeString = "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"; break;
	case CKR_USER_ALREADY_LOGGED_IN : retCodeString = "CKR_USER_ALREADY_LOGGED_IN"; break;
	case CKR_USER_NOT_LOGGED_IN : retCodeString = "CKR_USER_NOT_LOGGED_IN"; break;
	case CKR_USER_PIN_NOT_INITIALIZED : retCodeString = "CKR_USER_PIN_NOT_INITIALIZED"; break;
	case CKR_USER_TYPE_INVALID : retCodeString = "CKR_USER_TYPE_INVALID"; break;

	case CKR_USER_ANOTHER_ALREADY_LOGGED_IN : retCodeString = "CKR_USER_ANOTHER_ALREADY_LOGGED_IN"; break;
	case CKR_USER_TOO_MANY_TYPES : retCodeString = "CKR_USER_TOO_MANY_TYPES"; break;
	case CKR_WRAPPED_KEY_INVALID : retCodeString = "CKR_WRAPPED_KEY_INVALID"; break;
	case CKR_WRAPPED_KEY_LEN_RANGE : retCodeString = "CKR_WRAPPED_KEY_LEN_RANGE"; break;
	case CKR_WRAPPING_KEY_HANDLE_INVALID : retCodeString = "CKR_WRAPPING_KEY_HANDLE_INVALID"; break;
	case CKR_WRAPPING_KEY_SIZE_RANGE : retCodeString = "CKR_WRAPPING_KEY_SIZE_RANGE"; break;
	case CKR_WRAPPING_KEY_TYPE_INCONSISTENT : retCodeString = "CKR_WRAPPING_KEY_TYPE_INCONSISTENT"; break;
	case CKR_RANDOM_SEED_NOT_SUPPORTED : retCodeString = "CKR_RANDOM_SEED_NOT_SUPPORTED"; break;

	case CKR_RANDOM_NO_RNG : retCodeString = "CKR_RANDOM_NO_RNG"; break;
	case CKR_BUFFER_TOO_SMALL : retCodeString = "CKR_BUFFER_TOO_SMALL"; break;
	case CKR_SAVED_STATE_INVALID : retCodeString = "CKR_SAVED_STATE_INVALID"; break;
	case CKR_INFORMATION_SENSITIVE : retCodeString = "CKR_INFORMATION_SENSITIVE"; break;
	case CKR_STATE_UNSAVEABLE : retCodeString = "CKR_STATE_UNSAVEABLE"; break;

	case CKR_CRYPTOKI_NOT_INITIALIZED : retCodeString = "CKR_CRYPTOKI_NOT_INITIALIZED"; break;
	case CKR_CRYPTOKI_ALREADY_INITIALIZED : retCodeString = "CKR_CRYPTOKI_ALREADY_INITIALIZED"; break;
	case CKR_MUTEX_BAD : retCodeString = "CKR_MUTEX_BAD"; break;
	case CKR_MUTEX_NOT_LOCKED : retCodeString = "CKR_MUTEX_NOT_LOCKED"; break;

	default : retCodeString = "Unknown error code"; break;
	}

	printf("Error in function %s, code= 0x%08X (%s)\n", func, retCode, retCodeString);
}

/************************************************************************
Функция выводит на экран информацию о библиотеке
************************************************************************/
void PrintInfo(CK_INFO_PTR pInfo)
{
	printf("\nLibrary information:\n");

	printf("PKCS#11 version          : %d.%d\n", pInfo->cryptokiVersion.major, pInfo->cryptokiVersion.minor);
	printf("Manufacturer             : %.32s\n", pInfo->manufacturerID);
	printf("Description              : %.32s\n", pInfo->libraryDescription);
	printf("Library version          : %d.%d\n", pInfo->libraryVersion.major, pInfo->libraryVersion.minor);
}

/************************************************************************
Функция выводит на экран информацию о заданом слоте
************************************************************************/
void PrintSlotInfo(CK_SLOT_INFO_PTR pInfo, CK_ULONG slotNumber, CK_SLOT_ID slotID)
{
	printf("\nSlot #%2u = %12d [%08X]:\n", slotNumber, slotID, slotID);

	printf("Manufacturer             : '%.32s'\n", pInfo->manufacturerID);
	printf("Description              : '%.64s'\n", pInfo->slotDescription);
	printf("Hardware version         : %d.%d\n", pInfo->hardwareVersion.major, pInfo->hardwareVersion.minor);
	printf("Firmware version         : %d.%d\n", pInfo->firmwareVersion.major, pInfo->firmwareVersion.minor);
	printf("Slot type                : %s\n", (pInfo->flags & CKF_REMOVABLE_DEVICE) ? "removable" : "stationary");
	printf("Token type               : %s\n", (pInfo->flags & CKF_HW_SLOT) ? "hardware" : "software");
	printf("Token is                 : %s\n", (pInfo->flags & CKF_TOKEN_PRESENT) ? "present" : "absent");

	if(pInfo->flags & 0xFFFFFFF8)
		printf("Rest of flags            : %08X\n", pInfo->flags & 0xFFFFFFF8);
}

/************************************************************************/
/* Функция выводит на экран информацию о токене                                                                     
/************************************************************************/
void PrintTokenInfo(CK_TOKEN_INFO_PTR pInfo)
{
	printf("\nToken:\n");

	printf("Label                    : '%.32s'\n", pInfo->label);
	printf("Manufacturer             : '%.32s'\n", pInfo->manufacturerID);
	printf("Model                    : '%.16s'\n", pInfo->model);
	printf("Serial number            : '%.16s'\n", pInfo->serialNumber);
	printf("Hardware version         : %d.%d\n", pInfo->hardwareVersion.major, pInfo->hardwareVersion.minor);
	printf("Firmware version         : %d.%d\n", pInfo->firmwareVersion.major, pInfo->firmwareVersion.minor);
	printf("Session count            : %d / %d\n", pInfo->ulSessionCount, pInfo->ulMaxSessionCount);
	printf("Maximum RW count         : %d\n", pInfo->ulMaxRwSessionCount);
	printf("PIN length               : [%d...%d]\n", pInfo->ulMinPinLen, pInfo->ulMaxPinLen);
	printf("Public memory            : %d / %d\n", pInfo->ulFreePublicMemory, pInfo->ulTotalPublicMemory);
	printf("Private memory           : %d / %d\n", pInfo->ulFreePrivateMemory, pInfo->ulTotalPrivateMemory);
	printf("Random number generator  : %s\n", (pInfo->flags & CKF_RNG                     ) ? "Yes" : "No");
	printf("Is write protected       : %s\n", (pInfo->flags & CKF_WRITE_PROTECTED         ) ? "Yes" : "No");
	printf("Login required           : %s\n", (pInfo->flags & CKF_LOGIN_REQUIRED          ) ? "Yes" : "No");
	printf("User PIN is set          : %s\n", (pInfo->flags & CKF_USER_PIN_INITIALIZED    ) ? "Yes" : "No");
	printf("Restore key not needed   : %s\n", (pInfo->flags & CKF_RESTORE_KEY_NOT_NEEDED  ) ? "Yes" : "No");
	printf("Clock on token           : %s\n", (pInfo->flags & CKF_CLOCK_ON_TOKEN          ) ? "Yes" : "No");
	printf("Has PAP                  : %s\n", (pInfo->flags & CKF_PROTECTED_AUTHENTICATION_PATH) ? "Yes" : "No");
	printf("Dual crypto operations   : %s\n", (pInfo->flags & CKF_DUAL_CRYPTO_OPERATIONS  ) ? "Yes" : "No");
	printf("Token initialized        : %s\n", (pInfo->flags & CKF_TOKEN_INITIALIZED       ) ? "Yes" : "No");
	printf("Secondary authentication : %s\n", (pInfo->flags & CKF_SECONDARY_AUTHENTICATION) ? "Yes" : "No");
	printf("User PIN count low       : %s\n", (pInfo->flags & CKF_USER_PIN_COUNT_LOW      ) ? "Yes" : "No");
	printf("User PIN final try       : %s\n", (pInfo->flags & CKF_USER_PIN_FINAL_TRY      ) ? "Yes" : "No");
	printf("User PIN locked          : %s\n", (pInfo->flags & CKF_USER_PIN_LOCKED         ) ? "Yes" : "No");
	printf("User PIN to be changed   : %s\n", (pInfo->flags & CKF_USER_PIN_TO_BE_CHANGED  ) ? "Yes" : "No");
	printf("SO PIN count low         : %s\n", (pInfo->flags & CKF_SO_PIN_COUNT_LOW        ) ? "Yes" : "No");
	printf("SO PIN final try         : %s\n", (pInfo->flags & CKF_SO_PIN_FINAL_TRY        ) ? "Yes" : "No");
	printf("SO PIN locked            : %s\n", (pInfo->flags & CKF_SO_PIN_LOCKED           ) ? "Yes" : "No");
	printf("SO PIN to be changed     : %s\n", (pInfo->flags & CKF_SO_PIN_TO_BE_CHANGED    ) ? "Yes" : "No");
	
	if(pInfo->flags & 0xFF00F090)
		printf("Rest of flags            : %08X\n", pInfo->flags & 0xFF00F090);
}

void PrintBOOLValue(CK_BYTE_PTR pValue, CK_ULONG nValue)
{
	if(nValue == 1)
	{
		CK_BBOOL bValue = pValue[0];

		if(bValue == CK_TRUE)
		{
			printf("Yes\n");
		}
		else if(bValue == CK_FALSE)
		{
			printf("No\n");
		}
		else
		{
			printf("%d\n", bValue);
		}
	}
	else
	{
		PrintBLOBValue(pValue, nValue, 16);
	}
}

void PrintBLOBValue(CK_BYTE_PTR pValue, CK_ULONG nValue, CK_ULONG nRadix)
{
	CK_ULONG ckIndex, ckSubIndex = 0;

	if(nValue == 0)
	{
		printf("(NULL)");
	}
	else
	{
		printf("%5d bytes", nValue);
	}

	for(ckIndex = 0; ckIndex < nValue; ckIndex += nRadix)
	{
		printf("\n        %08X:", ckIndex);

		for(ckSubIndex = 0; (ckIndex + ckSubIndex < nValue) && (ckSubIndex < nRadix); ckSubIndex++)
		{
			printf(" %02X", pValue[ckIndex + ckSubIndex]);
		}
	}

	printf("\n");
}

void PrintULONGValue(CK_BYTE_PTR pValue, CK_ULONG nValue)
{
	if(nValue <= 4)
	{
		CK_ULONG ulValue = 0;

		memcpy(&ulValue, pValue, nValue);

		printf("%d [%0*X] (%d)\n", ulValue, nValue * 2, ulValue, nValue);
	}
	else
	{
		PrintBLOBValue(pValue, nValue, 16);
	}
}

void PrintTextValue(CK_BYTE_PTR pValue, CK_ULONG nValue)
{
	printf("'%.*s'\n", nValue, pValue);
}

void PrintDateValue(CK_BYTE_PTR pValue, CK_ULONG nValue)
{
	if(nValue == 8)
	{
		CK_DATE_PTR pDate = (CK_DATE_PTR)(pValue);

		printf("%.2s.%.2s.%.4s\n", pDate->day, pDate->month, pDate->year);
	}
	else
	{
		PrintBLOBValue(pValue, nValue, 16);
	}
}

void PrintOIDValue(CK_BYTE_PTR pValue, CK_ULONG nValue)
{
	DWORD dwOID;
	LPSTR lpOID;
	CHAR szOID[512];

	dwOID = 512;
	lpOID = szOID;

	if((nValue > 2) && (pValue[0] == 6) && CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_OBJECT_IDENTIFIER, pValue, nValue, CRYPT_DECODE_SHARE_OID_STRING_FLAG, &lpOID, &dwOID))
	{
		printf("%s\n", lpOID);
	}
	else
	{
		PrintBLOBValue(pValue, nValue, 16);
	}
}

void PrintDNValue(CK_BYTE_PTR pValue, CK_ULONG nValue)
{
	DWORD dwOID;
	CHAR szOID[512];
	CERT_NAME_BLOB blob;

	blob.pbData = pValue;
	blob.cbData = nValue;

	dwOID = 512;

	if((nValue > 2) && (pValue[0] == 0x30) && CertNameToStr(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &blob, CERT_X500_NAME_STR, szOID, dwOID))
	{
		printf("'%s'\n", szOID);
	}
	else
	{
		PrintBLOBValue(pValue, nValue, 16);
	}
}

void PrintAttrributeName(CK_ATTRIBUTE_TYPE type, CK_RV ckr)
{
	if(CKR_FUNCTION_FAILED == ckr)
	{
	}
	else if(CKR_ATTRIBUTE_TYPE_INVALID == ckr)
	{
	}
	else if(CKR_ATTRIBUTE_VALUE_INVALID == ckr)
	{
	}
	else 
	{
		if(type == CKA_CLASS)
		{
			printf("                   CKA_CLASS: ");
		}
		else if(type == CKA_HW_FEATURE_TYPE)
		{
			printf("         CKA_HW_FEATURE_TYPE: ");
		}
		else if(type == CKA_TOKEN)
		{
			printf("                   CKA_TOKEN: ");
		}
		else if(type == CKA_PRIVATE)
		{
			printf("                 CKA_PRIVATE: ");
		}
		else if(type == CKA_MODIFIABLE)
		{
			printf("              CKA_MODIFIABLE: ");
		}
		else if(type == CKA_LOCAL)
		{
			printf("                   CKA_LOCAL: ");
		}
		else if(type == CKA_SIGN)
		{
			printf("                    CKA_SIGN: ");
		}
		else if(type == CKA_SENSITIVE)
		{
			printf("               CKA_SENSITIVE: ");
		}
		else if(type == CKA_UNWRAP)
		{
			printf("                  CKA_UNWRAP: ");
		}
		else if(type == CKA_EXTRACTABLE)
		{
			printf("             CKA_EXTRACTABLE: ");
		}
		else if(type == CKA_NEVER_EXTRACTABLE)
		{
			printf("       CKA_NEVER_EXTRACTABLE: ");
		}
		else if(type == CKA_ALWAYS_SENSITIVE)
		{
			printf("        CKA_ALWAYS_SENSITIVE: ");
		}
		else if(type == CKA_LABEL)
		{
			printf("                   CKA_LABEL: ");
		}
		else if(type == CKA_APPLICATION)
		{
			printf("             CKA_APPLICATION: ");
		}
		else if(type == CKA_START_DATE)
		{
			printf("              CKA_START_DATE: ");
		}
		else if(type == CKA_END_DATE)
		{
			printf("                CKA_END_DATE: ");
		}
		else if(type == CKA_VALUE)
		{
			printf("                   CKA_VALUE: ");
		}
		else if(type == CKA_VALUE_BITS)
		{
			printf("              CKA_VALUE_BITS: ");
		}
		else if(type == CKA_VALUE_LEN)
		{
			printf("               CKA_VALUE_LEN: ");
		}
		else if(type == CKA_SUBJECT)
		{
			printf("                 CKA_SUBJECT: ");
		}
		else if(type == CKA_ID)
		{
			printf("                      CKA_ID: ");
		}
		else if(type == CKA_SERIAL_NUMBER)
		{
			printf("           CKA_SERIAL_NUMBER: ");
		}
		else if(type == CKA_CERTIFICATE_TYPE)
		{
			printf("        CKA_CERTIFICATE_TYPE: ");
		}
		else if(type == CKA_ISSUER)
		{
			printf("                  CKA_ISSUER: ");
		}
		else if(type == CKA_OBJECT_ID)
		{
			printf("               CKA_OBJECT_ID: ");
		}
		else if(type == CKA_KEY_TYPE)
		{
			printf("                CKA_KEY_TYPE: ");
		}
		else if(type == CKA_MODULUS)
		{
			printf("                 CKA_MODULUS: ");
		}
		else if(type == CKA_MODULUS_BITS)
		{
			printf("            CKA_MODULUS_BITS: ");
		}
		else if(type == CKA_PUBLIC_EXPONENT) 
		{ 
			printf("         CKA_PUBLIC_EXPONENT: "); 
		}
		else if(type == CKA_PRIME_1) 
		{    
			printf("                 CKA_PRIME_1: "); 
		}
		else if(type == CKA_PRIME_2) 
		{ 
			printf("                 CKA_PRIME_2: "); 
		}
		else if(type == CKA_EXPONENT_1)
		{
			printf("              CKA_EXPONENT_1: "); 
		}
		else if(type == CKA_EXPONENT_2  )
		{
			printf("              CKA_EXPONENT_2: "); 
		}
		else if(type == CKA_COEFFICIENT )
		{
			printf("             CKA_COEFFICIENT: "); 
		}
		else if(type == CKA_PRIME       )
		{
			printf("                   CKA_PRIME: "); 
		}
		else if(type == CKA_SUBPRIME    )
		{
			printf("                CKA_SUBPRIME: "); 
		}
		else if(type == CKA_BASE        )
		{
			printf("                    CKA_BASE: "); 
		}
		else if(type == CKA_PRIVATE_EXPONENT)
		{
			printf("        CKA_PRIVATE_EXPONENT: ");
		}
		else if(type == CKA_GOSTR3410_PARAMS)
		{
			printf("        CKA_GOSTR3410_PARAMS: ");
		}
		else if(type == CKA_GOSTR3411_PARAMS)
		{
			printf("        CKA_GOSTR3411_PARAMS: ");
		}
		else if(type == CKA_GOST28147_PARAMS)
		{
			printf("        CKA_GOST28147_PARAMS: ");
		}
		else if(type == CKA_TRUSTED)
		{
			printf("                 CKA_TRUSTED: ");
		}
		else if(type == CKA_URL)
		{
			printf("                     CKA_URL: ");
		}
		else if(type == CKA_HASH_OF_SUBJECT_PUBLIC_KEY)
		{
			printf("         HASH_OF_SUBJECT_KEY: ");
		}
		else if(type == CKA_HASH_OF_ISSUER_PUBLIC_KEY)
		{
			printf("          HASH_OF_ISSUER_KEY: ");
		}
		else if(type == CKA_CHECK_VALUE)
		{
			printf("             CKA_CHECK_VALUE: ");
		}
		else if(type == CKA_ENCRYPT)
		{
			printf("                 CKA_ENCRYPT: ");
		}
		else if(type == CKA_DECRYPT)
		{
			printf("                 CKA_DECRYPT: ");
		}
		else if(type == CKA_WRAP)
		{
			printf("                    CKA_WRAP: ");
		}
		else if(type == CKA_UNWRAP)
		{
			printf("                  CKA_UNWRAP: ");
		}
		else if(type == CKA_SIGN)
		{
			printf("                    CKA_SIGN: ");
		}
		else if(type == CKA_SIGN_RECOVER)
		{
			printf("            CKA_SIGN_RECOVER: ");
		}
		else if(type == CKA_VERIFY)
		{
			printf("                  CKA_VERIFY: ");
		}
		else if(type == CKA_VERIFY_RECOVER)
		{
			printf("          CKA_VERIFY_RECOVER: ");
		}
		else if(type == CKA_DERIVE)
		{
			printf("                  CKA_DERIVE: ");
		}
		else if(type == CKA_KEY_GEN_MECHANISM)
		{
			printf("       CKA_KEY_GEN_MECHANISM: ");
		}
		else if(type == CKA_ALWAYS_AUTHENTICATE)
		{
			printf("     CKA_ALWAYS_AUTHENTICATE: ");
		}
		else if(type == CKA_WRAP_WITH_TRUSTED)
		{
			printf("       CKA_WRAP_WITH_TRUSTED: ");
		}
		else if(type == CKA_CERTIFICATE_CATEGORY)
		{
			printf("        CERTIFICATE_CATEGORY: ");
		}
		else if(type == CKA_JAVA_MIDP_SECURITY_DOMAIN)
		{
			printf("                   JAVA_MIDP: ");
		}
		else if(type == CKA_NAME_HASH_ALGORITHM)
		{
			printf("     CKA_NAME_HASH_ALGORITHM: ");
		}
		else if(type == CKA_COPYABLE)
		{
			printf("                CKA_COPYABLE: ");
		}
		else if(type == CKA_DESTROYABLE)
		{
			printf("             CKA_DESTROYABLE: ");
		}
		else if(type == CKA_RESET_ON_INIT)
		{
			printf("           CKA_RESET_ON_INIT: ");
		}
		else if(type == CKA_HAS_RESET)
		{
			printf("               CKA_HAS_RESET: ");
		}
		else if(type == CKA_PIXEL_X)
		{
			printf("                 CKA_PIXEL_X: ");
		}
		else if(type == CKA_PIXEL_Y)
		{
			printf("                 CKA_PIXEL_Y: ");
		}
		else if(type == CKA_RESOLUTION)
		{
			printf("              CKA_RESOLUTION: ");
		}
		else if(type == CKA_CHAR_ROWS)
		{
			printf("               CKA_CHAR_ROWS: ");
		}
		else if(type == CKA_CHAR_COLUMNS)
		{
			printf("            CKA_CHAR_COLUMNS: ");
		}
		else if(type == CKA_COLOR)
		{
			printf("                   CKA_COLOR: ");
		}
		else if(type == CKA_BITS_PER_PIXEL)
		{
			printf("          CKA_BITS_PER_PIXEL: ");
		}
		else if(type == CKA_CHAR_SETS)
		{
			printf("               CKA_CHAR_SETS: ");
		}
		else if(type == CKA_ENCODING_METHODS)
		{
			printf("        CKA_ENCODING_METHODS: ");
		}
		else if(type == CKA_MIME_TYPES)
		{
			printf("              CKA_MIME_TYPES: ");
		}

		else if(type == CKA_MECHANISM_TYPE)
		{
			printf("          CKA_MECHANISM_TYPE: ");
		}
		else if(type == CKA_EC_PARAMS)
		{
			printf("               CKA_EC_PARAMS: ");
		}
		else if(type == CKA_EC_POINT)
		{
			printf("                CKA_EC_POINT: ");
		}

		else if(type == 0x80001101)
		{
			printf("          ETCKA_PRODUCT_NAME: ");
		}
		else if(type == 0x80001102)
		{
			printf("                 ETCKA_MODEL: ");
		}
		else if(type == 0x80001104)
		{
			printf("           ETCKA_FW_REVISION: ");
		}
		else if(type == 0x80001106)
		{
			printf("           ETCKA_HW_INTERNAL: ");
		}
		else if(type == 0x80001107)
		{
			printf("       ETCKA_PRODUCTION_DATE: ");
		}
		else if(type == 0x80001108)
		{
			printf("            ETCKA_CASE_MODEL: ");
		}
		else if(type == 0x80001109)
		{
			printf("              ETCKA_TOKEN_ID: ");
		}
		else if(type == 0x8000110a)
		{
			printf("               ETCKA_CARD_ID: ");
		}
		else if(type == 0x8000110b)
		{
			printf("             ETCKA_CARD_TYPE: ");
		}
		else if(type == 0x8000110c)
		{
			printf("          ETCKA_CARD_VERSION: ");
		}
		else if(type == 0x8000110e)
		{
			printf("                 ETCKA_COLOR: ");
		}
		else if(type == 0x80001110)
		{
			printf("            ETCKA_RETRY_USER: ");
		}
		else if(type == 0x80001111)
		{
			printf("              ETCKA_RETRY_SO: ");
		}
		else if(type == 0x80001112)
		{
			printf("        ETCKA_RETRY_USER_MAX: ");
		}
		else if(type == 0x80001113)
		{
			printf("          ETCKA_RETRY_SO_MAX: ");
		}
		else if(type == 0x8000111b)
		{
			printf("               ETCKA_HAS_LCD: ");
		}
		else if(type == 0x8000111d)
		{
			printf("                ETCKA_HAS_SO: ");
		}
		else if(type == 0x8000111e)
		{
			printf("                  ETCKA_FIPS: ");
		}
		else if(type == 0x8000111f)
		{
			printf("        ETCKA_FIPS_SUPPORTED: ");
		}
		else if(type == 0x80001120)
		{
			printf("          ETCKA_INIT_PIN_REQ: ");
		}
		else if(type == 0x80001121)
		{
			printf("              ETCKA_RSA_2048: ");
		}
		else if(type == 0x80001122)
		{
			printf("    ETCKA_RSA_2048_SUPPORTED: ");
		}
		else if(type == 0x80001123)
		{
			printf("             ETCKA_HMAC_SHA1: ");
		}
		else if(type == 0x80001124)
		{
			printf("   ETCKA_HMAC_SHA1_SUPPORTED: ");
		}
		else if(type == 0x80001125)
		{
			printf("            ETCKA_REAL_COLOR: ");
		}
		else if(type == 0x80001126)
		{
			printf("              ETCKA_MAY_INIT: ");
		}
		else if(type == 0x80001127)
		{
			printf("  ETCKA_MASS_STORAGE_PRESENT: ");
		}
		else if(type == 0x80001128)
		{
			printf("            ETCKA_ONE_FACTOR: ");
		}
		else if(type == 0x80001129)
		{
			printf("         ETCKA_RSA_AREA_SIZE: ");
		}
		else if(type == 0x8000112a)
		{
			printf("        ETCKA_FORMAT_VERSION: ");
		}
		else if(type == 0x8000112b)
		{
			printf("          ETCKA_USER_PIN_AGE: ");
		}
		else if(type == 0x8000112c)
		{
			printf("  ETCKA_CARDMODULE_AREA_SIZE: ");
		}
		else if(type == 0x8000112d)
		{
			printf("               ETCKA_HASHVAL: ");
		}
		else if(type == 0x8000112e)
		{
			printf("               ETCKA_OS_NAME: ");
		}
		else if(type == 0x8000112f)
		{
			printf(" ETCKA_MINIDRIVER_COMPATIBLE: ");
		}
		else if(type == 0x80001130)
		{
			printf("  ETCKA_MASS_STORAGE_SECURED: ");
		}
		else if(type == 0x80001131)
		{
			printf("      ETCKA_INIT_PKI_VERSION: ");
		}
		else if(type == 0x80001132)
		{
			printf("      ETCKA_CRYPTO_LOCK_MODE: ");
		}
		else if(type == 0x80001133)
		{
			printf("     ETCKA_CRYPTO_LOCK_STATE: ");
		}
		else if(type == 0x80001134)
		{
			printf("         ETCKA_USER_PIN_ITER: ");
		}
		else if(type == 0x80001135)
		{
			printf("    ETCKA_OVERRIDE_RETRY_MAX: ");
		}
		else if(type == 0x80001136)
		{
			printf("         ETCKA_ETV_TEMPORARY: ");
		}
		else if(type == 0x80001137)
		{
			printf("    ETCKA_CLIENTLESS_VERSION: ");
		}
		else if(type == 0x80001138)
		{
			printf("    ETCKA_OS_RELEASE_VERSION: ");
		}

		else if(type == 0x80001B02)
		{
			printf("          MECHANISM_80001B02: ");
		}
		else if(type == 0x80001B03)
		{
			printf("          MECHANISM_80001B03: ");
		}
		else if(type == 0x80001B04)
		{
			printf("          MECHANISM_80001B04: ");
		}
		else if(type == 0x80001B05)
		{
			printf("          MECHANISM_80001B05: ");
		}
		else if(type == 0x80001B06)
		{
			printf("          MECHANISM_80001B06: ");
		}
		else if(type == 0x80001B07)
		{
			printf("          MECHANISM_80001B07: ");
		}
		else if(type == 0x80001B08)
		{
			printf("          MECHANISM_80001B08: ");
		}
		else if(type == 0x80001B09)
		{
			printf("          MECHANISM_80001B09: ");
		}
		else if(type == 0x80001B0A)
		{
			printf("          MECHANISM_80001B0A: ");
		}
		else if(type == 0x80001B0B)
		{
			printf("          MECHANISM_80001B0B: ");
		}

		else if(type == 0x80001201)
		{
			printf("       ETCKA_PIN_POLICY_TYPE: ");
		}
		else if(type == 0x80001202)
		{
			printf("           ETCKA_PIN_MIN_LEN: ");
		}
		else if(type == 0x80001203)
		{
			printf("         ETCKA_PIN_MIX_CHARS: ");
		}
		else if(type == 0x80001204)
		{
			printf("           ETCKA_PIN_MAX_AGE: ");
		}
		else if(type == 0x80001205)
		{
			printf("           ETCKA_PIN_MIN_AGE: ");
		}
		else if(type == 0x80001206)
		{
			printf("       ETCKA_PIN_WARN_PERIOD: ");
		}
		else if(type == 0x80001207)
		{
			printf("      ETCKA_PIN_HISTORY_SIZE: ");
		}
		else if(type == 0x80001208)
		{
			printf("             ETCKA_PIN_PROXY: ");
		}
		else if(type == 0x80001209)
		{
			printf("              ETCKA_80001209: ");
		}
		else if(type == 0x8000120a)
		{
			printf("         ETCKA_BATTERY_VALUE: ");
		}
		else if(type == 0x8000120b)
		{
			printf("      ETCKA_BATTERY_HW_WARN1: ");
		}
		else if(type == 0x8000120c)
		{
			printf("      ETCKA_BATTERY_HW_WARN2: ");
		}
		else if(type == 0x8000120d)
		{
			printf("      ETCKA_BATTERY_HW_WARN3: ");
		}
		else if(type == 0x8000120e)
		{
			printf("   ETCKA_BATTERY_REPLACEABLE: ");
		}
		else if(type == 0x8000120f)
		{
			printf("              ETCKA_8000120F: ");
		}
		else if(type == 0x80001212)
		{
			printf("              ETCKA_80001212: ");
		}
		else if(type == 0x80001401)
		{
			printf("              ETCKA_80001401: ");
		}
		else
		{
			printf("            UNKNOWN %08X: ", type);
		}
	}
}

void PrintObjectClass(CK_OBJECT_CLASS ckUlong)
{
	if(ckUlong == CKO_DATA)
	{
		printf("CKO_DATA\n");
	}
	else if(ckUlong == CKO_CERTIFICATE)
	{
		printf("CKO_CERTIFICATE\n");
	}
	else if(ckUlong == CKO_PUBLIC_KEY)
	{
		printf("CKO_PUBLIC_KEY\n");
	}
	else if(ckUlong == CKO_PRIVATE_KEY)
	{
		printf("CKO_PRIVATE_KEY\n");
	}
	else if(ckUlong == CKO_SECRET_KEY)
	{
		printf("CKO_SECRET_KEY\n");
	}
	else if(ckUlong == CKO_HW_FEATURE)
	{
		printf("CKO_HW_FEATURE\n");
	}
	else if(ckUlong == CKO_DOMAIN_PARAMETERS)
	{
		printf("CKO_DOMAIN_PARAMETERS\n");
	}
	else if(ckUlong == CKO_MECHANISM)
	{
		printf("CKO_MECHANISM\n");
	}
	else if(ckUlong == CKO_OTP_KEY)
	{
		printf("CKO_OTP_KEY\n");
	}	
	else
	{
		printf("%08X\n", ckUlong);
	}
}

void PrintFeautureType(CK_HW_FEATURE_TYPE ckUlong)
{
	if(ckUlong == CKH_MONOTONIC_COUNTER)
	{
		printf("CKH_MONOTONIC_COUNTER\n");
	}
	else if(ckUlong == CKH_CLOCK)
	{
		printf("CKH_CLOCK\n");
	}
	else if(ckUlong == CKH_USER_INTERFACE)
	{
		printf("CKH_USER_INTERFACE\n");
	}
	else if(ckUlong == 0x80005003)
	{
		printf("ETCKH_PIN_POLICY\n");
	}
	else
	{
		printf("%08X\n", ckUlong);
	}
}

void PrintCertiFicateType(CK_ULONG ckUlong)
{
	if(ckUlong == CKC_X_509)
	{
		printf("CKC_X_509\n");
	}
	else if(ckUlong == CKC_X_509_ATTR_CERT)
	{
		printf("CKC_X_509_ATTR_CERT\n");
	}
	else if(ckUlong == CKC_WTLS)
	{
		printf("CKC_WTLS\n");
	}
	else
	{
		printf("%08X\n", ckUlong);
	}
}

void PrintCertificateCategory(CK_ULONG ckUlong)
{
	if(ckUlong == CK_CERTIFICATE_CATEGORY_UNSPECIFIED)
	{
		printf("UNSPECIFIED\n");
	}
	else if(ckUlong == CK_CERTIFICATE_CATEGORY_TOKEN_USER)
	{
		printf("TOKEN_USER\n");
	}
	else if(ckUlong == CK_CERTIFICATE_CATEGORY_AUTHORITY)
	{
		printf("AUTHORITY\n");
	}
	else if(ckUlong == CK_CERTIFICATE_CATEGORY_OTHER_ENTITY)
	{
		printf("OTHER_ENTITY\n");
	}
	else
	{
		printf("%08X\n", ckUlong);
	}
}

void PrintKeyType(CK_ULONG ckUlong)
{
	if(ckUlong == CKK_GOST28147)
	{
		printf("GOST 28147\n");
	}
	else if(ckUlong == CKK_GOSTR3410)
	{
		printf("GOST R 3410\n");
	}
	else if(ckUlong == CKK_GOSTR3411)
	{
		printf("GOST R 3411\n");
	}
	else if(ckUlong == CKK_RSA)
	{
		printf("RSA\n");
	}
	else if(ckUlong == CKK_ECDSA)
	{
		printf("ECDSA\n");
	}
	else if(ckUlong == CKK_GOSTR3410_512)
	{
		printf("GOST R 3410 512\n");
	}
	else if(ckUlong == CKK_KUZNECHIK)
	{
		printf("KUZNECHIK\n");
	}
	else if(ckUlong == CKK_ECDSA)
	{
		printf("ECDSA\n");
	}
	else
	{
		printf("%08X\n", ckUlong);
	}
}

void PrintObjectInfo(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, int nStart, int nFinish)
{
	int nIndex;
	CK_ATTRIBUTE ckAttr;
	CK_RV ckr;
	CK_BYTE pBuffer[BUFF_SIZE];
	CK_ULONG ckUlong, cbBuffer;

	for(nIndex = nStart; nIndex < nFinish; nIndex++)
	{
		memset(pBuffer, 0, BUFF_SIZE);

		ckAttr.type = nIndex;
		ckAttr.pValue = pBuffer;
		ckAttr.ulValueLen = BUFF_SIZE;

		ckr = pFunctionList->C_GetAttributeValue(hSession, hObject, &ckAttr, 1);

		PrintAttrributeName(nIndex, ckr);

		if(ckr == CKR_OK)
		{
			cbBuffer = ckAttr.ulValueLen;

			if(cbBuffer == 4)
			{
				ckUlong = *((CK_ULONG_PTR)pBuffer);
			}
			else
			{
				ckUlong = 0;
			}

			if(ckAttr.type == CKA_CLASS)
			{
				PrintObjectClass(ckUlong);
			}
			else if(ckAttr.type == CKA_HW_FEATURE_TYPE)
			{
				PrintFeautureType(ckUlong);
			}
			else if(ckAttr.type == CKA_TOKEN)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_PRIVATE)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_MODIFIABLE)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_COPYABLE)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_DESTROYABLE)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_LOCAL)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_SIGN)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_SENSITIVE)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_UNWRAP)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_EXTRACTABLE)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_NEVER_EXTRACTABLE)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_ALWAYS_SENSITIVE)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_LABEL)
			{
				PrintTextValue(pBuffer, ckAttr.ulValueLen);
			}
			else if(ckAttr.type == CKA_APPLICATION)
			{
				PrintTextValue(pBuffer, ckAttr.ulValueLen);
			}
			else if(ckAttr.type == CKA_START_DATE)
			{
				PrintDateValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_END_DATE)
			{
				PrintDateValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_VALUE)
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == CKA_VALUE_LEN)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_SUBJECT)
			{
				PrintDNValue(ckAttr.pValue, ckAttr.ulValueLen);
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == CKA_ISSUER)
			{
				PrintDNValue(ckAttr.pValue, ckAttr.ulValueLen);
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == CKA_ID)
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == CKA_SERIAL_NUMBER)
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == CKA_CERTIFICATE_TYPE)
			{
				PrintCertiFicateType(ckUlong);
			}
			else if(ckAttr.type == CKA_OBJECT_ID)
			{
				PrintOIDValue(ckAttr.pValue, ckAttr.ulValueLen);
			}
			else if(ckAttr.type == CKA_KEY_TYPE)
			{
				PrintKeyType(ckUlong);
			}
			else if(ckAttr.type == CKA_MODULUS)
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == CKA_MODULUS_BITS)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_PUBLIC_EXPONENT)
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == CKA_PRIVATE_EXPONENT)
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == CKA_GOSTR3410_PARAMS)
			{
				PrintOIDValue(ckAttr.pValue, ckAttr.ulValueLen);
			}
			else if(ckAttr.type == CKA_GOSTR3411_PARAMS)
			{
				PrintOIDValue(ckAttr.pValue, ckAttr.ulValueLen);
			}
			else if(ckAttr.type == CKA_GOST28147_PARAMS)
			{
				PrintOIDValue(ckAttr.pValue, ckAttr.ulValueLen);
			}
			else if(ckAttr.type == CKA_TRUSTED)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_URL)
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == CKA_HASH_OF_SUBJECT_PUBLIC_KEY)
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == CKA_HASH_OF_ISSUER_PUBLIC_KEY)
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == CKA_CHECK_VALUE)
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == CKA_ENCRYPT)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_DECRYPT)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_WRAP)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_UNWRAP)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_SIGN)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_SIGN_RECOVER)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_VERIFY)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_VERIFY_RECOVER)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_DERIVE)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_KEY_GEN_MECHANISM)
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == CKA_ALWAYS_AUTHENTICATE)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_WRAP_WITH_TRUSTED)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_CERTIFICATE_CATEGORY)
			{
				PrintCertificateCategory(ckUlong);
			}
			else if(ckAttr.type == CKA_JAVA_MIDP_SECURITY_DOMAIN)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_NAME_HASH_ALGORITHM)
			{
				PrintMechanismType(ckUlong);
			}
			else if(ckAttr.type == CKA_COPYABLE)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_RESET_ON_INIT)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_HAS_RESET)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_PIXEL_X)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_PIXEL_Y)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_RESOLUTION)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_CHAR_ROWS)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_CHAR_COLUMNS)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_COLOR)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_BITS_PER_PIXEL)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == CKA_CHAR_SETS)
			{
				PrintTextValue(pBuffer, ckAttr.ulValueLen);
			}
			else if(ckAttr.type == CKA_ENCODING_METHODS)
			{
				PrintTextValue(pBuffer, ckAttr.ulValueLen);
			}
			else if(ckAttr.type == CKA_MIME_TYPES)
			{
				PrintTextValue(pBuffer, ckAttr.ulValueLen);
			}
			else if(ckAttr.type == 0x80001101)
			{
				PrintTextValue(pBuffer, ckAttr.ulValueLen);
			}
			else if(ckAttr.type == 0x80001102)
			{
				PrintTextValue(pBuffer, ckAttr.ulValueLen);
			}
			else if(ckAttr.type == 0x80001104)
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == 0x80001106)
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == 0x80001107)
			{
				PrintDateValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001108)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001109)
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == 0x8000110a)
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == 0x8000110b)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x8000110c)
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == 0x8000110e)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001110)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001111)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001112)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001113)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x8000111b)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x8000111d)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x8000111e)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x8000111f)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001120)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001121)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001122)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001123)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001124)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001125)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001126)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001127)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001128)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001129)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x8000112a)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x8000112b)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x8000112c)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x8000112d)
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == 0x8000112e)
			{
				PrintTextValue(pBuffer, ckAttr.ulValueLen);
			}
			else if(ckAttr.type == 0x8000112f)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001130)
			{
				PrintBOOLValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001131)
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == 0x80001132)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001133)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001134)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001135)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001136)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001137)
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == 0x80001138)
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
			else if(ckAttr.type == CKA_MECHANISM_TYPE)
			{
				PrintMechanismType(ckUlong);
			}
			else if(ckAttr.type == 0x80001B02)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001B03)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001B04)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001B05)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001B06)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001B07)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001B08)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001B09)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001B0A)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001B0B)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001201)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001202)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001203)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001204)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001205)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001206)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001207)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001208)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001209)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x8000120a)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x8000120b)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x8000120c)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x8000120d)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x8000120e)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x8000120f)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001212)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else if(ckAttr.type == 0x80001401)
			{
				PrintULONGValue(pBuffer, cbBuffer);
			}
			else
			{
				PrintBLOBValue(ckAttr.pValue, ckAttr.ulValueLen, 16);
			}
		}
		else if(ckr == CKR_ATTRIBUTE_SENSITIVE)
		{
			printf("Sensitive\n");
		}
		else if(ckr == CKR_ATTRIBUTE_TYPE_INVALID)
		{
		}
		else if(ckr == CKR_ATTRIBUTE_VALUE_INVALID)
		{
		}
		else if(ckr == CKR_FUNCTION_FAILED)
		{
			//			printf("      Attrtibute %08X: invalid\n", nIndex);
		}
		else 
		{
			PrintError("C_GetAttributeValue", ckr);
		}
	}
}

void PrintMechanismType(CK_MECHANISM_TYPE ckMechType)
{	
	     if(ckMechType == CKM_RSA_PKCS_KEY_PAIR_GEN                        ) { printf("CKM_RSA_PKCS_KEY_PAIR_GEN      						 \n"); }
	else if(ckMechType == CKM_RSA_PKCS                   				   ) { printf("CKM_RSA_PKCS                   						 \n"); }
	else if(ckMechType == CKM_RSA_9796                   				   ) { printf("CKM_RSA_9796                   						 \n"); }
	else if(ckMechType == CKM_RSA_X_509                  				   ) { printf("CKM_RSA_X_509                  						 \n"); }
	else if(ckMechType == CKM_MD2_RSA_PKCS               				   ) { printf("CKM_MD2_RSA_PKCS               						 \n"); }
	else if(ckMechType == CKM_MD5_RSA_PKCS               				   ) { printf("CKM_MD5_RSA_PKCS               						 \n"); }
	else if(ckMechType == CKM_SHA1_RSA_PKCS              				   ) { printf("CKM_SHA1_RSA_PKCS              						 \n"); }
	else if(ckMechType == CKM_RIPEMD128_RSA_PKCS         				   ) { printf("CKM_RIPEMD128_RSA_PKCS         						 \n"); }
	else if(ckMechType == CKM_RIPEMD160_RSA_PKCS         				   ) { printf("CKM_RIPEMD160_RSA_PKCS         						 \n"); }
	else if(ckMechType == CKM_RSA_PKCS_OAEP              				   ) { printf("CKM_RSA_PKCS_OAEP              						 \n"); }
	else if(ckMechType == CKM_RSA_X9_31_KEY_PAIR_GEN     				   ) { printf("CKM_RSA_X9_31_KEY_PAIR_GEN     						 \n"); }
	else if(ckMechType == CKM_RSA_X9_31                  				   ) { printf("CKM_RSA_X9_31                  						 \n"); }
	else if(ckMechType == CKM_SHA1_RSA_X9_31             				   ) { printf("CKM_SHA1_RSA_X9_31             						 \n"); }
	else if(ckMechType == CKM_RSA_PKCS_PSS               				   ) { printf("CKM_RSA_PKCS_PSS               						 \n"); }
	else if(ckMechType == CKM_SHA1_RSA_PKCS_PSS          				   ) { printf("CKM_SHA1_RSA_PKCS_PSS          						 \n"); }
	else if(ckMechType == CKM_DSA_KEY_PAIR_GEN           				   ) { printf("CKM_DSA_KEY_PAIR_GEN           						 \n"); }
	else if(ckMechType == CKM_DSA                        				   ) { printf("CKM_DSA                        						 \n"); }
	else if(ckMechType == CKM_DSA_SHA1                   				   ) { printf("CKM_DSA_SHA1                   						 \n"); }
	else if(ckMechType == CKM_DH_PKCS_KEY_PAIR_GEN       				   ) { printf("CKM_DH_PKCS_KEY_PAIR_GEN       						 \n"); }
	else if(ckMechType == CKM_DH_PKCS_DERIVE             				   ) { printf("CKM_DH_PKCS_DERIVE             						 \n"); }
	else if(ckMechType == CKM_X9_42_DH_KEY_PAIR_GEN      				   ) { printf("CKM_X9_42_DH_KEY_PAIR_GEN      						 \n"); }
	else if(ckMechType == CKM_X9_42_DH_DERIVE            				   ) { printf("CKM_X9_42_DH_DERIVE            						 \n"); }
	else if(ckMechType == CKM_X9_42_DH_HYBRID_DERIVE     				   ) { printf("CKM_X9_42_DH_HYBRID_DERIVE     						 \n"); }
	else if(ckMechType == CKM_X9_42_MQV_DERIVE           				   ) { printf("CKM_X9_42_MQV_DERIVE           						 \n"); }
	else if(ckMechType == CKM_SHA256_RSA_PKCS            				   ) { printf("CKM_SHA256_RSA_PKCS            						 \n"); }
	else if(ckMechType == CKM_SHA384_RSA_PKCS            				   ) { printf("CKM_SHA384_RSA_PKCS            						 \n"); }
	else if(ckMechType == CKM_SHA512_RSA_PKCS            				   ) { printf("CKM_SHA512_RSA_PKCS            						 \n"); }
	else if(ckMechType == CKM_SHA256_RSA_PKCS_PSS        				   ) { printf("CKM_SHA256_RSA_PKCS_PSS        						 \n"); }
	else if(ckMechType == CKM_SHA384_RSA_PKCS_PSS        				   ) { printf("CKM_SHA384_RSA_PKCS_PSS        						 \n"); }
	else if(ckMechType == CKM_SHA512_RSA_PKCS_PSS        				   ) { printf("CKM_SHA512_RSA_PKCS_PSS        						 \n"); }
	else if(ckMechType == CKM_SHA224_RSA_PKCS            				   ) { printf("CKM_SHA224_RSA_PKCS            						 \n"); }
	else if(ckMechType == CKM_SHA224_RSA_PKCS_PSS        				   ) { printf("CKM_SHA224_RSA_PKCS_PSS        						 \n"); }
	else if(ckMechType == CKM_RC2_KEY_GEN                				   ) { printf("CKM_RC2_KEY_GEN                						 \n"); }
	else if(ckMechType == CKM_RC2_ECB                    				   ) { printf("CKM_RC2_ECB                    						 \n"); }
	else if(ckMechType == CKM_RC2_CBC                    				   ) { printf("CKM_RC2_CBC                    						 \n"); }
	else if(ckMechType == CKM_RC2_MAC                    				   ) { printf("CKM_RC2_MAC                    						 \n"); }
	else if(ckMechType == CKM_RC2_MAC_GENERAL            				   ) { printf("CKM_RC2_MAC_GENERAL            						 \n"); }
	else if(ckMechType == CKM_RC2_CBC_PAD                				   ) { printf("CKM_RC2_CBC_PAD                						 \n"); }
	else if(ckMechType == CKM_RC4_KEY_GEN                				   ) { printf("CKM_RC4_KEY_GEN                						 \n"); }
	else if(ckMechType == CKM_RC4                        				   ) { printf("CKM_RC4                        						 \n"); }
	else if(ckMechType == CKM_DES_KEY_GEN                				   ) { printf("CKM_DES_KEY_GEN                						 \n"); }
	else if(ckMechType == CKM_DES_ECB                    				   ) { printf("CKM_DES_ECB                    						 \n"); }
	else if(ckMechType == CKM_DES_CBC                    				   ) { printf("CKM_DES_CBC                    						 \n"); }
	else if(ckMechType == CKM_DES_MAC                    				   ) { printf("CKM_DES_MAC                    						 \n"); }
	else if(ckMechType == CKM_DES_MAC_GENERAL            				   ) { printf("CKM_DES_MAC_GENERAL            						 \n"); }
	else if(ckMechType == CKM_DES_CBC_PAD                				   ) { printf("CKM_DES_CBC_PAD                						 \n"); }
	else if(ckMechType == CKM_DES2_KEY_GEN               				   ) { printf("CKM_DES2_KEY_GEN               						 \n"); }
	else if(ckMechType == CKM_DES3_KEY_GEN               				   ) { printf("CKM_DES3_KEY_GEN               						 \n"); }
	else if(ckMechType == CKM_DES3_ECB                   				   ) { printf("CKM_DES3_ECB                   						 \n"); }
	else if(ckMechType == CKM_DES3_CBC                   				   ) { printf("CKM_DES3_CBC                   						 \n"); }
	else if(ckMechType == CKM_DES3_MAC                   				   ) { printf("CKM_DES3_MAC                   						 \n"); }
	else if(ckMechType == CKM_DES3_MAC_GENERAL           				   ) { printf("CKM_DES3_MAC_GENERAL           						 \n"); }
	else if(ckMechType == CKM_DES3_CBC_PAD               				   ) { printf("CKM_DES3_CBC_PAD               						 \n"); }
	else if(ckMechType == CKM_CDMF_KEY_GEN               				   ) { printf("CKM_CDMF_KEY_GEN               						 \n"); }
	else if(ckMechType == CKM_CDMF_ECB                   				   ) { printf("CKM_CDMF_ECB                   						 \n"); }
	else if(ckMechType == CKM_CDMF_CBC                   				   ) { printf("CKM_CDMF_CBC                   						 \n"); }
	else if(ckMechType == CKM_CDMF_MAC                   				   ) { printf("CKM_CDMF_MAC                   						 \n"); }
	else if(ckMechType == CKM_CDMF_MAC_GENERAL           				   ) { printf("CKM_CDMF_MAC_GENERAL           						 \n"); }
	else if(ckMechType == CKM_CDMF_CBC_PAD               				   ) { printf("CKM_CDMF_CBC_PAD               						 \n"); }
	else if(ckMechType == CKM_DES_OFB64                  				   ) { printf("CKM_DES_OFB64                  						 \n"); }
	else if(ckMechType == CKM_DES_OFB8                   				   ) { printf("CKM_DES_OFB8                   						 \n"); }
	else if(ckMechType == CKM_DES_CFB64                  				   ) { printf("CKM_DES_CFB64                  						 \n"); }
	else if(ckMechType == CKM_DES_CFB8                   				   ) { printf("CKM_DES_CFB8                   						 \n"); }
	else if(ckMechType == CKM_MD2                        				   ) { printf("CKM_MD2                        						 \n"); }
	else if(ckMechType == CKM_MD2_HMAC                   				   ) { printf("CKM_MD2_HMAC                   						 \n"); }
	else if(ckMechType == CKM_MD2_HMAC_GENERAL           				   ) { printf("CKM_MD2_HMAC_GENERAL           						 \n"); }
	else if(ckMechType == CKM_MD5                        				   ) { printf("CKM_MD5                        						 \n"); }
	else if(ckMechType == CKM_MD5_HMAC                   				   ) { printf("CKM_MD5_HMAC                   						 \n"); }
	else if(ckMechType == CKM_MD5_HMAC_GENERAL           				   ) { printf("CKM_MD5_HMAC_GENERAL           						 \n"); }
	else if(ckMechType == CKM_SHA_1                      				   ) { printf("CKM_SHA_1                      						 \n"); }
	else if(ckMechType == CKM_SHA_1_HMAC                 				   ) { printf("CKM_SHA_1_HMAC                 						 \n"); }
	else if(ckMechType == CKM_SHA_1_HMAC_GENERAL         				   ) { printf("CKM_SHA_1_HMAC_GENERAL         						 \n"); }
	else if(ckMechType == CKM_RIPEMD128                  				   ) { printf("CKM_RIPEMD128                  						 \n"); }
	else if(ckMechType == CKM_RIPEMD128_HMAC             				   ) { printf("CKM_RIPEMD128_HMAC             						 \n"); }
	else if(ckMechType == CKM_RIPEMD128_HMAC_GENERAL     				   ) { printf("CKM_RIPEMD128_HMAC_GENERAL     						 \n"); }
	else if(ckMechType == CKM_RIPEMD160                  				   ) { printf("CKM_RIPEMD160                  						 \n"); }
	else if(ckMechType == CKM_RIPEMD160_HMAC             				   ) { printf("CKM_RIPEMD160_HMAC             						 \n"); }
	else if(ckMechType == CKM_RIPEMD160_HMAC_GENERAL     				   ) { printf("CKM_RIPEMD160_HMAC_GENERAL     						 \n"); }
	else if(ckMechType == CKM_SHA256                     				   ) { printf("CKM_SHA256                     						 \n"); }
	else if(ckMechType == CKM_SHA256_HMAC                				   ) { printf("CKM_SHA256_HMAC                						 \n"); }
	else if(ckMechType == CKM_SHA256_HMAC_GENERAL        				   ) { printf("CKM_SHA256_HMAC_GENERAL        						 \n"); }
	else if(ckMechType == CKM_SHA224                     				   ) { printf("CKM_SHA224                     						 \n"); }
	else if(ckMechType == CKM_SHA224_HMAC                				   ) { printf("CKM_SHA224_HMAC                						 \n"); }
	else if(ckMechType == CKM_SHA224_HMAC_GENERAL        				   ) { printf("CKM_SHA224_HMAC_GENERAL        						 \n"); }
	else if(ckMechType == CKM_SHA384                     				   ) { printf("CKM_SHA384                     						 \n"); }
	else if(ckMechType == CKM_SHA384_HMAC                				   ) { printf("CKM_SHA384_HMAC                						 \n"); }
	else if(ckMechType == CKM_SHA384_HMAC_GENERAL        				   ) { printf("CKM_SHA384_HMAC_GENERAL        						 \n"); }
	else if(ckMechType == CKM_SHA512                     				   ) { printf("CKM_SHA512                     						 \n"); }
	else if(ckMechType == CKM_SHA512_HMAC                				   ) { printf("CKM_SHA512_HMAC                						 \n"); }
	else if(ckMechType == CKM_SHA512_HMAC_GENERAL        				   ) { printf("CKM_SHA512_HMAC_GENERAL        						 \n"); }
	else if(ckMechType == CKM_SECURID_KEY_GEN            				   ) { printf("CKM_SECURID_KEY_GEN            						 \n"); }
	else if(ckMechType == CKM_SECURID                    				   ) { printf("CKM_SECURID                    						 \n"); }
	else if(ckMechType == CKM_HOTP_KEY_GEN    							   ) { printf("CKM_HOTP_KEY_GEN    									 \n"); }
	else if(ckMechType == CKM_HOTP            							   ) { printf("CKM_HOTP            									 \n"); }
	else if(ckMechType == CKM_ACTI            							   ) { printf("CKM_ACTI            									 \n"); }
	else if(ckMechType == CKM_ACTI_KEY_GEN    							   ) { printf("CKM_ACTI_KEY_GEN    									 \n"); }
	else if(ckMechType == CKM_CAST_KEY_GEN               				   ) { printf("CKM_CAST_KEY_GEN               						 \n"); }
	else if(ckMechType == CKM_CAST_ECB                   				   ) { printf("CKM_CAST_ECB                   						 \n"); }
	else if(ckMechType == CKM_CAST_CBC                   				   ) { printf("CKM_CAST_CBC                   						 \n"); }
	else if(ckMechType == CKM_CAST_MAC                   				   ) { printf("CKM_CAST_MAC                   						 \n"); }
	else if(ckMechType == CKM_CAST_MAC_GENERAL           				   ) { printf("CKM_CAST_MAC_GENERAL           						 \n"); }
	else if(ckMechType == CKM_CAST_CBC_PAD               				   ) { printf("CKM_CAST_CBC_PAD               						 \n"); }
	else if(ckMechType == CKM_CAST3_KEY_GEN              				   ) { printf("CKM_CAST3_KEY_GEN              						 \n"); }
	else if(ckMechType == CKM_CAST3_ECB                  				   ) { printf("CKM_CAST3_ECB                  						 \n"); }
	else if(ckMechType == CKM_CAST3_CBC                  				   ) { printf("CKM_CAST3_CBC                  						 \n"); }
	else if(ckMechType == CKM_CAST3_MAC                  				   ) { printf("CKM_CAST3_MAC                  						 \n"); }
	else if(ckMechType == CKM_CAST3_MAC_GENERAL          				   ) { printf("CKM_CAST3_MAC_GENERAL          						 \n"); }
	else if(ckMechType == CKM_CAST3_CBC_PAD              				   ) { printf("CKM_CAST3_CBC_PAD              						 \n"); }
	else if(ckMechType == CKM_CAST5_KEY_GEN              				   ) { printf("CKM_CAST5_KEY_GEN              						 \n"); }
	else if(ckMechType == CKM_CAST128_KEY_GEN            				   ) { printf("CKM_CAST128_KEY_GEN            						 \n"); }
	else if(ckMechType == CKM_CAST5_ECB                  				   ) { printf("CKM_CAST5_ECB                  						 \n"); }
	else if(ckMechType == CKM_CAST128_ECB                				   ) { printf("CKM_CAST128_ECB                						 \n"); }
	else if(ckMechType == CKM_CAST5_CBC                  				   ) { printf("CKM_CAST5_CBC                  						 \n"); }
	else if(ckMechType == CKM_CAST128_CBC                				   ) { printf("CKM_CAST128_CBC                						 \n"); }
	else if(ckMechType == CKM_CAST5_MAC                  				   ) { printf("CKM_CAST5_MAC                  						 \n"); }
	else if(ckMechType == CKM_CAST128_MAC                				   ) { printf("CKM_CAST128_MAC                						 \n"); }
	else if(ckMechType == CKM_CAST5_MAC_GENERAL          				   ) { printf("CKM_CAST5_MAC_GENERAL          						 \n"); }
	else if(ckMechType == CKM_CAST128_MAC_GENERAL        				   ) { printf("CKM_CAST128_MAC_GENERAL        						 \n"); }
	else if(ckMechType == CKM_CAST5_CBC_PAD              				   ) { printf("CKM_CAST5_CBC_PAD              						 \n"); }
	else if(ckMechType == CKM_CAST128_CBC_PAD            				   ) { printf("CKM_CAST128_CBC_PAD            						 \n"); }
	else if(ckMechType == CKM_RC5_KEY_GEN                				   ) { printf("CKM_RC5_KEY_GEN                						 \n"); }
	else if(ckMechType == CKM_RC5_ECB                    				   ) { printf("CKM_RC5_ECB                    						 \n"); }
	else if(ckMechType == CKM_RC5_CBC                    				   ) { printf("CKM_RC5_CBC                    						 \n"); }
	else if(ckMechType == CKM_RC5_MAC                    				   ) { printf("CKM_RC5_MAC                    						 \n"); }
	else if(ckMechType == CKM_RC5_MAC_GENERAL            				   ) { printf("CKM_RC5_MAC_GENERAL            						 \n"); }
	else if(ckMechType == CKM_RC5_CBC_PAD                				   ) { printf("CKM_RC5_CBC_PAD                						 \n"); }
	else if(ckMechType == CKM_IDEA_KEY_GEN               				   ) { printf("CKM_IDEA_KEY_GEN               						 \n"); }
	else if(ckMechType == CKM_IDEA_ECB                   				   ) { printf("CKM_IDEA_ECB                   						 \n"); }
	else if(ckMechType == CKM_IDEA_CBC                   				   ) { printf("CKM_IDEA_CBC                   						 \n"); }
	else if(ckMechType == CKM_IDEA_MAC                   				   ) { printf("CKM_IDEA_MAC                   						 \n"); }
	else if(ckMechType == CKM_IDEA_MAC_GENERAL           				   ) { printf("CKM_IDEA_MAC_GENERAL           						 \n"); }
	else if(ckMechType == CKM_IDEA_CBC_PAD               				   ) { printf("CKM_IDEA_CBC_PAD               						 \n"); }
	else if(ckMechType == CKM_GENERIC_SECRET_KEY_GEN     				   ) { printf("CKM_GENERIC_SECRET_KEY_GEN     						 \n"); }
	else if(ckMechType == CKM_CONCATENATE_BASE_AND_KEY   				   ) { printf("CKM_CONCATENATE_BASE_AND_KEY   						 \n"); }
	else if(ckMechType == CKM_CONCATENATE_BASE_AND_DATA  				   ) { printf("CKM_CONCATENATE_BASE_AND_DATA  						 \n"); }
	else if(ckMechType == CKM_CONCATENATE_DATA_AND_BASE  				   ) { printf("CKM_CONCATENATE_DATA_AND_BASE  						 \n"); }
	else if(ckMechType == CKM_XOR_BASE_AND_DATA          				   ) { printf("CKM_XOR_BASE_AND_DATA          						 \n"); }
	else if(ckMechType == CKM_EXTRACT_KEY_FROM_KEY       				   ) { printf("CKM_EXTRACT_KEY_FROM_KEY       						 \n"); }
	else if(ckMechType == CKM_SSL3_PRE_MASTER_KEY_GEN    				   ) { printf("CKM_SSL3_PRE_MASTER_KEY_GEN    						 \n"); }
	else if(ckMechType == CKM_SSL3_MASTER_KEY_DERIVE     				   ) { printf("CKM_SSL3_MASTER_KEY_DERIVE     						 \n"); }
	else if(ckMechType == CKM_SSL3_KEY_AND_MAC_DERIVE    				   ) { printf("CKM_SSL3_KEY_AND_MAC_DERIVE    						 \n"); }
	else if(ckMechType == CKM_SSL3_MASTER_KEY_DERIVE_DH  				   ) { printf("CKM_SSL3_MASTER_KEY_DERIVE_DH  						 \n"); }
	else if(ckMechType == CKM_TLS_PRE_MASTER_KEY_GEN     				   ) { printf("CKM_TLS_PRE_MASTER_KEY_GEN     						 \n"); }
	else if(ckMechType == CKM_TLS_MASTER_KEY_DERIVE      				   ) { printf("CKM_TLS_MASTER_KEY_DERIVE      						 \n"); }
	else if(ckMechType == CKM_TLS_KEY_AND_MAC_DERIVE     				   ) { printf("CKM_TLS_KEY_AND_MAC_DERIVE     						 \n"); }
	else if(ckMechType == CKM_TLS_MASTER_KEY_DERIVE_DH   				   ) { printf("CKM_TLS_MASTER_KEY_DERIVE_DH   						 \n"); }
	else if(ckMechType == CKM_TLS_PRF                    				   ) { printf("CKM_TLS_PRF                    						 \n"); }
	else if(ckMechType == CKM_SSL3_MD5_MAC               				   ) { printf("CKM_SSL3_MD5_MAC               						 \n"); }
	else if(ckMechType == CKM_SSL3_SHA1_MAC              				   ) { printf("CKM_SSL3_SHA1_MAC              						 \n"); }
	else if(ckMechType == CKM_MD5_KEY_DERIVATION         				   ) { printf("CKM_MD5_KEY_DERIVATION         						 \n"); }
	else if(ckMechType == CKM_MD2_KEY_DERIVATION         				   ) { printf("CKM_MD2_KEY_DERIVATION         						 \n"); }
	else if(ckMechType == CKM_SHA1_KEY_DERIVATION        				   ) { printf("CKM_SHA1_KEY_DERIVATION        						 \n"); }
	else if(ckMechType == CKM_SHA224_KEY_DERIVATION      				   ) { printf("CKM_SHA224_KEY_DERIVATION      						 \n"); }
	else if(ckMechType == CKM_PBE_MD2_DES_CBC            				   ) { printf("CKM_PBE_MD2_DES_CBC            						 \n"); }
	else if(ckMechType == CKM_PBE_MD5_DES_CBC            				   ) { printf("CKM_PBE_MD5_DES_CBC            						 \n"); }
	else if(ckMechType == CKM_PBE_MD5_CAST_CBC           				   ) { printf("CKM_PBE_MD5_CAST_CBC           						 \n"); }
	else if(ckMechType == CKM_PBE_MD5_CAST3_CBC          				   ) { printf("CKM_PBE_MD5_CAST3_CBC          						 \n"); }
	else if(ckMechType == CKM_PBE_MD5_CAST5_CBC          				   ) { printf("CKM_PBE_MD5_CAST5_CBC          						 \n"); }
	else if(ckMechType == CKM_PBE_MD5_CAST128_CBC        				   ) { printf("CKM_PBE_MD5_CAST128_CBC        						 \n"); }
	else if(ckMechType == CKM_PBE_SHA1_CAST5_CBC         				   ) { printf("CKM_PBE_SHA1_CAST5_CBC         						 \n"); }
	else if(ckMechType == CKM_PBE_SHA1_CAST128_CBC       				   ) { printf("CKM_PBE_SHA1_CAST128_CBC       						 \n"); }
	else if(ckMechType == CKM_PBE_SHA1_RC4_128           				   ) { printf("CKM_PBE_SHA1_RC4_128           						 \n"); }
	else if(ckMechType == CKM_PBE_SHA1_RC4_40            				   ) { printf("CKM_PBE_SHA1_RC4_40            						 \n"); }
	else if(ckMechType == CKM_PBE_SHA1_DES3_EDE_CBC      				   ) { printf("CKM_PBE_SHA1_DES3_EDE_CBC      						 \n"); }
	else if(ckMechType == CKM_PBE_SHA1_DES2_EDE_CBC      				   ) { printf("CKM_PBE_SHA1_DES2_EDE_CBC      						 \n"); }
	else if(ckMechType == CKM_PBE_SHA1_RC2_128_CBC       				   ) { printf("CKM_PBE_SHA1_RC2_128_CBC       						 \n"); }
	else if(ckMechType == CKM_PBE_SHA1_RC2_40_CBC        				   ) { printf("CKM_PBE_SHA1_RC2_40_CBC        						 \n"); }
	else if(ckMechType == CKM_PKCS5_PBKD2                				   ) { printf("CKM_PKCS5_PBKD2                						 \n"); }
	else if(ckMechType == CKM_PBA_SHA1_WITH_SHA1_HMAC    				   ) { printf("CKM_PBA_SHA1_WITH_SHA1_HMAC    						 \n"); }
	else if(ckMechType == CKM_WTLS_PRE_MASTER_KEY_GEN         			   ) { printf("CKM_WTLS_PRE_MASTER_KEY_GEN         					 \n"); }
	else if(ckMechType == CKM_WTLS_MASTER_KEY_DERIVE          			   ) { printf("CKM_WTLS_MASTER_KEY_DERIVE          					 \n"); }
	else if(ckMechType == CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC   			   ) { printf("CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC   					 \n"); }
	else if(ckMechType == CKM_WTLS_PRF                        			   ) { printf("CKM_WTLS_PRF                        					 \n"); }
	else if(ckMechType == CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE  			   ) { printf("CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE  					 \n"); }
	else if(ckMechType == CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE  			   ) { printf("CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE  					 \n"); }
	else if(ckMechType == CKM_KEY_WRAP_LYNKS             				   ) { printf("CKM_KEY_WRAP_LYNKS             						 \n"); }
	else if(ckMechType == CKM_KEY_WRAP_SET_OAEP          				   ) { printf("CKM_KEY_WRAP_SET_OAEP          						 \n"); }
	else if(ckMechType == CKM_CMS_SIG                    				   ) { printf("CKM_CMS_SIG                    						 \n"); }
	else if(ckMechType == CKM_KIP_DERIVE	               				   ) { printf("CKM_KIP_DERIVE	               						 \n"); }
	else if(ckMechType == CKM_KIP_WRAP	               					   ) { printf("CKM_KIP_WRAP	               							 \n"); }
	else if(ckMechType == CKM_KIP_MAC					   				   ) { printf("CKM_KIP_MAC					   						 \n"); }
	else if(ckMechType == CKM_CAMELLIA_KEY_GEN           				   ) { printf("CKM_CAMELLIA_KEY_GEN           						 \n"); }
	else if(ckMechType == CKM_CAMELLIA_ECB               				   ) { printf("CKM_CAMELLIA_ECB               						 \n"); }
	else if(ckMechType == CKM_CAMELLIA_CBC               				   ) { printf("CKM_CAMELLIA_CBC               						 \n"); }
	else if(ckMechType == CKM_CAMELLIA_MAC               				   ) { printf("CKM_CAMELLIA_MAC               						 \n"); }
	else if(ckMechType == CKM_CAMELLIA_MAC_GENERAL       				   ) { printf("CKM_CAMELLIA_MAC_GENERAL       						 \n"); }
	else if(ckMechType == CKM_CAMELLIA_CBC_PAD           				   ) { printf("CKM_CAMELLIA_CBC_PAD           						 \n"); }
	else if(ckMechType == CKM_CAMELLIA_ECB_ENCRYPT_DATA  				   ) { printf("CKM_CAMELLIA_ECB_ENCRYPT_DATA  						 \n"); }
	else if(ckMechType == CKM_CAMELLIA_CBC_ENCRYPT_DATA  				   ) { printf("CKM_CAMELLIA_CBC_ENCRYPT_DATA  						 \n"); }
	else if(ckMechType == CKM_CAMELLIA_CTR               				   ) { printf("CKM_CAMELLIA_CTR               						 \n"); }
	else if(ckMechType == CKM_ARIA_KEY_GEN               				   ) { printf("CKM_ARIA_KEY_GEN               						 \n"); }
	else if(ckMechType == CKM_ARIA_ECB                   				   ) { printf("CKM_ARIA_ECB                   						 \n"); }
	else if(ckMechType == CKM_ARIA_CBC                   				   ) { printf("CKM_ARIA_CBC                   						 \n"); }
	else if(ckMechType == CKM_ARIA_MAC                   				   ) { printf("CKM_ARIA_MAC                   						 \n"); }
	else if(ckMechType == CKM_ARIA_MAC_GENERAL           				   ) { printf("CKM_ARIA_MAC_GENERAL           						 \n"); }
	else if(ckMechType == CKM_ARIA_CBC_PAD               				   ) { printf("CKM_ARIA_CBC_PAD               						 \n"); }
	else if(ckMechType == CKM_ARIA_ECB_ENCRYPT_DATA      				   ) { printf("CKM_ARIA_ECB_ENCRYPT_DATA      						 \n"); }
	else if(ckMechType == CKM_ARIA_CBC_ENCRYPT_DATA      				   ) { printf("CKM_ARIA_CBC_ENCRYPT_DATA      						 \n"); }
	else if(ckMechType == CKM_SKIPJACK_KEY_GEN           				   ) { printf("CKM_SKIPJACK_KEY_GEN           						 \n"); }
	else if(ckMechType == CKM_SKIPJACK_ECB64             				   ) { printf("CKM_SKIPJACK_ECB64             						 \n"); }
	else if(ckMechType == CKM_SKIPJACK_CBC64             				   ) { printf("CKM_SKIPJACK_CBC64             						 \n"); }
	else if(ckMechType == CKM_SKIPJACK_OFB64             				   ) { printf("CKM_SKIPJACK_OFB64             						 \n"); }
	else if(ckMechType == CKM_SKIPJACK_CFB64             				   ) { printf("CKM_SKIPJACK_CFB64             						 \n"); }
	else if(ckMechType == CKM_SKIPJACK_CFB32             				   ) { printf("CKM_SKIPJACK_CFB32             						 \n"); }
	else if(ckMechType == CKM_SKIPJACK_CFB16             				   ) { printf("CKM_SKIPJACK_CFB16             						 \n"); }
	else if(ckMechType == CKM_SKIPJACK_CFB8              				   ) { printf("CKM_SKIPJACK_CFB8              						 \n"); }
	else if(ckMechType == CKM_SKIPJACK_WRAP              				   ) { printf("CKM_SKIPJACK_WRAP              						 \n"); }
	else if(ckMechType == CKM_SKIPJACK_PRIVATE_WRAP      				   ) { printf("CKM_SKIPJACK_PRIVATE_WRAP      						 \n"); }
	else if(ckMechType == CKM_SKIPJACK_RELAYX            				   ) { printf("CKM_SKIPJACK_RELAYX            						 \n"); }
	else if(ckMechType == CKM_KEA_KEY_PAIR_GEN           				   ) { printf("CKM_KEA_KEY_PAIR_GEN           						 \n"); }
	else if(ckMechType == CKM_KEA_KEY_DERIVE             				   ) { printf("CKM_KEA_KEY_DERIVE             						 \n"); }
	else if(ckMechType == CKM_FORTEZZA_TIMESTAMP         				   ) { printf("CKM_FORTEZZA_TIMESTAMP         						 \n"); }
	else if(ckMechType == CKM_BATON_KEY_GEN              				   ) { printf("CKM_BATON_KEY_GEN              						 \n"); }
	else if(ckMechType == CKM_BATON_ECB128               				   ) { printf("CKM_BATON_ECB128               						 \n"); }
	else if(ckMechType == CKM_BATON_ECB96                				   ) { printf("CKM_BATON_ECB96                						 \n"); }
	else if(ckMechType == CKM_BATON_CBC128               				   ) { printf("CKM_BATON_CBC128               						 \n"); }
	else if(ckMechType == CKM_BATON_COUNTER              				   ) { printf("CKM_BATON_COUNTER              						 \n"); }
	else if(ckMechType == CKM_BATON_SHUFFLE              				   ) { printf("CKM_BATON_SHUFFLE              						 \n"); }
	else if(ckMechType == CKM_BATON_WRAP                 				   ) { printf("CKM_BATON_WRAP                 						 \n"); }
	else if(ckMechType == CKM_ECDSA_KEY_PAIR_GEN         				   ) { printf("CKM_ECDSA_KEY_PAIR_GEN         						 \n"); }
	else if(ckMechType == CKM_EC_KEY_PAIR_GEN            				   ) { printf("CKM_EC_KEY_PAIR_GEN            						 \n"); }
	else if(ckMechType == CKM_ECDSA                      				   ) { printf("CKM_ECDSA                      						 \n"); }
	else if(ckMechType == CKM_ECDSA_SHA1                 				   ) { printf("CKM_ECDSA_SHA1                 						 \n"); }
	else if(ckMechType == CKM_ECDH1_DERIVE               				   ) { printf("CKM_ECDH1_DERIVE               						 \n"); }
	else if(ckMechType == CKM_ECDH1_COFACTOR_DERIVE      				   ) { printf("CKM_ECDH1_COFACTOR_DERIVE      						 \n"); }
	else if(ckMechType == CKM_ECMQV_DERIVE               				   ) { printf("CKM_ECMQV_DERIVE               						 \n"); }
	else if(ckMechType == CKM_JUNIPER_KEY_GEN            				   ) { printf("CKM_JUNIPER_KEY_GEN            						 \n"); }
	else if(ckMechType == CKM_JUNIPER_ECB128             				   ) { printf("CKM_JUNIPER_ECB128             						 \n"); }
	else if(ckMechType == CKM_JUNIPER_CBC128             				   ) { printf("CKM_JUNIPER_CBC128             						 \n"); }
	else if(ckMechType == CKM_JUNIPER_COUNTER            				   ) { printf("CKM_JUNIPER_COUNTER            						 \n"); }
	else if(ckMechType == CKM_JUNIPER_SHUFFLE            				   ) { printf("CKM_JUNIPER_SHUFFLE            						 \n"); }
	else if(ckMechType == CKM_JUNIPER_WRAP               				   ) { printf("CKM_JUNIPER_WRAP               						 \n"); }
	else if(ckMechType == CKM_FASTHASH                   				   ) { printf("CKM_FASTHASH                   						 \n"); }
	else if(ckMechType == CKM_AES_KEY_GEN                				   ) { printf("CKM_AES_KEY_GEN                						 \n"); }
	else if(ckMechType == CKM_AES_ECB                    				   ) { printf("CKM_AES_ECB                    						 \n"); }
	else if(ckMechType == CKM_AES_CBC                    				   ) { printf("CKM_AES_CBC                    						 \n"); }
	else if(ckMechType == CKM_AES_MAC                    				   ) { printf("CKM_AES_MAC                    						 \n"); }
	else if(ckMechType == CKM_AES_MAC_GENERAL            				   ) { printf("CKM_AES_MAC_GENERAL            						 \n"); }
	else if(ckMechType == CKM_AES_CBC_PAD                				   ) { printf("CKM_AES_CBC_PAD                						 \n"); }
	else if(ckMechType == CKM_AES_CTR                    				   ) { printf("CKM_AES_CTR                    						 \n"); }
	else if(ckMechType == CKM_BLOWFISH_KEY_GEN           				   ) { printf("CKM_BLOWFISH_KEY_GEN           						 \n"); }
	else if(ckMechType == CKM_BLOWFISH_CBC               				   ) { printf("CKM_BLOWFISH_CBC               						 \n"); }
	else if(ckMechType == CKM_TWOFISH_KEY_GEN            				   ) { printf("CKM_TWOFISH_KEY_GEN            						 \n"); }
	else if(ckMechType == CKM_TWOFISH_CBC                				   ) { printf("CKM_TWOFISH_CBC                						 \n"); }
	else if(ckMechType == CKM_DES_ECB_ENCRYPT_DATA       				   ) { printf("CKM_DES_ECB_ENCRYPT_DATA       						 \n"); }
	else if(ckMechType == CKM_DES_CBC_ENCRYPT_DATA       				   ) { printf("CKM_DES_CBC_ENCRYPT_DATA       						 \n"); }
	else if(ckMechType == CKM_DES3_ECB_ENCRYPT_DATA      				   ) { printf("CKM_DES3_ECB_ENCRYPT_DATA      						 \n"); }
	else if(ckMechType == CKM_DES3_CBC_ENCRYPT_DATA      				   ) { printf("CKM_DES3_CBC_ENCRYPT_DATA      						 \n"); }
	else if(ckMechType == CKM_AES_ECB_ENCRYPT_DATA       				   ) { printf("CKM_AES_ECB_ENCRYPT_DATA       						 \n"); }
	else if(ckMechType == CKM_AES_CBC_ENCRYPT_DATA       				   ) { printf("CKM_AES_CBC_ENCRYPT_DATA       						 \n"); }
	else if(ckMechType == CKM_DSA_PARAMETER_GEN          				   ) { printf("CKM_DSA_PARAMETER_GEN          						 \n"); }
	else if(ckMechType == CKM_DH_PKCS_PARAMETER_GEN      				   ) { printf("CKM_DH_PKCS_PARAMETER_GEN      						 \n"); }
	else if(ckMechType == CKM_X9_42_DH_PARAMETER_GEN     				   ) { printf("CKM_X9_42_DH_PARAMETER_GEN     						 \n"); }
	else if(ckMechType == CKD_CPDIVERSIFY_KDF                 			   ) { printf("CKD_CPDIVERSIFY_KDF                 					 \n"); }
	else if(ckMechType == CKK_GOSTR3410       							   ) { printf("CKK_GOSTR3410       									 \n"); }
	else if(ckMechType == CKK_GOSTR3411       							   ) { printf("CKK_GOSTR3411       									 \n"); }
	else if(ckMechType == CKK_GOST28147       							   ) { printf("CKK_GOST28147       									 \n"); }
	else if(ckMechType == CKA_GOSTR3410_PARAMS                			   ) { printf("CKA_GOSTR3410_PARAMS                					 \n"); }
	else if(ckMechType == CKA_GOSTR3411_PARAMS                			   ) { printf("CKA_GOSTR3411_PARAMS                					 \n"); }
	else if(ckMechType == CKA_GOST28147_PARAMS                			   ) { printf("CKA_GOST28147_PARAMS                					 \n"); }
	else if(ckMechType == CKM_GOSTR3410_KEY_PAIR_GEN          			   ) { printf("CKM_GOSTR3410_KEY_PAIR_GEN          					 \n"); }
	else if(ckMechType == CKM_GOSTR3410                       			   ) { printf("CKM_GOSTR3410                       					 \n"); }
	else if(ckMechType == CKM_GOSTR3410_WITH_GOSTR3411        			   ) { printf("CKM_GOSTR3410_WITH_GOSTR3411        					 \n"); }
	else if(ckMechType == CKM_GOSTR3410_KEY_WRAP              			   ) { printf("CKM_GOSTR3410_KEY_WRAP              					 \n"); }
	else if(ckMechType == CKM_GOSTR3410_DERIVE                			   ) { printf("CKM_GOSTR3410_DERIVE                					 \n"); }
	else if(ckMechType == CKM_GOSTR3411                       			   ) { printf("CKM_GOSTR3411                       					 \n"); }
	else if(ckMechType == CKM_GOSTR3411_HMAC                  			   ) { printf("CKM_GOSTR3411_HMAC                  					 \n"); }
	else if(ckMechType == CKM_GOST28147_KEY_GEN               			   ) { printf("CKM_GOST28147_KEY_GEN               					 \n"); }
	else if(ckMechType == CKM_GOST28147_ECB                   			   ) { printf("CKM_GOST28147_ECB                   					 \n"); }
	else if(ckMechType == CKM_GOST28147                       			   ) { printf("CKM_GOST28147                       					 \n"); }
	else if(ckMechType == CKM_GOST28147_MAC                   			   ) { printf("CKM_GOST28147_MAC                   					 \n"); }
	else if(ckMechType == CKM_GOST28147_KEY_WRAP              			   ) { printf("CKM_GOST28147_KEY_WRAP              					 \n"); }
	else if(ckMechType == CKD_GOST_KDF   								   ) { printf("CKD_GOST_KDF   										 \n"); }
	else if(ckMechType == CKD_TK26_CPDIVERSIFY_KDF						   ) { printf("CKD_TK26_CPDIVERSIFY_KDF								 \n"); }
	else if(ckMechType == CKA_TK26_GOSTR3410_PARAMS   					   ) { printf("CKA_TK26_GOSTR3410_PARAMS   							 \n"); }
	else if(ckMechType == CKA_TK26_GOSTR3411_PARAMS   					   ) { printf("CKA_TK26_GOSTR3411_PARAMS   							 \n"); }
	else if(ckMechType == CKA_TK26_GOST28147_PARAMS   					   ) { printf("CKA_TK26_GOST28147_PARAMS   							 \n"); }
	else if(ckMechType == CKM_TK26_GOSTR341094_KEY_PAIR_GEN   			   ) { printf("CKM_TK26_GOSTR341094_KEY_PAIR_GEN   					 \n"); }
	else if(ckMechType == CKM_TK26_GOSTR341094                			   ) { printf("CKM_TK26_GOSTR341094                					 \n"); }
	else if(ckMechType == CKM_TK26_GOSTR341094_WITH_GOSTR3411 			   ) { printf("CKM_TK26_GOSTR341094_WITH_GOSTR3411 					 \n"); }
	else if(ckMechType == CKM_TK26_GOSTR341094_KEY_WRAP       			   ) { printf("CKM_TK26_GOSTR341094_KEY_WRAP       					 \n"); }
	else if(ckMechType == CKK_TK26_GOSTR341094   						   ) { printf("CKK_TK26_GOSTR341094   								 \n"); }
	else if(ckMechType == CKK_TK26_GOSTR3410     						   ) { printf("CKK_TK26_GOSTR3410     								 \n"); }
	else if(ckMechType == CKK_TK26_GOSTR3411     						   ) { printf("CKK_TK26_GOSTR3411     								 \n"); }
	else if(ckMechType == CKK_TK26_GOST28147     						   ) { printf("CKK_TK26_GOST28147     								 \n"); }
	else if(ckMechType == CKM_TK26_GOSTR3410_KEY_PAIR_GEN 				   ) { printf("CKM_TK26_GOSTR3410_KEY_PAIR_GEN 						 \n"); }
	else if(ckMechType == CKM_TK26_GOSTR3410              				   ) { printf("CKM_TK26_GOSTR3410              						 \n"); }
	else if(ckMechType == CKM_TK26_GOSTR3410_WITH_GOSTR3411 			   ) { printf("CKM_TK26_GOSTR3410_WITH_GOSTR3411 					 \n"); }
	else if(ckMechType == CKM_TK26_GOSTR3410_DERIVE       				   ) { printf("CKM_TK26_GOSTR3410_DERIVE       						 \n"); }
	else if(ckMechType == CKM_TK26_GOSTR3410_KEY_WRAP     				   ) { printf("CKM_TK26_GOSTR3410_KEY_WRAP     						 \n"); }
	else if(ckMechType == CKM_TK26_GOSTR3411              				   ) { printf("CKM_TK26_GOSTR3411              						 \n"); }
	else if(ckMechType == CKM_TK26_GOSTR3411_HMAC         				   ) { printf("CKM_TK26_GOSTR3411_HMAC         						 \n"); }
	else if(ckMechType == CKM_TK26_GOST28147_KEY_GEN      				   ) { printf("CKM_TK26_GOST28147_KEY_GEN      						 \n"); }
	else if(ckMechType == CKM_TK26_GOST28147_ECB          				   ) { printf("CKM_TK26_GOST28147_ECB          						 \n"); }
	else if(ckMechType == CKM_TK26_GOST28147              				   ) { printf("CKM_TK26_GOST28147              						 \n"); }
	else if(ckMechType == CKM_TK26_GOST28147_MAC          				   ) { printf("CKM_TK26_GOST28147_MAC          						 \n"); }
	else if(ckMechType == CKM_TK26_GOST28147_KEY_WRAP     				   ) { printf("CKM_TK26_GOST28147_KEY_WRAP     						 \n"); }
	else if(ckMechType == CKM_PBA_GOSTR3411_WITH_GOSTR3411_HMAC_CRYPTOPRO  ) { printf("CKM_PBA_GOSTR3411_WITH_GOSTR3411_HMAC_CRYPTOPRO 		 \n"); }
	else if(ckMechType == CKM_PBA_GOSTR3411_WITH_GOSTR3411_HMAC 		   ) { printf("CKM_PBA_GOSTR3411_WITH_GOSTR3411_HMAC 				 \n"); }
	else if(ckMechType == CKM_TLS_GOST_MASTER_KEY_DERIVE         		   ) { printf("CKM_TLS_GOST_MASTER_KEY_DERIVE         				 \n"); }
	else if(ckMechType == CKM_TLS_GOST_KEY_AND_MAC_DERIVE        		   ) { printf("CKM_TLS_GOST_KEY_AND_MAC_DERIVE        				 \n"); }
	else if(ckMechType == CKM_TLS_GOST_PRF                       		   ) { printf("CKM_TLS_GOST_PRF                       				 \n"); }
	else if(ckMechType == CKM_TLS_GOST_PRE_MASTER_KEY_GEN        		   ) { printf("CKM_TLS_GOST_PRE_MASTER_KEY_GEN        				 \n"); }
	else if(ckMechType == CKM_UEK_DERIVE        						   ) { printf("CKM_UEK_DERIVE        								 \n"); }
	else if(ckMechType == CKM_NETSCAPE_PBE_SHA1_DES_CBC          		   ) { printf("CKM_NETSCAPE_PBE_SHA1_DES_CBC          				 \n"); }
	else if(ckMechType == CKM_NETSCAPE_PBE_SHA1_TRIPLE_DES_CBC   		   ) { printf("CKM_NETSCAPE_PBE_SHA1_TRIPLE_DES_CBC   				 \n"); }
	else if(ckMechType == CKM_NETSCAPE_PBE_SHA1_40_BIT_RC2_CBC   		   ) { printf("CKM_NETSCAPE_PBE_SHA1_40_BIT_RC2_CBC   				 \n"); }
	else if(ckMechType == CKM_NETSCAPE_PBE_SHA1_128_BIT_RC2_CBC  		   ) { printf("CKM_NETSCAPE_PBE_SHA1_128_BIT_RC2_CBC  				 \n"); }
	else if(ckMechType == CKM_NETSCAPE_PBE_SHA1_40_BIT_RC4       		   ) { printf("CKM_NETSCAPE_PBE_SHA1_40_BIT_RC4       				 \n"); }
	else if(ckMechType == CKM_NETSCAPE_PBE_SHA1_128_BIT_RC4      		   ) { printf("CKM_NETSCAPE_PBE_SHA1_128_BIT_RC4      				 \n"); }
	else if(ckMechType == CKM_NETSCAPE_PBE_SHA1_FAULTY_3DES_CBC  		   ) { printf("CKM_NETSCAPE_PBE_SHA1_FAULTY_3DES_CBC  				 \n"); }
	else if(ckMechType == CKM_NETSCAPE_PBE_SHA1_HMAC_KEY_GEN     		   ) { printf("CKM_NETSCAPE_PBE_SHA1_HMAC_KEY_GEN     				 \n"); }
	else if(ckMechType == CKM_NETSCAPE_PBE_MD5_HMAC_KEY_GEN      		   ) { printf("CKM_NETSCAPE_PBE_MD5_HMAC_KEY_GEN      				 \n"); }
	else if(ckMechType == CKM_NETSCAPE_PBE_MD2_HMAC_KEY_GEN      		   ) { printf("CKM_NETSCAPE_PBE_MD2_HMAC_KEY_GEN      				 \n"); }
	else if(ckMechType == CKM_TLS_PRF_GENERAL                    		   ) { printf("CKM_TLS_PRF_GENERAL                                   \n"); }
	else if(ckMechType == CKM_SHA256_RSA_PKCS                              ) { printf("CKM_SHA256_RSA_PKCS                                   \n"); }
	else if(ckMechType == CKM_SHA384_RSA_PKCS            				   ) { printf("CKM_SHA384_RSA_PKCS            						 \n"); }
	else if(ckMechType == CKM_SHA512_RSA_PKCS            				   ) { printf("CKM_SHA512_RSA_PKCS            						 \n"); }
	else if(ckMechType == CKM_SHA256_RSA_PKCS_PSS        				   ) { printf("CKM_SHA256_RSA_PKCS_PSS        						 \n"); }
	else if(ckMechType == CKM_SHA384_RSA_PKCS_PSS        				   ) { printf("CKM_SHA384_RSA_PKCS_PSS        						 \n"); }
	else if(ckMechType == CKM_SHA512_RSA_PKCS_PSS        				   ) { printf("CKM_SHA512_RSA_PKCS_PSS        						 \n"); }
	else if(ckMechType == CKM_SHA224_RSA_PKCS            				   ) { printf("CKM_SHA224_RSA_PKCS            						 \n"); }
	else if(ckMechType == CKM_SHA224_RSA_PKCS_PSS        				   ) { printf("CKM_SHA224_RSA_PKCS_PSS        						 \n"); }
	else if(ckMechType == CKM_SHA_1                      				   ) { printf("CKM_SHA_1                      						 \n"); }
	else if(ckMechType == CKM_SHA_1_HMAC                 				   ) { printf("CKM_SHA_1_HMAC                 						 \n"); }
	else if(ckMechType == CKM_SHA_1_HMAC_GENERAL         				   ) { printf("CKM_SHA_1_HMAC_GENERAL         						 \n"); }
	else if(ckMechType == CKM_SHA256                     				   ) { printf("CKM_SHA256                     						 \n"); }
	else if(ckMechType == CKM_SHA256_HMAC                				   ) { printf("CKM_SHA256_HMAC                						 \n"); }
	else if(ckMechType == CKM_SHA256_HMAC_GENERAL        				   ) { printf("CKM_SHA256_HMAC_GENERAL        						 \n"); }
	else if(ckMechType == CKM_SHA224                     				   ) { printf("CKM_SHA224                     						 \n"); }
	else if(ckMechType == CKM_SHA224_HMAC                				   ) { printf("CKM_SHA224_HMAC                						 \n"); }
	else if(ckMechType == CKM_SHA224_HMAC_GENERAL        				   ) { printf("CKM_SHA224_HMAC_GENERAL        						 \n"); }
	else if(ckMechType == CKM_SHA384                     				   ) { printf("CKM_SHA384                     						 \n"); }
	else if(ckMechType == CKM_SHA384_HMAC                				   ) { printf("CKM_SHA384_HMAC                						 \n"); }
	else if(ckMechType == CKM_SHA384_HMAC_GENERAL        				   ) { printf("CKM_SHA384_HMAC_GENERAL        						 \n"); }
	else if(ckMechType == CKM_SHA512                     				   ) { printf("CKM_SHA512                     						 \n"); }
	else if(ckMechType == CKM_SHA512_HMAC                				   ) { printf("CKM_SHA512_HMAC                						 \n"); }
	else if(ckMechType == CKM_SHA512_HMAC_GENERAL        				   ) { printf("CKM_SHA512_HMAC_GENERAL        						 \n"); }
	else if(ckMechType == CKM_SHA256_KEY_DERIVATION      				   ) { printf("CKM_SHA256_KEY_DERIVATION      						 \n"); }
	else if(ckMechType == CKM_SHA384_KEY_DERIVATION      				   ) { printf("CKM_SHA384_KEY_DERIVATION      						 \n"); }
	else if(ckMechType == CKM_SHA512_KEY_DERIVATION      				   ) { printf("CKM_SHA512_KEY_DERIVATION      						 \n"); }
	else if(ckMechType == CKM_SHA224_KEY_DERIVATION      				   ) { printf("CKM_SHA224_KEY_DERIVATION      						 \n"); }

	else if(ckMechType == 0x80006001                                       ) { printf("ETCKM_PBA_LEGACY                                      \n"); }

	else
	{
		printf("%08X\n", ckMechType);
	}
}

void PrintObjectsInfo(CK_SLOT_ID ckSlot, char* szPin)
{
	CK_OBJECT_HANDLE hGlobalObjects[OBJECTS_COUNT];
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hObjects[OBJECT_COUNT];
	CK_ULONG nObjectsCount, nObjectsIndex, nGlobalObjects;

	CK_BBOOL bLogin = CK_FALSE;
	CK_OBJECT_CLASS cko = CKO_DATA;
	CK_HW_FEATURE_TYPE pae = 0x80005002;
	CK_ATTRIBUTE ckattr[] = {
		{CKA_CLASS, &cko, sizeof(cko)},
		{CKA_HW_FEATURE_TYPE, &pae, sizeof(pae)}
	};

	CK_OBJECT_HANDLE hObject;

	nGlobalObjects = 0;

	if(CKR_OK == pFunctionList->C_OpenSession(ckSlot, CKF_SERIAL_SESSION, NULL, NULL, &hSession))
	{
		if(szPin && strlen(szPin) > 0)
		{
			if(CKR_OK == pFunctionList->C_Login(hSession, CKU_USER, szPin, (CK_ULONG)strlen(szPin)))
			{
				printf("\nLogin Successful\n");
				bLogin = CK_TRUE;
			}
			else
			{
				printf("\nLogin failed\n");
			}
		}

		cko = CKO_DATA;

		if(CKR_OK == pFunctionList->C_FindObjectsInit(hSession, ckattr, 1))
		{
			nObjectsCount = OBJECT_COUNT;

			if(CKR_OK == pFunctionList->C_FindObjects(hSession, hObjects, nObjectsCount, &nObjectsCount))
			{
				printf("\n       CKO_DATA Object count: %d\n", nObjectsCount);

				if(nObjectsCount > 0)
				{
					for(nObjectsIndex = 0; nObjectsIndex < nObjectsCount; nObjectsIndex++)
					{
						hObject = hObjects[nObjectsIndex];

						if(ObjectFind(hGlobalObjects, nGlobalObjects, hObject))
						{
							printf("\nObject %12d [%08X]: Duplicate\n", hObject, hObject);
						}
						else
						{
							printf("\nObject %12d [%08X]:\n", hObject, hObject);

							PrintObjectInfo(hSession, hObject, 0, 0x0800);

							hGlobalObjects[nGlobalObjects++] = hObject;
						}
					}
				}
			}

			pFunctionList->C_FindObjectsFinal(hSession);
		}

		cko = CKO_CERTIFICATE;

		if(CKR_OK == pFunctionList->C_FindObjectsInit(hSession, ckattr, 1))
		{
			nObjectsCount = OBJECT_COUNT;

			if(CKR_OK == pFunctionList->C_FindObjects(hSession, hObjects, nObjectsCount, &nObjectsCount))
			{
				printf("\nCKO_CERTIFICATE Object count: %d\n", nObjectsCount);

				if(nObjectsCount > 0)
				{
					for(nObjectsIndex = 0; nObjectsIndex < nObjectsCount; nObjectsIndex++)
					{
						hObject = hObjects[nObjectsIndex];

						if(ObjectFind(hGlobalObjects, nGlobalObjects, hObject))
						{
							printf("\nObject %12d [%08X]: Duplicate\n", hObject, hObject);
						}
						else
						{
							printf("\nObject %12d [%08X]:\n", hObject, hObject);

							PrintObjectInfo(hSession, hObject, 0, 0x0800);

							hGlobalObjects[nGlobalObjects++] = hObject;
						}
					}
				}
			}

			pFunctionList->C_FindObjectsFinal(hSession);
		}

		cko = CKO_SECRET_KEY;

		if(CKR_OK == pFunctionList->C_FindObjectsInit(hSession, ckattr, 1))
		{
			nObjectsCount = OBJECT_COUNT;
			if(CKR_OK == pFunctionList->C_FindObjects(hSession, hObjects, nObjectsCount, &nObjectsCount))
			{
				printf("\n CKO_SECRET_KEY Object count: %d\n", nObjectsCount);

				if(nObjectsCount > 0)
				{
					for(nObjectsIndex = 0; nObjectsIndex < nObjectsCount; nObjectsIndex++)
					{
						hObject = hObjects[nObjectsIndex];

						if(ObjectFind(hGlobalObjects, nGlobalObjects, hObject))
						{
							printf("\nObject %12d [%08X]: Duplicate\n", hObject, hObject);
						}
						else
						{
							printf("\nObject %12d [%08X]:\n", hObject, hObject);

							PrintObjectInfo(hSession, hObject, 0, 0x0800);

							hGlobalObjects[nGlobalObjects++] = hObject;
						}
					}
				}
			}

			pFunctionList->C_FindObjectsFinal(hSession);
		}

		cko = CKO_PUBLIC_KEY;

		if(CKR_OK == pFunctionList->C_FindObjectsInit(hSession, ckattr, 1))
		{
			nObjectsCount = OBJECT_COUNT;

			if(CKR_OK == pFunctionList->C_FindObjects(hSession, hObjects, nObjectsCount, &nObjectsCount))
			{
				printf("\n CKO_PUBLIC_KEY Object count: %d\n", nObjectsCount);

				if(nObjectsCount > 0)
				{
					for(nObjectsIndex = 0; nObjectsIndex < nObjectsCount; nObjectsIndex++)
					{
						hObject = hObjects[nObjectsIndex];

						if(ObjectFind(hGlobalObjects, nGlobalObjects, hObject))
						{
							printf("\nObject %12d [%08X]: Duplicate\n", hObject, hObject);
						}
						else
						{
							printf("\nObject %12d [%08X]:\n", hObject, hObject);

							PrintObjectInfo(hSession, hObject, 0, 0x0800);
							PrintObjectInfo(hSession, hObject, 0x80000000, 0x80010000);

							hGlobalObjects[nGlobalObjects++] = hObject;
						}
					}
				}
			}

			pFunctionList->C_FindObjectsFinal(hSession);
		}

		cko = CKO_PRIVATE_KEY;

		if(CKR_OK == pFunctionList->C_FindObjectsInit(hSession, ckattr, 1))
		{
			nObjectsCount = OBJECT_COUNT;

			if(CKR_OK == pFunctionList->C_FindObjects(hSession, hObjects, nObjectsCount, &nObjectsCount))
			{
				printf("\nCKO_PRIVATE_KEY Object count: %d\n", nObjectsCount);

				if(nObjectsCount > 0)
				{
					for(nObjectsIndex = 0; nObjectsIndex < nObjectsCount; nObjectsIndex++)
					{
						hObject = hObjects[nObjectsIndex];

						if(ObjectFind(hGlobalObjects, nGlobalObjects, hObject))
						{
							printf("\nObject %12d [%08X]: Duplicate\n", hObject, hObject);
						}
						else
						{
							printf("\nObject %12d [%08X]:\n", hObject, hObject);

							PrintObjectInfo(hSession, hObject, 0, 0x0800);
							PrintObjectInfo(hSession, hObject, 0x80000000, 0x80010000);

							hGlobalObjects[nGlobalObjects++] = hObject;
						}
					}
				}
			}

			pFunctionList->C_FindObjectsFinal(hSession);
		}

		cko = CKO_HW_FEATURE;

		if(CKR_OK == pFunctionList->C_FindObjectsInit(hSession, ckattr, 1))
		{
			nObjectsCount = OBJECT_COUNT;

			if(CKR_OK == pFunctionList->C_FindObjects(hSession, hObjects, nObjectsCount, &nObjectsCount))
			{
				printf("\n CKO_HW_FEATURE Object count: %d\n", nObjectsCount);

				if(nObjectsCount > 0)
				{
					for(nObjectsIndex = 0; nObjectsIndex < nObjectsCount; nObjectsIndex++)
					{
						hObject = hObjects[nObjectsIndex];

						if(ObjectFind(hGlobalObjects, nGlobalObjects, hObject))
						{
							printf("\nObject %12d [%08X]: Duplicate\n", hObject, hObject);
						}
						else
						{
							printf("\nObject %12d [%08X]:\n", hObject, hObject);

							PrintObjectInfo(hSession, hObject, 0, 0x10000);
							PrintObjectInfo(hSession, hObject, 0x80000000, 0x80010000);

							hGlobalObjects[nGlobalObjects++] = hObject;
						}
					}
				}
			}

			pFunctionList->C_FindObjectsFinal(hSession);
		}

		cko = CKO_MECHANISM;

		if(CKR_OK == pFunctionList->C_FindObjectsInit(hSession, ckattr, 1))
		{
			nObjectsCount = OBJECT_COUNT;

			if(CKR_OK == pFunctionList->C_FindObjects(hSession, hObjects, nObjectsCount, &nObjectsCount))
			{
				printf("\n  CKO_MECHANISM Object count: %d\n", nObjectsCount);

				if(nObjectsCount > 0)
				{
					for(nObjectsIndex = 0; nObjectsIndex < nObjectsCount; nObjectsIndex++)
					{
						hObject = hObjects[nObjectsIndex];

						if(ObjectFind(hGlobalObjects, nGlobalObjects, hObject))
						{
							printf("\nObject %12d [%08X]: Duplicate\n", hObject, hObject);
						}
						else
						{
							printf("\nObject %12d [%08X]:\n", hObject, hObject);

							PrintObjectInfo(hSession, hObject, 0, 0x1000);
							PrintObjectInfo(hSession, hObject, 0x80001000, 0x80002000);

							hGlobalObjects[nGlobalObjects++] = hObject;
						}
					}
				}
			}

			pFunctionList->C_FindObjectsFinal(hSession);
		}

		cko = CKO_DOMAIN_PARAMETERS;

		if(CKR_OK == pFunctionList->C_FindObjectsInit(hSession, ckattr, 1))
		{
			nObjectsCount = OBJECT_COUNT;

			if(CKR_OK == pFunctionList->C_FindObjects(hSession, hObjects, nObjectsCount, &nObjectsCount))
			{
				printf("\nCKO_DOMAIN_PARAMETERS Object count: %d\n", nObjectsCount);

				if(nObjectsCount > 0)
				{
					for(nObjectsIndex = 0; nObjectsIndex < nObjectsCount; nObjectsIndex++)
					{
						hObject = hObjects[nObjectsIndex];

						if(ObjectFind(hGlobalObjects, nGlobalObjects, hObject))
						{
							printf("\nObject %12d [%08X]: Duplicate\n", hObject, hObject);
						}
						else
						{
							printf("\nObject %12d [%08X]:\n", hObject, hObject);

							PrintObjectInfo(hSession, hObject, 0, 0x0800);

							hGlobalObjects[nGlobalObjects++] = hObject;
						}
					}
				}
			}

			pFunctionList->C_FindObjectsFinal(hSession);
		}

		if(CKR_OK == pFunctionList->C_FindObjectsInit(hSession, NULL, 0))
		{
			nObjectsCount = OBJECT_COUNT;

			if(CKR_OK == pFunctionList->C_FindObjects(hSession, hObjects, nObjectsCount, &nObjectsCount))
			{
				printf("\n          Other Object count: %d\n", nObjectsCount);

				for(nObjectsIndex = 0; nObjectsIndex < nObjectsCount; nObjectsIndex++)
				{
					hObject = hObjects[nObjectsIndex];

					if(ObjectFind(hGlobalObjects, nGlobalObjects, hObject))
					{
						printf("\nObject %12d [%08X]: Duplicate\n", hObject, hObject);
					}
					else
					{
						printf("\nObject %12d [%08X]:\n", hObject, hObject);

						PrintObjectInfo(hSession, hObject, 0, 0x1000);
						PrintObjectInfo(hSession, hObject, 0x80001000, 0x80003000);

						hGlobalObjects[nGlobalObjects++] = hObject;
					}
				}
			}

			pFunctionList->C_FindObjectsFinal(hSession);
		}

		printf("\nObjects Enum Finished\n");

		if(bLogin)
		{
			bLogin = CK_FALSE;

			if(CKR_OK == pFunctionList->C_Logout(hSession))
			{
				printf("\nLogout Successful\n");
			}
			else
			{
				printf("\nLogout failed\n");
			}
		}

		pFunctionList->C_CloseSession(hSession);
	}
}

void PrintTokenMechanism(CK_SLOT_ID ckSlot)
{
	CK_ULONG nMechIndex, nMechCount;
	CK_MECHANISM_TYPE ckMechTypes[128], ckMechType;
	CK_MECHANISM_INFO ckMechInfo;

	nMechCount = 0;
	if(CKR_OK == pFunctionList->C_GetMechanismList(ckSlot, NULL_PTR, &nMechCount))
	{
		nMechCount = min(nMechCount, 128);

		printf("\nMechanisms Count: %d\n", nMechCount);

		if(CKR_OK == pFunctionList->C_GetMechanismList(ckSlot, ckMechTypes, &nMechCount))
		{
			for(nMechIndex = 0; nMechIndex < nMechCount; nMechIndex++)
			{
				ckMechType = ckMechTypes[nMechIndex];
				if(CKR_OK == pFunctionList->C_GetMechanismInfo(ckSlot, ckMechType, &ckMechInfo))
				{
					printf("\nMechanism                 : ");

					PrintMechanismType(ckMechType);

					printf("KeySize                   : %d - %d\n", ckMechInfo.ulMinKeySize, ckMechInfo.ulMaxKeySize);
					printf("CKF_HW                    : %s\n", (ckMechInfo.flags & CKF_HW                 ) ? "Yes" : "No");
					printf("CKF_ENCRYPT               : %s\n", (ckMechInfo.flags & CKF_ENCRYPT            ) ? "Yes" : "No");
					printf("CKF_DECRYPT               : %s\n", (ckMechInfo.flags & CKF_DECRYPT            ) ? "Yes" : "No");
					printf("CKF_DIGEST                : %s\n", (ckMechInfo.flags & CKF_DIGEST             ) ? "Yes" : "No");
					printf("CKF_SIGN                  : %s\n", (ckMechInfo.flags & CKF_SIGN               ) ? "Yes" : "No");
					printf("CKF_SIGN_RECOVER          : %s\n", (ckMechInfo.flags & CKF_SIGN_RECOVER       ) ? "Yes" : "No");
					printf("CKF_VERIFY                : %s\n", (ckMechInfo.flags & CKF_VERIFY             ) ? "Yes" : "No");
					printf("CKF_VERIFY_RECOVER        : %s\n", (ckMechInfo.flags & CKF_VERIFY_RECOVER     ) ? "Yes" : "No");
					printf("CKF_GENERATE              : %s\n", (ckMechInfo.flags & CKF_GENERATE           ) ? "Yes" : "No");
					printf("CKF_GENERATE_KEY_PAIR     : %s\n", (ckMechInfo.flags & CKF_GENERATE_KEY_PAIR  ) ? "Yes" : "No");
					printf("CKF_WRAP                  : %s\n", (ckMechInfo.flags & CKF_WRAP               ) ? "Yes" : "No");
					printf("CKF_UNWRAP                : %s\n", (ckMechInfo.flags & CKF_UNWRAP             ) ? "Yes" : "No");
					printf("CKF_DERIVE                : %s\n", (ckMechInfo.flags & CKF_DERIVE             ) ? "Yes" : "No");
				}
			}
		}
	}
}

BOOL ObjectFind(CK_OBJECT_HANDLE_PTR hObjects, CK_ULONG nObjects, CK_OBJECT_HANDLE hObject)
{
	CK_ULONG nIndex;

	for(nIndex = 0; nIndex < nObjects; nIndex++)
	{
		if(hObjects[nIndex] == hObject)
			break;
	}

	return nIndex != nObjects;
}

int main(int argc, char *argv[])
{
	CK_RV rv;
	CK_INFO sInfo;
	CK_SLOT_ID_PTR slots = NULL;
	CK_ULONG slotIndex, slotCount;
	char *szPin;
	char *szLibrary;
	void *hLibrary;
	CK_BBOOL bInit;

	bInit = FALSE;
	szLibrary = "jcPkcs11-2.dll";
	szPin = NULL;

	if(argc > 1) szLibrary = argv[1];

	if(argc > 3) szPin = argv[3];

	hLibrary = LoadLibrary(szLibrary);

	if(hLibrary == NULL)
	{
		rv = GetLastError();
		PrintError("LoadLibrary", CKR_FUNCTION_FAILED);
		goto end;
	}

	printf("LoadLibrary      : '%s'\n", szLibrary);

	pGetFunctionList = (CK_C_GetFunctionList)GetProcAddress(hLibrary, "C_GetFunctionList");

	if(hLibrary == NULL)
	{
		PrintError("GetProcAddress", CKR_FUNCTION_FAILED);
		goto end;
	}

	printf("GetProcAddress   : ok\n");

	rv = pGetFunctionList(&pFunctionList);
	if(rv != CKR_OK)
	{
		PrintError("C_GetFunctionList", rv);
		goto end;
	}                       

	printf("C_GetFunctionList: ok\n");
	printf("FunctionList Version: %d.%d\n", pFunctionList->version.major, pFunctionList->version.minor);

	// инициализация библиотеки
	rv = pFunctionList->C_Initialize(0);
	if(rv != CKR_OK)
	{
		PrintError("C_Initialize", rv);
		goto end;
	}                       

	bInit = CK_TRUE;
	
	printf("C_Initialize     : ok\n");

	// получаем информацию о библиотеке
	rv = pFunctionList->C_GetInfo(&sInfo);
	if(rv != CKR_OK)
	{
		PrintError("C_GetInfo", rv);
		goto end;
	} 

	// выводим информацию о библиотеке
	PrintInfo(&sInfo);

	slotCount = 0;

	// получаем список слотов с поключенными токенами
	rv = pFunctionList->C_GetSlotList(CK_FALSE, NULL, &slotCount);
	if(rv != CKR_OK)
	{
		PrintError("C_GetSlotList", rv);
		goto end;
	}

	slots = (CK_SLOT_ID_PTR)malloc(sizeof(CK_SLOT_ID)*slotCount);

	rv = pFunctionList->C_GetSlotList(CK_FALSE, slots, &slotCount);
	if(rv != CKR_OK)
	{
		PrintError("C_GetSlotList", rv);
		goto end;
	}

	// таких слотов нет? 
	if(slotCount == 0)
	{
		printf("\nCards not found.\n");
		goto end;
	}

	for(slotIndex = 0; slotIndex < slotCount; slotIndex++)
	{
		CK_SLOT_ID slotID;
		CK_SLOT_INFO slotInfo;
		CK_TOKEN_INFO tokenInfo;

		slotID = slots[slotIndex];

		// получаем информации о слоте
		rv = pFunctionList->C_GetSlotInfo(slotID, &slotInfo);

		if(rv != CKR_OK)
		{
			PrintError("C_GetSlotInfo", rv);
			continue;
		} 

		if(argc < 3 || strncmp(argv[2], slotInfo.slotDescription, min(strlen(argv[2]), 64)) == 0)
		{
			// выводим информацию о выбраном слоте
			PrintSlotInfo(&slotInfo, slotIndex, slotID);

			if(slotInfo.flags & CKF_TOKEN_PRESENT)
			{
				// получить информацию о токене в слоте
				rv = pFunctionList->C_GetTokenInfo(slotID, &tokenInfo);

				if(rv != CKR_OK)
				{
					PrintError("C_GetTokenInfo", rv);
					continue;
				}

				// выводим информацию о токене 
				PrintTokenInfo(&tokenInfo);

// 				PrintTokenMechanism(slots[slotIndex]);

				PrintObjectsInfo(slotID, szPin);
			}
		}
	}

	end:

	if(slots != NULL) free(slots);

	// завершаем работу библиотеки
	if(bInit)
	{
		pFunctionList->C_Finalize(NULL);
	}

	if(hLibrary)
	{
		FreeLibrary(hLibrary);
	}

	return 0;
}

