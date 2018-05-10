
#ifndef __info_h__
#define __info_h__

void PrintError(char* func, int retCode);
void PrintInfo(CK_INFO_PTR pInfo);
void PrintSlotInfo(CK_SLOT_INFO_PTR pInfo, CK_ULONG slotNumber, CK_SLOT_ID slotID);
void PrintTokenInfo(CK_TOKEN_INFO_PTR pInfo);

void PrintBOOLValue(CK_BYTE_PTR pValue, CK_ULONG nValue);
void PrintBLOBValue(CK_BYTE_PTR pValue, CK_ULONG nValue, CK_ULONG nRadix);
void PrintULONGValue(CK_BYTE_PTR pValue, CK_ULONG nValue);
void PrintTextValue(CK_BYTE_PTR pValue, CK_ULONG nValue);
void PrintDateValue(CK_BYTE_PTR pValue, CK_ULONG nValue);
void PrintOIDValue(CK_BYTE_PTR pValue, CK_ULONG nValue);
void PrintDNValue(CK_BYTE_PTR pValue, CK_ULONG nValue);

void PrintAttrributeName(CK_ATTRIBUTE_TYPE type, CK_RV ckr);
void PrintObjectClass(CK_OBJECT_CLASS ckUlong);
void PrintFeautureType(CK_HW_FEATURE_TYPE ckUlong);
void PrintMechanismType(CK_MECHANISM_TYPE ckMechType);
void PrintCertiFicateType(CK_ULONG ckUlong);
void PrintKeyType(CK_ULONG ckUlong);

void PrintObjectInfo(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, int nStart, int nFinish);
void PrintObjectsInfo(CK_SLOT_ID ckSlot, char* szPin);
void PrintTokenMechanism(CK_SLOT_ID ckSlot);

#define BUFF_SIZE		8192
#define OBJECT_COUNT	256
#define OBJECTS_COUNT	4096

BOOL ObjectFind(CK_OBJECT_HANDLE_PTR hObjects, CK_ULONG nObjects, CK_OBJECT_HANDLE hObject);

typedef CK_DATE CK_PTR CK_DATE_PTR;

#endif // __info_h__

