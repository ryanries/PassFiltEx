// Please read PassFiltEx.c for full commentary.

#pragma once


#define __FILENAMEW__ (wcsrchr(__FILEW__, L'\\') ? wcsrchr(__FILEW__, L'\\') + 1 : __FILEW__)

#define ETW_MAX_STRING_SIZE				2048

#define MAX_BLACKLIST_STRING_SIZE		32

#define BLACKLIST_THREAD_RUN_FREQUENCY	60000


// The registry subkey that this DLL loads configuration from.

#define FILTER_REG_SUBKEY L"SOFTWARE\\PassFiltEx"

// These are the names of the registry values.
#define FILTER_REG_BLACKLIST_FILENAME L"BlacklistFileName"
#define FILTER_REG_TOKEN_PERCENTAGE_OF_PASSWORD L"TokenPercentageOfPassword"
#define TOKEN_PERCENTAGE_OF_PASSWORD_DEFAULT 60
#define FILTER_REG_REQUIRE_EITHER_LOWER_OR_UPPER L"RequireEitherLowerOrUpper"
#define FILTER_REG_MIN_LOWER L"MinLower"
#define FILTER_REG_MIN_UPPER L"MinUpper"
#define FILTER_REG_MIN_DIGIT L"MinDigit"
#define FILTER_REG_MIN_SPECIAL L"MinSpecial"
#define FILTER_REG_MIN_UNICODE L"MinUnicode"

//#define CHARACTER_CLASS_LOWERCASE 1
//#define CHARACTER_CLASS_UPPERCASE 2
//#define CHARACTER_CLASS_DIGIT     4
//#define CHARACTER_CLASS_SPECIAL   8
//#define CHARACTER_CLASS_UNICODE   16
//#define CHARACTER_CLASS_EITHER_UPPER_OR_LOWER	32


typedef struct BADSTRING
{
	wchar_t String[MAX_BLACKLIST_STRING_SIZE];
	struct BADSTRING* Next;
} BADSTRING;


BOOL WINAPI DllMain(_In_ HINSTANCE DLLHandle, _In_ DWORD Reason, _In_ LPVOID Reserved);
__declspec(dllexport) BOOL CALLBACK InitializeChangeNotify(void);
__declspec(dllexport) NTSTATUS CALLBACK PasswordChangeNotify(_In_ PUNICODE_STRING UserName, _In_ ULONG RelativeId, _In_ PUNICODE_STRING NewPassword);
__declspec(dllexport) BOOL CALLBACK PasswordFilter(_In_ PUNICODE_STRING AccountName, _In_ PUNICODE_STRING FullName, _In_ PUNICODE_STRING Password, _In_ BOOL SetOperation);
ULONG EventWriteStringW2(_In_ PCWSTR String, _In_ ...);
DWORD WINAPI BlacklistThreadProc(_In_ LPVOID Args);
DWORD UpdateConfigurationFromRegistry(void);