// Please read PassFiltEx.c for full commentary.

#pragma once


// Disable warnings about adding padding bytes to structs.
#pragma warning(disable: 4820)

#define __FILENAMEW__ (wcsrchr(__FILEW__, L'\\') ? wcsrchr(__FILEW__, L'\\') + 1 : __FILEW__)

#define ETW_MAX_STRING_SIZE 2048

#define MAX_BLACKLIST_STRING_SIZE 128

#define BLACKLIST_THREAD_RUN_FREQUENCY 60000



// The registry subkey that this DLL loads configuration from.

#define FILTER_REG_SUBKEY L"SOFTWARE\\PassFiltEx"

// These are the names of the registry values.

#define FILTER_REG_BLACKLIST_FILENAME L"BlacklistFileName"

#define FILTER_REG_TOKEN_PERCENTAGE_OF_PASSWORD L"TokenPercentageOfPassword"


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