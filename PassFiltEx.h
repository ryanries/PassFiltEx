// PassFiltEx.h
#pragma once

#ifdef _DEBUG
#define ASSERT(Expression) if (!Expression) { __ud2(); }
#else
#define ASSERT(Expression) ((void)0)
#endif

#define __FILENAMEW__ (wcsrchr(__FILEW__, L'\\') ? wcsrchr(__FILEW__, L'\\') + 1 : __FILEW__)
#define MAX_BLACKLIST_STRING_SIZE		32
#define BLACKLIST_THREAD_RUN_FREQUENCY	60000

// The registry subkey that this DLL loads configuration from.
#define FILTER_REG_SUBKEY L"SOFTWARE\\PassFiltEx"

// The name of the log file.
#define FILTER_LOG_FILE_NAME	L"PassFiltEx.log"
#define FILTER_VERSION_STRING	L"1.4.17"

// These are the names of the registry values.
#define FILTER_REG_DEBUG	L"Debug"
#define FILTER_REG_BLACKLIST_FILENAME L"BlacklistFileName"
#define FILTER_REG_TOKEN_PERCENTAGE_OF_PASSWORD L"TokenPercentageOfPassword"
#define TOKEN_PERCENTAGE_OF_PASSWORD_DEFAULT 60
#define FILTER_REG_REQUIRE_EITHER_LOWER_OR_UPPER L"RequireEitherLowerOrUpper"
#define FILTER_REG_MIN_LOWER L"MinLower"
#define FILTER_REG_MIN_UPPER L"MinUpper"
#define FILTER_REG_MIN_DIGIT L"MinDigit"
#define FILTER_REG_MIN_SPECIAL L"MinSpecial"
#define FILTER_REG_MIN_UNICODE L"MinUnicode"
#define FILTER_REG_BLOCK_SEQUENTIAL	L"BlockSequentialChars"
#define FILTER_REG_BLOCK_REPEATING	L"BlockRepeatingChars"

#define	ASCII_LOWERCASE_BEGIN	97
#define	ASCII_LOWERCASE_END		122
#define	ASCII_UPPERCASE_BEGIN	65
#define	ASCII_UPPERCASE_END		90
#define	ASCII_DIGITS_BEGIN		48
#define	ASCII_DIGITS_END		57

typedef struct BADSTRING
{
	wchar_t String[MAX_BLACKLIST_STRING_SIZE];
	struct BADSTRING* Next;
} BADSTRING;

// NOTE: LOG_DEBUG should always be first and the lowest value. Check LogMessageW for logic.
typedef enum LOG_LEVEL
{	
	LOG_DEBUG,
	LOG_ERROR
} LOG_LEVEL;

BOOL WINAPI DllMain(_In_ HINSTANCE DLLHandle, _In_ DWORD Reason, _In_ LPVOID Reserved);
__declspec(dllexport) BOOL CALLBACK InitializeChangeNotify(void);
__declspec(dllexport) NTSTATUS CALLBACK PasswordChangeNotify(_In_ PUNICODE_STRING UserName, _In_ ULONG RelativeId, _In_ PUNICODE_STRING NewPassword);
__declspec(dllexport) BOOL CALLBACK PasswordFilter(_In_ PUNICODE_STRING AccountName, _In_ PUNICODE_STRING FullName, _In_ PUNICODE_STRING Password, _In_ BOOL SetOperation);
DWORD WINAPI BlacklistThreadProc(_In_ LPVOID Args);
DWORD UpdateConfigurationFromRegistry(void);
void LogMessageW(_In_ LOG_LEVEL LogLevel, _In_ wchar_t* Message, _In_ ...);
