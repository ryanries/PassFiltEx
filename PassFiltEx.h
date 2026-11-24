// PassFiltEx.h
#ifdef _DEBUG
#define ASSERT(Expression) do { if (!(Expression)) { __debugbreak(); } } while (0)
#else
#define ASSERT(Expression) ((void)0)
#endif

#define __FILENAMEW__ (wcsrchr(__FILEW__, L'\\') ? wcsrchr(__FILEW__, L'\\') + 1 : __FILEW__)
#define MAX_BLOCKLIST_STRING_SIZE          32
#define BLOCKLIST_THREAD_RUN_FREQUENCY  60000

// The longest that PasswordFilter will wait for the blocklist thread to finish loading
// the configuration and the blocklist for the first time after the DLL is initialized.
#define INITIAL_LOAD_TIMEOUT_MS         10000

// The registry subkey that this DLL loads configuration from.
#define FILTER_REG_SUBKEY L"SOFTWARE\\PassFiltEx"

// The name of the log file.
#define FILTER_LOG_FILE_NAME	L"PassFiltEx.log"
// The log file contains user names and blocklisted strings found in rejected passwords,
// so only SYSTEM and Administrators are allowed to access it.
#define FILTER_LOG_FILE_SDDL	L"D:P(A;;FA;;;SY)(A;;FA;;;BA)"
// When the log file reaches this size in bytes, it is archived and a new log file is started.
#define FILTER_LOG_MAX_SIZE		(1024 * 1024)
#define FILTER_VERSION_STRING	L"1.6.3"

// The blocklist file that is used if the BlocklistFileName registry value does not exist or is blank.
#define FILTER_DEFAULT_BLOCKLIST_FILE_NAME	L"PassFiltExBlocklist.txt"

// These are the names of the registry values.
#define FILTER_REG_DEBUG													L"Debug"
#define FILTER_REG_BLOCKLIST_FILENAME							L"BlocklistFileName"
#define FILTER_REG_APPLY_TO_GROUPS								L"ApplyToTheseGroupsOnly"
#define FILTER_REG_TOKEN_PERCENTAGE_OF_PASSWORD		L"TokenPercentageOfPassword"
#define FILTER_REG_REQUIRE_EITHER_LOWER_OR_UPPER	L"RequireEitherLowerOrUpper"
#define FILTER_REG_MIN_LOWER											L"MinLower"
#define FILTER_REG_MIN_UPPER											L"MinUpper"
#define FILTER_REG_MIN_DIGIT											L"MinDigit"
#define FILTER_REG_MIN_SPECIAL										L"MinSpecial"
#define FILTER_REG_MIN_UNICODE										L"MinUnicode"
#define FILTER_REG_BLOCK_SEQUENTIAL								L"BlockSequentialChars"
#define FILTER_REG_BLOCK_REPEATING								L"BlockRepeatingChars"

#define	ASCII_LOWERCASE_BEGIN	 97
#define	ASCII_LOWERCASE_END		122
#define	ASCII_UPPERCASE_BEGIN	 65
#define	ASCII_UPPERCASE_END		 90
#define	ASCII_DIGITS_BEGIN		 48
#define	ASCII_DIGITS_END			 57

typedef struct BADSTRING
{
	wchar_t String[MAX_BLOCKLIST_STRING_SIZE];
	struct BADSTRING* Next;
} BADSTRING;

// All of the settings that are read from the registry.
typedef struct FILTER_CONFIG
{
	DWORD Debug;
	DWORD RequireEitherUpperOrLower;
	DWORD TokenPercentageOfPassword;
	DWORD MinLower;
	DWORD MinUpper;
	DWORD MinDigit;
	DWORD MinSpecial;
	DWORD MinUnicode;
	DWORD BlockSequential;
	DWORD BlockRepeating;
	wchar_t BlocklistFileName[256];
	// The group names from ApplyToTheseGroupsOnly, with any spaces around them removed. Each name is
	// null-terminated, and the list ends with an empty string. If the list is empty, all users are filtered.
	wchar_t ApplyToTheseGroups[1026];
} FILTER_CONFIG;

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
DWORD WINAPI BlocklistThreadProc(_In_ LPVOID Args);
void UpdateBlocklist(_In_z_ const wchar_t* FileName);
BOOL AddBlocklistLine(_In_z_ const wchar_t* Line, _In_ DWORD LineNumber, _In_z_ const wchar_t* FileName, _Inout_ BADSTRING** Head, _Inout_ BADSTRING** Tail, _Inout_ DWORD* EntryCount);
void FreeBlocklist(_In_opt_ BADSTRING* Head);
DWORD UpdateConfigurationFromRegistry(void);
void ParseGroupList(_In_z_ const wchar_t* GroupList, _Out_writes_(OutputCount) wchar_t* Output, _In_ size_t OutputCount);
BOOL ContainsString(_In_reads_(HaystackLength) const wchar_t* Haystack, _In_ size_t HaystackLength, _In_reads_(NeedleLength) const wchar_t* Needle, _In_ size_t NeedleLength);
BOOL IsRodcKrbtgtAccountName(_In_z_ const wchar_t* AccountName);
HANDLE OpenLogFile(_Out_opt_ BOOL* Secured);
void LogMessageW(_In_ LOG_LEVEL LogLevel, _In_ _Printf_format_string_ wchar_t* Message, _In_ ...);
