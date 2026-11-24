/*
PassFiltEx.c
PassFiltEx by Joseph Ryan Ries
Author: Joseph Ryan Ries 2019-2025 <ryanries09@gmail.com>,<ryan.ries@microsoft.com>
A password filter for Active Directory that uses a blocklist of bad passwords/character sequences 
and also has some other options for a more robust password policy.

Technical Reference: https://msdn.microsoft.com/en-us/library/windows/desktop/ms721882(v=vs.85).aspx
********************************************************************************************
# READ ME
This is a personal project and is NOT endorsed or supported by Microsoft in any way.
Use at your own risk. This code is not guaranteed to be free of errors, and comes
with no guarantees, liability, warranties or support.
********************************************************************************************
01/29/2025: I have removed the rest of the readme text. See the external README.md file for more info.
*/

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <intrin.h>
#include <NTSecAPI.h>
#include <ntstatus.h>
#include <stdio.h>
#include <wchar.h>
#include <lm.h>
#include <sddl.h>
#include <AclAPI.h>
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Advapi32.lib")
#include "PassFiltEx.h"

// Provided by the linker. Its address is the base address of this DLL.
extern IMAGE_DOS_HEADER __ImageBase;

static HANDLE gLogFileHandle = INVALID_HANDLE_VALUE;
static HANDLE gBlocklistThread;
// Signaled once the blocklist thread has loaded the configuration and the blocklist for the first time.
static HANDLE gInitialLoadEvent;
// Protects gBlocklistHead. Never do file I/O while holding it, because every password change needs it.
static CRITICAL_SECTION gBlocklistCritSec;
static CRITICAL_SECTION gLogCritSec;
// The first blocklisted string, or NULL if there are none.
static BADSTRING* gBlocklistHead;
// Which file the current blocklist was loaded from. Only the blocklist thread uses these.
static BOOL gBlocklistLoaded;
static wchar_t gLoadedBlocklistFileName[256];
static FILETIME gLoadedBlocklistFileTime;
static LARGE_INTEGER gLoadedBlocklistFileSize;
static LARGE_INTEGER gPerformanceFrequency;
// Protects gConfig. Only the blocklist thread changes gConfig, and it always replaces all of it at once,
// so PasswordFilter never sees a configuration that has only been partially updated.
static SRWLOCK gConfigLock = SRWLOCK_INIT;
static FILTER_CONFIG gConfig = { .TokenPercentageOfPassword = 60, .BlocklistFileName = FILTER_DEFAULT_BLOCKLIST_FILE_NAME };
// A copy of gConfig.Debug, so that LogMessageW doesn't need to take gConfigLock.
static volatile LONG gDebug;

/*
DllMain
-------
https://msdn.microsoft.com/en-us/library/windows/desktop/ms682583(v=vs.85).aspx
The safest DllMain is one that does nothing.
*/
BOOL WINAPI DllMain(_In_ HINSTANCE DLLHandle, _In_ DWORD Reason, _In_ LPVOID Reserved)
{
	UNREFERENCED_PARAMETER(DLLHandle);
	UNREFERENCED_PARAMETER(Reason);	
	UNREFERENCED_PARAMETER(Reserved);
	return(TRUE);
}

/*
InitializeChangeNotify
----------------------
The InitializeChangeNotify function is implemented by a password filter DLL. This function initializes the DLL.
Parameters:
None.
Return value:
TRUE
	The password filter DLL is initialized.
FALSE
	The password filter DLL is not initialized.
Remarks:
InitializeChangeNotify is called by the Local Security Authority (LSA) to verify that the password notification DLL is loaded and initialized.
This function must use the __stdcall calling convention, and must be exported by the DLL.
This function is called only for password filters that are installed and registered on a system.
*/
__declspec(dllexport) BOOL CALLBACK InitializeChangeNotify(void)
{
	HMODULE ThisModule = NULL;
	BOOL LogFileSecured = FALSE;

	// DO NOT ATTEMPT TO LOG ANYTHING UNTIL THESE CRITICAL SECTIONS ARE INITIALIZED
	(void)InitializeCriticalSectionAndSpinCount(&gBlocklistCritSec, 100);
	(void)InitializeCriticalSectionAndSpinCount(&gLogCritSec, 100);
	QueryPerformanceFrequency(&gPerformanceFrequency);

	// Not being able to open the log file is not a good reason to fail. If we returned FALSE here, LSA would
	// never call PasswordFilter, so no passwords would be checked at all. LogMessageW will try to open it again later.
	EnterCriticalSection(&gLogCritSec);
	gLogFileHandle = OpenLogFile(&LogFileSecured);
	LeaveCriticalSection(&gLogCritSec);
	if (gLogFileHandle == INVALID_HANDLE_VALUE)
	{
		OutputDebugStringW(L"WARNING: Failed to create or open log file " FILTER_LOG_FILE_NAME L"!\n");
	}
	else if (LogFileSecured == FALSE)
	{
		LogMessageW(
			LOG_ERROR,
			L"[%s:%s@%d] WARNING: Could not restrict access to %s to SYSTEM and Administrators! Please check its permissions.",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__,
			FILTER_LOG_FILE_NAME);
	}

	// The blocklist thread runs code from this DLL for the rest of the life of the process,
	// so make sure that this DLL can never be unloaded out from under it.
	if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN, (LPCWSTR)&__ImageBase, &ThisModule) == FALSE)
	{
		LogMessageW(
			LOG_ERROR,
			L"[%s:%s@%d] WARNING: Failed to pin the module in memory! Error 0x%08lx",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__,
			GetLastError());
	}

	// Manual-reset, so that it stays signaled after the first load.
	if ((gInitialLoadEvent = CreateEventW(NULL, TRUE, FALSE, NULL)) == NULL)
	{
		LogMessageW(
			LOG_ERROR,
			L"[%s:%s@%d] WARNING: Failed to create the initial load event! Error 0x%08lx",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__,
			GetLastError());
	}

	if ((gBlocklistThread = CreateThread(NULL, 0, BlocklistThreadProc, NULL, 0, NULL)) == NULL)
	{
		LogMessageW(
			LOG_ERROR,
			L"[%s:%s@%d] Failed to create blocklist update thread! Error 0x%08lx",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__, 
			GetLastError());
		return(FALSE);
	}

	LogMessageW(
		LOG_DEBUG,
		L"[%s:%s@%d] Blocklist update thread created.", 
		__FILENAMEW__, 
		__FUNCTIONW__, 
		__LINE__);

	return(TRUE);
}

/*
PasswordChangeNotify
--------------------
The PasswordChangeNotify function is implemented by a password filter DLL. It notifies the DLL that a password was changed.
Parameters:
UserName [in]
	The account name of the user whose password changed.
	If the values of this parameter and the NewPassword parameter are NULL, this function should return STATUS_SUCCESS.
RelativeId [in]
	The relative identifier (RID) of the user specified in UserName.
NewPassword [in]
	A new plaintext password for the user specified in UserName. When you have finished using the password, clear the 
	information by calling the SecureZeroMemory function. For more information about protecting passwords, see Handling Passwords.
	If the values of this parameter and the UserName parameter are NULL, this function should return STATUS_SUCCESS.
Return value:
STATUS_SUCCESS
	Indicates the password of the user was changed, or that the values of both the UserName and NewPassword parameters are NULL.
Remarks:
The PasswordChangeNotify function is called after the PasswordFilter function has been called successfully and the new password has been stored.
This function must use the __stdcall calling convention and must be exported by the DLL.
When the PasswordChangeNotify routine is running, processing is blocked until the routine is finished. When appropriate, move any 
lengthy processing to a separate thread prior to returning from this routine.
This function is called only for password filters that are installed and registered on the system.
Any process exception that is not handled within this function may cause security-related failures system-wide.
Structured exception handling should be used when appropriate.
*/
__declspec(dllexport) NTSTATUS CALLBACK PasswordChangeNotify(_In_ PUNICODE_STRING UserName, _In_ ULONG RelativeId, _In_ PUNICODE_STRING NewPassword)
{
	UNREFERENCED_PARAMETER(NewPassword);

	// UserName can be NULL, and UNICODE_STRINGs might not be null-terminated.
	// Let's make a null-terminated copy of it. It is only used for logging, so it's OK to cut it short.
	// MSDN says that the upper limit of sAMAccountName is 256
	// but SAM is AFAIK restricted to <= 20 characters. Let's pick a safe buffer size.
	wchar_t UserNameCopy[257] = { 0 };

	if ((UserName != NULL) && (UserName->Buffer != NULL))
	{
		size_t UserNameLen = UserName->Length / sizeof(wchar_t);

		if (UserNameLen > ARRAYSIZE(UserNameCopy) - 1)
		{
			UserNameLen = ARRAYSIZE(UserNameCopy) - 1;
		}

		memcpy(UserNameCopy, UserName->Buffer, UserNameLen * sizeof(wchar_t));
	}

	LogMessageW(
		LOG_DEBUG,
		L"[%s:%s@%d] Password for %s (RID %lu) was changed.", 
		__FILENAMEW__, 
		__FUNCTIONW__, 
		__LINE__, 
		UserNameCopy, 
		RelativeId);

	return(STATUS_SUCCESS);
}

/*
PasswordFilter
--------------
The PasswordFilter function is implemented by a password filter DLL. The value returned by this function determines whether the new password is accepted by the system. 
All of the password filters installed on a system must return TRUE for the password change to take effect.
Parameters:
AccountName [in]
	Pointer to a UNICODE_STRING that represents the name of the user whose password changed.
FullName [in]
	Pointer to a UNICODE_STRING that represents the full name of the user whose password changed.
Password [in]
	Pointer to a UNICODE_STRING that represents the new plaintext password. When you have finished using the password, clear it from memory by calling the SecureZeroMemory function.
SetOperation [in]
	TRUE if the password was set rather than changed.
Return value:
TRUE
	Return TRUE if the new password is valid with respect to the password policy implemented in the password filter DLL. 
	When TRUE is returned, the Local Security Authority (LSA) continues to evaluate the password by calling any other password filters installed on the system.
FALSE
	Return FALSE if the new password is not valid with respect to the password policy implemented in the password filter DLL.
	When FALSE is returned, the LSA returns the ERROR_ILL_FORMED_PASSWORD (1324) status code to the source of the password change request.
Remarks:
Password change requests may be made when users specify a new password, accounts are created and when administrators override a password.
This function must use the __stdcall calling convention and must be exported by the DLL.
When the PasswordFilter routine is running, processing is blocked until the routine is finished. When appropriate, move any lengthy processing to a separate thread prior to returning from this routine.
This function is called only for password filters that are installed and registered on a system.
Any process exception that is not handled within this function may cause security-related failures system-wide. Structured exception handling should be used when appropriate.
*/
__declspec(dllexport) BOOL CALLBACK PasswordFilter(_In_ PUNICODE_STRING AccountName, _In_ PUNICODE_STRING FullName, _In_ PUNICODE_STRING Password, _In_ BOOL SetOperation)
{
	UNREFERENCED_PARAMETER(FullName);

	BOOL PasswordIsOK = TRUE;
	BOOL SkipThisUser = TRUE;
	BOOL IsSuperBlocked = FALSE;
	size_t AccountNameLen = 0;
	size_t PasswordLen = 0;
	wchar_t* PasswordCopy = NULL;
	DWORD NumLowers = 0;
	DWORD NumUppers = 0;
	DWORD NumDigits = 0;
	DWORD NumSpecials = 0;
	DWORD NumUnicodes = 0;
	LARGE_INTEGER StartTime = { 0 };
	LARGE_INTEGER EndTime = { 0 };
	LARGE_INTEGER ElapsedMicroseconds = { 0 };
	FILTER_CONFIG Config = { 0 };

	// UNICODE_STRINGs are usually not null-terminated.
	// Let's make a null-terminated copy of the account name.
	// MSDN says that the upper limit of sAMAccountName is 256
	// but SAM is AFAIK restricted to <= 20 characters.
	// Anyway, let's pick a safe buffer size.
	wchar_t AccountNameCopy[257] = { 0 };
	wchar_t BlockedString[MAX_BLOCKLIST_STRING_SIZE] = { 0 };

	QueryPerformanceCounter(&StartTime);

	// Right after the DLL is initialized, the blocklist thread might still be loading the configuration and the blocklist.
	// Wait for it, but not forever, so that even the first password change is checked against them.
	if ((gInitialLoadEvent != NULL) && (WaitForSingleObject(gInitialLoadEvent, INITIAL_LOAD_TIMEOUT_MS) != WAIT_OBJECT_0))
	{
		LogMessageW(
			LOG_ERROR,
			L"[%s:%s@%d] WARNING: Timed out waiting for the configuration and blocklist to be loaded. Continuing with what has been loaded so far.",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__);
	}

	// Work on a copy of the configuration, so that it can't change while we're using it.
	AcquireSRWLockShared(&gConfigLock);
	Config = gConfig;
	ReleaseSRWLockShared(&gConfigLock);

	if ((AccountName == NULL) ||
		(Password == NULL) ||
		((AccountName->Length > 0) && (AccountName->Buffer == NULL)) ||
		((Password->Length > 0) && (Password->Buffer == NULL)))
	{
		LogMessageW(
			LOG_ERROR,
			L"[%s:%s@%d] ERROR: Invalid parameter! Rejecting password.",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__);
		PasswordIsOK = FALSE;
		goto End;
	}

	// The Length of a UNICODE_STRING is in bytes, not characters.
	AccountNameLen = AccountName->Length / sizeof(wchar_t);
	if (AccountNameLen >= ARRAYSIZE(AccountNameCopy))
	{
		LogMessageW(
			LOG_ERROR,
			L"[%s:%s@%d] ERROR: The account name is %zu characters long, which is too long! Rejecting password.",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__,
			AccountNameLen);
		PasswordIsOK = FALSE;
		goto End;
	}

	if (AccountNameLen > 0)
	{
		memcpy(AccountNameCopy, AccountName->Buffer, AccountNameLen * sizeof(wchar_t));
	}

	// A null character inside the account name would make it look like a different account (such as krbtgt) below.
	if (wcslen(AccountNameCopy) != AccountNameLen)
	{
		LogMessageW(
			LOG_ERROR,
			L"[%s:%s@%d] ERROR: The account name %s contains a null character! Rejecting password.",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__,
			AccountNameCopy);
		PasswordIsOK = FALSE;
		goto End;
	}

	if (wcscmp(AccountNameCopy, L"krbtgt") == 0)
	{
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Always allowing password change for krbtgt account.", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__);
		goto End;
	}

	if (IsRodcKrbtgtAccountName(AccountNameCopy))
	{
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Always allowing password change for RODC krbtgt account.", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__);
		goto End;
	}

	PasswordLen = Password->Length / sizeof(wchar_t);

	// Don't print the password.
	if (SetOperation)
	{
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Attempting to SET password for user %s.", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__, 
			AccountNameCopy);
	}
	else
	{
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Attempting to CHANGE password for user %s.", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__, 
			AccountNameCopy);
	}

	if (PasswordLen == 0)
	{
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Empty password! Cannot continue.", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__);
		PasswordIsOK = FALSE;
		goto End;
	}

	// Make a lowercase copy of the password for the case-insensitive blocklist search.
	// Passwords can be any length, so the copy goes on the heap. It is cleared before it is freed.
	// From here on, everything uses PasswordLen instead of looking for a null terminator,
	// because the password itself might contain null characters.
	if ((PasswordCopy = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (PasswordLen + 1) * sizeof(wchar_t))) == NULL)
	{
		LogMessageW(
			LOG_ERROR,
			L"[%s:%s@%d] ERROR: Failed to allocate memory for a copy of the password! Rejecting password.",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__);
		PasswordIsOK = FALSE;
		goto End;
	}

	for (size_t Counter = 0; Counter < PasswordLen; Counter++)
	{
		PasswordCopy[Counter] = towlower(Password->Buffer[Counter]);
	}

	// NOTE: Currently this only scans top-level global security group membership of the user.
	// It does NOT expand all nested group membership.
	// I do this on purpose because this is much faster, and I'm worried that calculating all nested
	// group membership could slow us down too much.
	if (Config.ApplyToTheseGroups[0] != L'\0')
	{
		NET_API_STATUS Status = ERROR_SUCCESS;
		LPGROUP_USERS_INFO_0 GroupMemberships = NULL;
		DWORD EntriesRead = 0;
		DWORD TotalEntries = 0;
		Status = NetUserGetGroups(
			NULL,
			AccountNameCopy,
			0,
			(LPBYTE*)&GroupMemberships,
			MAX_PREFERRED_LENGTH,
			&EntriesRead,
			&TotalEntries);

		if ((Status != NERR_Success) || (EntriesRead != TotalEntries) || ((EntriesRead > 0) && (GroupMemberships == NULL)))
		{
			LogMessageW(
				LOG_ERROR,
				L"[%s:%s@%d] ERROR: NetUserGetGroups failed with 0x%08lx while trying to check the group memberships for %s!",
				__FILENAMEW__,
				__FUNCTIONW__,
				__LINE__,
				Status,
				AccountNameCopy);
			if (GroupMemberships)
			{
				NetApiBufferFree(GroupMemberships);
			}
			PasswordIsOK = FALSE;
			goto End;
		}

		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] %lu group memberships found for user %s.",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__,
			EntriesRead,
			AccountNameCopy);

		// Config.ApplyToTheseGroups is a list of null-terminated group names that ends with an empty string.
		for (const wchar_t* GroupName = Config.ApplyToTheseGroups; (*GroupName != L'\0') && (SkipThisUser == TRUE); GroupName += wcslen(GroupName) + 1)
		{
			for (DWORD g = 0; g < EntriesRead; g++)
			{
				if ((GroupMemberships[g].grui0_name != NULL) &&
					(CompareStringOrdinal(GroupName, -1, GroupMemberships[g].grui0_name, -1, TRUE) == CSTR_EQUAL))
				{
					LogMessageW(
						LOG_DEBUG,
						L"[%s:%s@%d] User %s was found to be a member of group %s.",
						__FILENAMEW__,
						__FUNCTIONW__,
						__LINE__,
						AccountNameCopy,
						GroupMemberships[g].grui0_name);
					SkipThisUser = FALSE;
					break;
				}
			}
		}

		if (GroupMemberships)
		{
			NetApiBufferFree(GroupMemberships);
		}
	}
	else
	{
		LogMessageW(LOG_DEBUG, 
			L"[%s:%s@%d] Not filtering by security group.",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__);
		SkipThisUser = FALSE;
	}

	if (SkipThisUser)
	{
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Skipping the user %s because they are not a member of any of the groups specified in the registry setting %s.",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__,
			AccountNameCopy,
			FILTER_REG_APPLY_TO_GROUPS);
		goto End;
	}

	EnterCriticalSection(&gBlocklistCritSec);
	for (const BADSTRING* CurrentNode = gBlocklistHead; CurrentNode != NULL; CurrentNode = CurrentNode->Next)
	{
		// if the blocklisted string starts with ! that means this string is totally forbidden regardless of how big the overall password is.
		// else we will honor the TokenPercentageOfPassword rule.
		// the password copy has already been towlower'd at this point, and so was the blocklist when it was loaded; this is a case-insensitive search.
		// Blocklisted strings are never empty (not even after the !), and they are always null-terminated.
		BOOL SuperBlocked = (CurrentNode->String[0] == L'!');
		const wchar_t* String = SuperBlocked ? CurrentNode->String + 1 : CurrentNode->String;
		size_t StringLen = wcslen(String);

		// Unless it's super-blocked, a string that is too short to be TokenPercentageOfPassword of this password can't get
		// the password rejected, so don't waste time searching for it. (This matters a lot for very long passwords.)
		if ((SuperBlocked == FALSE) && ((StringLen * 100) < ((size_t)Config.TokenPercentageOfPassword * PasswordLen)))
		{
			continue;
		}

		if (ContainsString(PasswordCopy, PasswordLen, String, StringLen))
		{
			// Remember which string it was, so it can be logged after leaving the critical section.
			wcscpy_s(BlockedString, ARRAYSIZE(BlockedString), String);
			IsSuperBlocked = SuperBlocked;
			PasswordIsOK = FALSE;
			break;
		}
	}
	LeaveCriticalSection(&gBlocklistCritSec);

	if (PasswordIsOK == FALSE)
	{
		if (IsSuperBlocked)
		{
			LogMessageW(
				LOG_DEBUG,
				L"[%s:%s@%d] Rejecting password because it contains the super-blocked string \"%s\"!",
				__FILENAMEW__,
				__FUNCTIONW__,
				__LINE__,
				BlockedString);
		}
		else
		{
			LogMessageW(
				LOG_DEBUG,
				L"[%s:%s@%d] Rejecting password because it contains the blocklisted string \"%s\" and it is at least %lu%% of the full password!",
				__FILENAMEW__,
				__FUNCTIONW__,
				__LINE__,
				BlockedString,
				Config.TokenPercentageOfPassword);
		}
		goto End;
	}
	
	// Here we look at the original Password and not the toLowered PasswordCopy because we need case sensitivity for this section.
	for (size_t Character = 0; Character < PasswordLen; Character++)
	{
		if ((Password->Buffer[Character] >= ASCII_LOWERCASE_BEGIN) && (Password->Buffer[Character] <= ASCII_LOWERCASE_END))
		{			
			NumLowers++;
		}

		if ((Password->Buffer[Character] >= ASCII_UPPERCASE_BEGIN) && (Password->Buffer[Character] <= ASCII_UPPERCASE_END))
		{			
			NumUppers++;
		}

		if ((Password->Buffer[Character] >= ASCII_DIGITS_BEGIN) && (Password->Buffer[Character] <= ASCII_DIGITS_END))
		{			
			NumDigits++;
		}

		if (((Password->Buffer[Character] >= 32 && Password->Buffer[Character] <= 47) || 
			(Password->Buffer[Character] >= 58 && Password->Buffer[Character] <= 64) ||
			(Password->Buffer[Character] >= 91 && Password->Buffer[Character] <= 96) ||
			(Password->Buffer[Character] >= 123 && Password->Buffer[Character] <= 126) ||
			(Password->Buffer[Character] >= 128 && Password->Buffer[Character] <= 255)))
		{			
			NumSpecials++;
		}

		if ((Password->Buffer[Character] > 255))
		{			
			NumUnicodes++;
		}
	}

	// Not printing this in Release builds because I guess it would give too much detail about the user's password.
#ifdef _DEBUG
	LogMessageW(
		LOG_DEBUG,
		L"[%s:%s@%d] Password composition: %lu lowers, %lu uppers, %lu digits, %lu specials, %lu unicode.", 
		__FILENAMEW__, 
		__FUNCTIONW__, 
		__LINE__,
		NumLowers,
		NumUppers,
		NumDigits,
		NumSpecials,
		NumUnicodes);
#endif

	if (Config.RequireEitherUpperOrLower)
	{
		if (NumLowers + NumUppers == 0)
		{
			LogMessageW(
				LOG_DEBUG,
				L"[%s:%s@%d] Rejecting password because %s is set but the password contains no uppercase or lowercase letters.", 
				__FILENAMEW__, 
				__FUNCTIONW__, 
				__LINE__,
				FILTER_REG_REQUIRE_EITHER_LOWER_OR_UPPER);
			PasswordIsOK = FALSE;
			goto End;
		}
	}

	if (NumLowers < Config.MinLower)
	{		
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Rejecting password because %s is set to require %lu lowercase letters, but the password contained %lu lowercase letters.", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__, 
			FILTER_REG_MIN_LOWER,
			Config.MinLower,
			NumLowers);
		PasswordIsOK = FALSE;
		goto End;
	}

	if (NumUppers < Config.MinUpper)
	{		
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Rejecting password because %s is set to require %lu uppercase letters, but the password contained %lu uppercase letters.",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__,
			FILTER_REG_MIN_UPPER,
			Config.MinUpper,
			NumUppers);
		PasswordIsOK = FALSE;
		goto End;
	}

	if (NumDigits < Config.MinDigit)
	{
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Rejecting password because %s is set to require %lu digits, but the password contained %lu digits.",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__,
			FILTER_REG_MIN_DIGIT,
			Config.MinDigit,
			NumDigits);
		PasswordIsOK = FALSE;
		goto End;
	}

	if (NumSpecials < Config.MinSpecial)
	{		
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Rejecting password because %s is set to require %lu special symbols, but the password contained %lu special characters.",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__,
			FILTER_REG_MIN_SPECIAL,
			Config.MinSpecial,
			NumSpecials);
		PasswordIsOK = FALSE;
		goto End;
	}
	
	if (NumUnicodes < Config.MinUnicode)
	{		
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Rejecting password because %s is set to require %lu unicode symbols, but the password contained %lu unicode symbols.",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__,
			FILTER_REG_MIN_UNICODE,
			Config.MinUnicode,
			NumUnicodes);
		PasswordIsOK = FALSE;
		goto End;
	}

	// Only check alphanumeric characters for sequences, so block abc and 123 but not !@#
	// NOTE: Character + 2 < PasswordLen, rather than Character < PasswordLen - 2, because PasswordLen - 2 
	// wraps around to a huge number when the password is shorter than 2 characters.
	if (Config.BlockSequential)
	{
		for (size_t Character = 0; Character + 2 < PasswordLen; Character++)
		{
			if (((Password->Buffer[Character] >= ASCII_LOWERCASE_BEGIN) && (Password->Buffer[Character] <= ASCII_LOWERCASE_END)) ||
				((Password->Buffer[Character] >= ASCII_UPPERCASE_BEGIN) && (Password->Buffer[Character] <= ASCII_UPPERCASE_END)) ||
				((Password->Buffer[Character] >= ASCII_DIGITS_BEGIN) && (Password->Buffer[Character] <= ASCII_DIGITS_END)))
			{
				if ((Password->Buffer[Character + 1] == Password->Buffer[Character] + 1) &&
					(Password->Buffer[Character + 2] == Password->Buffer[Character] + 2))
				{
					LogMessageW(
						LOG_DEBUG,
						L"[%s:%s@%d] Rejecting password because a sequential set was detected (e.g. 'abc' or '123' etc.) and %s is set to block it.",
						__FILENAMEW__,
						__FUNCTIONW__,
						__LINE__,
						FILTER_REG_BLOCK_SEQUENTIAL);
					PasswordIsOK = FALSE;
					goto End;
				}
			}
		}
	}

	if (Config.BlockRepeating)
	{
		for (size_t Character = 0; Character + 2 < PasswordLen; Character++)
		{
			if ((Password->Buffer[Character + 1] == Password->Buffer[Character]) &&
				(Password->Buffer[Character + 2] == Password->Buffer[Character]))
			{
				LogMessageW(
					LOG_DEBUG,
					L"[%s:%s@%d] Rejecting password because of repeating chars (e.g. 'aaa' or '1111' etc.) and %s is set to block it.",
					__FILENAMEW__,
					__FUNCTIONW__,
					__LINE__,
					FILTER_REG_BLOCK_REPEATING);
					PasswordIsOK = FALSE;
					goto End;
			}
		}
	}

	
End:
	QueryPerformanceCounter(&EndTime);
	if (gPerformanceFrequency.QuadPart > 0)
	{
		ElapsedMicroseconds.QuadPart = EndTime.QuadPart - StartTime.QuadPart;
		ElapsedMicroseconds.QuadPart *= 1000000;
		ElapsedMicroseconds.QuadPart /= gPerformanceFrequency.QuadPart;
	}
	LogMessageW(
		LOG_DEBUG,
		L"[%s:%s@%d] Finished in %lld microseconds. Will accept new password: %s", 
		__FILENAMEW__, 
		__FUNCTIONW__, 
		__LINE__, 
		ElapsedMicroseconds.QuadPart, 
		(PasswordIsOK == 0 ? L"FALSE" : L"TRUE"));
	
	// NOTE: Despite what the MSDN documentation says, we should NOT be clearing the original password buffer that was passed in to us by Windows.
	// We only need to clear any copies of the password that we have made.
	//RtlSecureZeroMemory(&Password, Password->Length);

	if (PasswordCopy != NULL)
	{
		RtlSecureZeroMemory(PasswordCopy, (PasswordLen + 1) * sizeof(wchar_t));
		HeapFree(GetProcessHeap(), 0, PasswordCopy);
	}

	return(PasswordIsOK);
}

DWORD WINAPI BlocklistThreadProc(_In_ LPVOID Args)
{
	UNREFERENCED_PARAMETER(Args);

	BOOL FirstRun = TRUE;

	while (TRUE)
	{
		LARGE_INTEGER StartTime = { 0 };
		LARGE_INTEGER EndTime = { 0 };
		LARGE_INTEGER ElapsedMicroseconds = { 0 };
		wchar_t BlocklistFileName[ARRAYSIZE(gConfig.BlocklistFileName)] = { 0 };
		QueryPerformanceCounter(&StartTime);

		// This always leaves a usable configuration in gConfig, even if some or all of the registry values can't be read.
		(void)UpdateConfigurationFromRegistry();

		if (FirstRun)
		{
			LogMessageW(
				LOG_DEBUG, 
				L"[%s:%s@%d] %s %s is starting.",
				__FILENAMEW__,
				__FUNCTIONW__,
				__LINE__,
				L"PassFiltEx",
				FILTER_VERSION_STRING);
		}

		AcquireSRWLockShared(&gConfigLock);
		wcscpy_s(BlocklistFileName, ARRAYSIZE(BlocklistFileName), gConfig.BlocklistFileName);
		ReleaseSRWLockShared(&gConfigLock);

		UpdateBlocklist(BlocklistFileName);

		if (FirstRun)
		{
			if (gInitialLoadEvent != NULL)
			{
				SetEvent(gInitialLoadEvent);
			}
			FirstRun = FALSE;
		}

		QueryPerformanceCounter(&EndTime);
		if (gPerformanceFrequency.QuadPart > 0)
		{
			ElapsedMicroseconds.QuadPart = EndTime.QuadPart - StartTime.QuadPart;
			ElapsedMicroseconds.QuadPart *= 1000000;
			ElapsedMicroseconds.QuadPart /= gPerformanceFrequency.QuadPart;
		}
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Finished in %lld microseconds.", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__, 
			ElapsedMicroseconds.QuadPart);
		Sleep(BLOCKLIST_THREAD_RUN_FREQUENCY);
	}

	return(0);
}

// Loads the blocklist file if it is a different file than last time, or if it has changed since it was last loaded.
// If the file can't be loaded, the current blocklist is kept, and we'll try again next time.
void UpdateBlocklist(_In_z_ const wchar_t* FileName)
{
	HANDLE BlocklistFileHandle = INVALID_HANDLE_VALUE;
	FILETIME LastWriteTime = { 0 };
	LARGE_INTEGER FileSize = { 0 };
	BADSTRING* NewHead = NULL;
	BADSTRING* NewTail = NULL;
	BADSTRING* OldHead = NULL;
	BOOL Failed = FALSE;
	BYTE Buffer[4096] = { 0 };
	DWORD BytesRead = 0;
	ULONGLONG TotalBytesRead = 0;
	DWORD LinesRead = 0;
	DWORD EntryCount = 0;
	wchar_t Line[MAX_BLOCKLIST_STRING_SIZE] = { 0 };
	size_t LineLength = 0;
	BOOL LineTooLong = FALSE;

	// We are being loaded by lsass.exe. The current working directory of lsass should be C:\Windows\System32
	// Other processes may read the file, or replace it by renaming, but not write to it while we're reading it.
	// If something is still writing to it (e.g. an editor in the middle of saving it), opening it fails with a 
	// sharing violation, and we try again next time, instead of loading a half-written file.
	if ((BlocklistFileHandle = CreateFileW(FileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
	{
		DWORD lastError = GetLastError();			
		wchar_t CurrentDir[MAX_PATH] = { 0 };
		GetCurrentDirectoryW(MAX_PATH, CurrentDir);
		LogMessageW(
			LOG_ERROR,
			L"[%s:%s@%d] Unable to open file %s! Current working directory: %s. Error 0x%08lx", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__, 
			FileName, 
			CurrentDir, 
			lastError);			
		goto Exit;
	}

	LogMessageW(
		LOG_DEBUG,
		L"[%s:%s@%d] %s opened for read.", 
		__FILENAMEW__, 
		__FUNCTIONW__, 
		__LINE__, 
		FileName);

	if ((GetFileTime(BlocklistFileHandle, NULL, NULL, &LastWriteTime) == 0) || (GetFileSizeEx(BlocklistFileHandle, &FileSize) == 0))
	{
		LogMessageW(
			LOG_ERROR,
			L"[%s:%s@%d] Failed to get the last modified time or size of %s! Error 0x%08lx", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__, 
			FileName, 
			GetLastError());
		goto Exit;
	}

	if ((gBlocklistLoaded == TRUE) &&
		(wcscmp(FileName, gLoadedBlocklistFileName) == 0) &&
		(CompareFileTime(&LastWriteTime, &gLoadedBlocklistFileTime) == 0) &&
		(FileSize.QuadPart == gLoadedBlocklistFileSize.QuadPart))
	{
		goto Exit;
	}

	LogMessageW(
		LOG_DEBUG,
		L"[%s:%s@%d] %s has changed since the last time we looked. Reloading the file.", 
		__FILENAMEW__, 
		__FUNCTIONW__, 
		__LINE__, 
		FileName);

	// The new blocklist is built without holding gBlocklistCritSec, so password changes never have to wait on
	// file I/O, which can be slow, especially when the file is on a network share. If anything goes wrong, the 
	// new blocklist is thrown away, and the current one stays in use.
	while (Failed == FALSE)
	{
		DWORD Start = 0;

		if (ReadFile(BlocklistFileHandle, Buffer, sizeof(Buffer), &BytesRead, NULL) == FALSE)
		{
			LogMessageW(
				LOG_ERROR,
				L"[%s:%s@%d] ERROR: Failed to read %s! Error 0x%08lx", 
				__FILENAMEW__, 
				__FUNCTIONW__, 
				__LINE__, 
				FileName, 
				GetLastError());
			Failed = TRUE;
			break;
		}

		if (BytesRead == 0)
		{
			break;
		}

		// Skip the byte order mark at the start of the file, if there is one, so it doesn't become part of the first blocklisted string.
		if (TotalBytesRead == 0)
		{
			if ((BytesRead >= 3) && (Buffer[0] == 0xEF) && (Buffer[1] == 0xBB) && (Buffer[2] == 0xBF))
			{
				// UTF-8
				Start = 3;
			}
			else if ((BytesRead >= 2) && (Buffer[0] == 0xFF) && (Buffer[1] == 0xFE))
			{
				// UTF-16LE
				Start = 2;
			}
		}

		TotalBytesRead += BytesRead;

		for (DWORD Index = Start; Index < BytesRead; Index++)
		{
			BYTE Read = Buffer[Index];

			if (Read == 0x0A)
			{
				LinesRead++;
				if (AddBlocklistLine(Line, LinesRead, FileName, &NewHead, &NewTail, &EntryCount) == FALSE)
				{
					Failed = TRUE;
					break;
				}
				memset(Line, 0, sizeof(Line));
				LineLength = 0;
				LineTooLong = FALSE;
				continue;
			}

			// Ignore unprintable characters, such as the \r in \r\n line endings.
			if (Read < 0x20)
			{
				continue;
			}

			if (LineLength >= MAX_BLOCKLIST_STRING_SIZE - 1)
			{
				if (LineTooLong == FALSE)
				{
					LogMessageW(
						LOG_ERROR,
						L"[%s:%s@%d] WARNING: Line %lu of %s is longer than the max length of %d characters! It will be truncated.", 
						__FILENAMEW__, 
						__FUNCTIONW__, 
						__LINE__, 
						LinesRead + 1,
						FileName,
						MAX_BLOCKLIST_STRING_SIZE - 1);
					LineTooLong = TRUE;
				}
				continue;
			}

			Line[LineLength++] = (wchar_t)towlower(Read);
		}
	}

	// The last line doesn't have to end with a newline.
	if ((Failed == FALSE) && (LineLength > 0))
	{
		LinesRead++;
		Failed = (AddBlocklistLine(Line, LinesRead, FileName, &NewHead, &NewTail, &EntryCount) == FALSE);
	}

	if (Failed)
	{
		LogMessageW(
			LOG_ERROR,
			L"[%s:%s@%d] ERROR: Failed to load %s. The previous blocklist will stay in use.", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__, 
			FileName);
		FreeBlocklist(NewHead);
		goto Exit;
	}

	// Swap in the new blocklist. The old one can be freed after leaving the critical section,
	// because once gBlocklistHead no longer points to it, nothing else can be using it.
	EnterCriticalSection(&gBlocklistCritSec);
	OldHead = gBlocklistHead;
	gBlocklistHead = NewHead;
	LeaveCriticalSection(&gBlocklistCritSec);
	FreeBlocklist(OldHead);

	wcscpy_s(gLoadedBlocklistFileName, ARRAYSIZE(gLoadedBlocklistFileName), FileName);
	gLoadedBlocklistFileTime = LastWriteTime;
	gLoadedBlocklistFileSize = FileSize;
	gBlocklistLoaded = TRUE;

	LogMessageW(
		LOG_DEBUG,
		L"[%s:%s@%d] Read %llu bytes, %lu lines, %lu blocklisted strings from file %s.", 
		__FILENAMEW__, 
		__FUNCTIONW__, 
		__LINE__, 
		TotalBytesRead, 
		LinesRead, 
		EntryCount,
		FileName);

Exit:
	if (BlocklistFileHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(BlocklistFileHandle);
	}
}

// Adds one line from the blocklist file to the end of a blocklist that is being built.
// Returns FALSE only if memory could not be allocated.
BOOL AddBlocklistLine(_In_z_ const wchar_t* Line, _In_ DWORD LineNumber, _In_z_ const wchar_t* FileName, _Inout_ BADSTRING** Head, _Inout_ BADSTRING** Tail, _Inout_ DWORD* EntryCount)
{
	BADSTRING* NewNode = NULL;

	// Blank lines are skipped.
	if (Line[0] == L'\0')
	{
		return(TRUE);
	}

	// A ! all by itself would block every possible password.
	if (wcscmp(Line, L"!") == 0)
	{
		LogMessageW(
			LOG_ERROR,
			L"[%s:%s@%d] WARNING: Line %lu of %s contains nothing but a ! character. It will be skipped.", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__, 
			LineNumber,
			FileName);
		return(TRUE);
	}

	if ((NewNode = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(BADSTRING))) == NULL)
	{
		LogMessageW(
			LOG_ERROR,
			L"[%s:%s@%d] ERROR: Failed to allocate memory for list node!", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__);
		return(FALSE);
	}

	wcscpy_s(NewNode->String, ARRAYSIZE(NewNode->String), Line);

	if (*Tail == NULL)
	{
		*Head = NewNode;
	}
	else
	{
		(*Tail)->Next = NewNode;
	}

	*Tail = NewNode;
	(*EntryCount)++;
	return(TRUE);
}

void FreeBlocklist(_In_opt_ BADSTRING* Head)
{
	while (Head != NULL)
	{
		BADSTRING* Next = Head->Next;
		HeapFree(GetProcessHeap(), 0, Head);
		Head = Next;
	}
}

// Reads the settings from the registry and replaces gConfig with them.
// Settings that don't exist in the registry get their default values. If a setting exists but can't be read,
// for example because it is the wrong type, it keeps its current value. gConfig always ends up usable.
DWORD UpdateConfigurationFromRegistry(void)
{
	DWORD Status = ERROR_SUCCESS;
	DWORD Result = ERROR_SUCCESS;
	HKEY SubKeyHandle = NULL;
	DWORD SubKeyDisposition = 0;
	DWORD RegDataSize = 0;
	FILTER_CONFIG NewConfig = { 0 };
	wchar_t FileNameValue[ARRAYSIZE(NewConfig.BlocklistFileName)] = { 0 };
	wchar_t GroupsValue[1024] = { 0 };

	typedef struct DWORD_REG_SETTING
	{
		wchar_t* Name;
		DWORD* Destination;
		DWORD MinValue;
		DWORD MaxValue;
		DWORD DefaultValue;
	} DWORD_REG_SETTING;

	// Debug is first, so that it takes effect for the rest of the messages logged by this function.
	DWORD_REG_SETTING DwordRegValues[] = { 
		{ .Name = FILTER_REG_DEBUG, .Destination = &NewConfig.Debug, .MinValue = 0, .MaxValue = 1, .DefaultValue = 0 },
		{ .Name = FILTER_REG_REQUIRE_EITHER_LOWER_OR_UPPER, .Destination = &NewConfig.RequireEitherUpperOrLower, .MinValue = 0, .MaxValue = 1, .DefaultValue = 0 },
		{ .Name = FILTER_REG_TOKEN_PERCENTAGE_OF_PASSWORD, .Destination = &NewConfig.TokenPercentageOfPassword, .MinValue = 0, .MaxValue = 100, .DefaultValue = 60 },
		{ .Name = FILTER_REG_MIN_LOWER, .Destination = &NewConfig.MinLower, .MinValue = 0, .MaxValue = 16, .DefaultValue = 0 },
		{ .Name = FILTER_REG_MIN_UPPER, .Destination = &NewConfig.MinUpper, .MinValue = 0, .MaxValue = 16, .DefaultValue = 0 },
		{ .Name = FILTER_REG_MIN_DIGIT, .Destination = &NewConfig.MinDigit, .MinValue = 0, .MaxValue = 16, .DefaultValue = 0 },
		{ .Name = FILTER_REG_MIN_SPECIAL, .Destination = &NewConfig.MinSpecial, .MinValue = 0, .MaxValue = 16, .DefaultValue = 0 },
		{ .Name = FILTER_REG_MIN_UNICODE, .Destination = &NewConfig.MinUnicode, .MinValue = 0, .MaxValue = 16, .DefaultValue = 0 },
		{ .Name = FILTER_REG_BLOCK_SEQUENTIAL, .Destination = &NewConfig.BlockSequential, .MinValue = 0, .MaxValue = 1, .DefaultValue = 0 },
		{ .Name = FILTER_REG_BLOCK_REPEATING, .Destination = &NewConfig.BlockRepeating, .MinValue = 0, .MaxValue = 1, .DefaultValue = 0 }
	};

	AcquireSRWLockShared(&gConfigLock);
	NewConfig = gConfig;
	ReleaseSRWLockShared(&gConfigLock);

	// KEY_READ is all we need. RegCreateKeyExW still creates the key if it doesn't exist yet (and we're allowed to.)
	if ((Status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, FILTER_REG_SUBKEY, 0, NULL, 0, KEY_READ, NULL, &SubKeyHandle, &SubKeyDisposition)) != ERROR_SUCCESS)
	{
		LogMessageW(
			LOG_ERROR,
			L"[%s:%s@%d] Failed to open or create registry key HKLM\\%s! Error 0x%08lx. Keeping the current settings.", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__, 
			FILTER_REG_SUBKEY, 
			Status);
		Result = Status;
		goto Exit;
	}

	if (SubKeyDisposition == REG_CREATED_NEW_KEY)
	{
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Created new registry subkey HKLM\\%s.", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__, 
			FILTER_REG_SUBKEY);
	}
	else if (SubKeyDisposition == REG_OPENED_EXISTING_KEY)
	{
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Opened existing registry subkey HKLM\\%s.", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__, 
			FILTER_REG_SUBKEY);
	}

	for (unsigned int setting = 0; setting < ARRAYSIZE(DwordRegValues); setting++)
	{
		DWORD Value = 0;
		RegDataSize = (DWORD)sizeof(Value);
		Status = RegGetValueW(SubKeyHandle, NULL, DwordRegValues[setting].Name, RRF_RT_DWORD, NULL, &Value, &RegDataSize);
		if (Status == ERROR_SUCCESS)
		{
			LogMessageW(
				LOG_DEBUG,
				L"[%s:%s@%d] Successfully read registry value %s. Data: %lu", 
				__FILENAMEW__, 
				__FUNCTIONW__, 
				__LINE__, 
				DwordRegValues[setting].Name, 
				Value);

			if (Value > DwordRegValues[setting].MaxValue)
			{
				LogMessageW(
					LOG_ERROR,
					L"[%s:%s@%d] WARNING: %s was greater than the max allowed value %lu. Defaulting to %lu.", 
					__FILENAMEW__, 
					__FUNCTIONW__, 
					__LINE__, 
					DwordRegValues[setting].Name,
					DwordRegValues[setting].MaxValue, 
					DwordRegValues[setting].DefaultValue);
				Value = DwordRegValues[setting].DefaultValue;
			}
			else if (Value < DwordRegValues[setting].MinValue)
			{
				LogMessageW(
					LOG_ERROR,
					L"[%s:%s@%d] WARNING: %s was less than the minimum allowed value %lu. Defaulting to %lu.",
					__FILENAMEW__,
					__FUNCTIONW__,
					__LINE__,
					DwordRegValues[setting].Name,
					DwordRegValues[setting].MinValue,
					DwordRegValues[setting].DefaultValue);
				Value = DwordRegValues[setting].DefaultValue;
			}

			*DwordRegValues[setting].Destination = Value;
		}
		else if (Status == ERROR_FILE_NOT_FOUND)
		{
			*DwordRegValues[setting].Destination = DwordRegValues[setting].DefaultValue;
			LogMessageW(
				LOG_DEBUG,
				L"[%s:%s@%d] Registry value %s was not found. Using default value %lu", 
				__FILENAMEW__, 
				__FUNCTIONW__, 
				__LINE__, 
				DwordRegValues[setting].Name, 
				DwordRegValues[setting].DefaultValue);
		}
		else
		{
			LogMessageW(
				LOG_ERROR,
				L"[%s:%s@%d] ERROR: Failed to read registry value %s! Error 0x%08lx. Keeping the current value %lu.", 
				__FILENAMEW__, 
				__FUNCTIONW__, 
				__LINE__, 
				DwordRegValues[setting].Name, 
				Status,
				*DwordRegValues[setting].Destination);
			Result = Status;
		}

		if (DwordRegValues[setting].Destination == &NewConfig.Debug)
		{
			InterlockedExchange(&gDebug, (LONG)NewConfig.Debug);
		}
	}

	RegDataSize = (DWORD)sizeof(FileNameValue);
	Status = RegGetValueW(SubKeyHandle, NULL, FILTER_REG_BLOCKLIST_FILENAME, RRF_RT_REG_SZ | RRF_ZEROONFAILURE, NULL, FileNameValue, &RegDataSize);
	if (Status == ERROR_SUCCESS)
	{
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Successfully read registry value %s. Data: %s", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__, 
			FILTER_REG_BLOCKLIST_FILENAME, 
			FileNameValue);

		if (FileNameValue[0] == L'\0')
		{
			LogMessageW(
				LOG_ERROR,
				L"[%s:%s@%d] WARNING: %s was blank! Using default value %s", 
				__FILENAMEW__, 
				__FUNCTIONW__, 
				__LINE__, 
				FILTER_REG_BLOCKLIST_FILENAME,
				FILTER_DEFAULT_BLOCKLIST_FILE_NAME);
			wcscpy_s(NewConfig.BlocklistFileName, ARRAYSIZE(NewConfig.BlocklistFileName), FILTER_DEFAULT_BLOCKLIST_FILE_NAME);
		}
		else
		{
			wcscpy_s(NewConfig.BlocklistFileName, ARRAYSIZE(NewConfig.BlocklistFileName), FileNameValue);
		}
	}
	else if (Status == ERROR_FILE_NOT_FOUND)
	{
		wcscpy_s(NewConfig.BlocklistFileName, ARRAYSIZE(NewConfig.BlocklistFileName), FILTER_DEFAULT_BLOCKLIST_FILE_NAME);
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Registry value %s was not found. Using default value %s", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__, 
			FILTER_REG_BLOCKLIST_FILENAME, 
			FILTER_DEFAULT_BLOCKLIST_FILE_NAME);
	}
	else
	{
		LogMessageW(
			LOG_ERROR,
			L"[%s:%s@%d] Failed to read registry value %s! Error 0x%08lx. Keeping the current value %s", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__, 
			FILTER_REG_BLOCKLIST_FILENAME, 
			Status,
			NewConfig.BlocklistFileName);
		Result = Status;
	}

	RegDataSize = (DWORD)sizeof(GroupsValue);
	Status = RegGetValueW(SubKeyHandle, NULL, FILTER_REG_APPLY_TO_GROUPS, RRF_RT_REG_SZ | RRF_ZEROONFAILURE, NULL, GroupsValue, &RegDataSize);
	if (Status == ERROR_SUCCESS)
	{
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Successfully read registry value %s. Data: %s",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__,
			FILTER_REG_APPLY_TO_GROUPS,
			GroupsValue);

		ParseGroupList(GroupsValue, NewConfig.ApplyToTheseGroups, ARRAYSIZE(NewConfig.ApplyToTheseGroups));

		if ((GroupsValue[0] != L'\0') && (NewConfig.ApplyToTheseGroups[0] == L'\0'))
		{
			LogMessageW(
				LOG_ERROR,
				L"[%s:%s@%d] WARNING: %s does not contain any group names. All users will be filtered.",
				__FILENAMEW__,
				__FUNCTIONW__,
				__LINE__,
				FILTER_REG_APPLY_TO_GROUPS);
		}
	}
	else if (Status == ERROR_FILE_NOT_FOUND)
	{
		memset(NewConfig.ApplyToTheseGroups, 0, sizeof(NewConfig.ApplyToTheseGroups));
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Registry value %s was not found. Using default value %s",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__,
			FILTER_REG_APPLY_TO_GROUPS,
			L"(empty)");
	}
	else
	{
		LogMessageW(
			LOG_ERROR,
			L"[%s:%s@%d] Failed to read registry value %s! Error 0x%08lx. Keeping the current value.",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__,
			FILTER_REG_APPLY_TO_GROUPS,
			Status);
		Result = Status;
	}

	AcquireSRWLockExclusive(&gConfigLock);
	gConfig = NewConfig;
	ReleaseSRWLockExclusive(&gConfigLock);

Exit:

	if (SubKeyHandle != NULL)
	{
		RegCloseKey(SubKeyHandle);
	}

	LogMessageW(
		(Result == ERROR_SUCCESS ? LOG_DEBUG : LOG_ERROR),
		L"[%s:%s@%d] Returning 0x%08lx", 
		__FILENAMEW__, 
		__FUNCTIONW__, 
		__LINE__, 
		Result);

	return(Result);
}

// Turns a comma-separated list of group names into a list of null-terminated names that ends with an empty string.
// Spaces around each name are removed, and empty names are skipped. OutputCount must be at least the length of GroupList + 2.
void ParseGroupList(_In_z_ const wchar_t* GroupList, _Out_writes_(OutputCount) wchar_t* Output, _In_ size_t OutputCount)
{
	const wchar_t* Current = GroupList;
	size_t OutputIndex = 0;

	memset(Output, 0, OutputCount * sizeof(wchar_t));

	while (*Current != L'\0')
	{
		const wchar_t* NameStart = NULL;
		const wchar_t* NameEnd = NULL;

		while (*Current == L' ')
		{
			Current++;
		}

		NameStart = Current;
		while ((*Current != L'\0') && (*Current != L','))
		{
			Current++;
		}

		NameEnd = Current;
		while ((NameEnd > NameStart) && (*(NameEnd - 1) == L' '))
		{
			NameEnd--;
		}

		if (NameEnd > NameStart)
		{
			size_t NameLength = (size_t)(NameEnd - NameStart);

			// Leave room for this name's null terminator and for the empty string that ends the list.
			if (OutputIndex + NameLength + 2 > OutputCount)
			{
				break;
			}

			memcpy(&Output[OutputIndex], NameStart, NameLength * sizeof(wchar_t));
			OutputIndex += NameLength + 1;
		}

		if (*Current == L',')
		{
			Current++;
		}
	}
}

// Like wcsstr, but it works with lengths instead of null terminators, so the haystack can contain null characters.
BOOL ContainsString(_In_reads_(HaystackLength) const wchar_t* Haystack, _In_ size_t HaystackLength, _In_reads_(NeedleLength) const wchar_t* Needle, _In_ size_t NeedleLength)
{
	if ((NeedleLength == 0) || (NeedleLength > HaystackLength))
	{
		return(FALSE);
	}

	for (size_t Position = 0; Position <= HaystackLength - NeedleLength; Position++)
	{
		if ((Haystack[Position] == Needle[0]) && (wmemcmp(&Haystack[Position], Needle, NeedleLength) == 0))
		{
			return(TRUE);
		}
	}

	return(FALSE);
}

// Each RODC has its own krbtgt account, named krbtgt_ followed by a number, such as krbtgt_12345.
BOOL IsRodcKrbtgtAccountName(_In_z_ const wchar_t* AccountName)
{
	const size_t PrefixLength = wcslen(L"krbtgt_");

	if ((wcsncmp(AccountName, L"krbtgt_", PrefixLength) != 0) || (AccountName[PrefixLength] == L'\0'))
	{
		return(FALSE);
	}

	for (const wchar_t* Character = &AccountName[PrefixLength]; *Character != L'\0'; Character++)
	{
		if ((*Character < L'0') || (*Character > L'9'))
		{
			return(FALSE);
		}
	}

	return(TRUE);
}

// Opens the log file, or creates it if it doesn't exist. Returns INVALID_HANDLE_VALUE on failure.
// Secured is set to TRUE if the log file is known to be accessible only by SYSTEM and Administrators.
// Must be called while holding gLogCritSec (or before any other thread can log.)
HANDLE OpenLogFile(_Out_opt_ BOOL* Secured)
{
	HANDLE FileHandle = INVALID_HANDLE_VALUE;
	PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;
	SECURITY_ATTRIBUTES SecurityAttributes = { .nLength = sizeof(SECURITY_ATTRIBUTES), .lpSecurityDescriptor = NULL, .bInheritHandle = FALSE };
	PACL Dacl = NULL;
	BOOL DaclPresent = FALSE;
	BOOL DaclDefaulted = FALSE;
	BOOL IsSecured = FALSE;

	// If the security descriptor can't be created for some reason, the log file just gets default permissions instead.
	if (ConvertStringSecurityDescriptorToSecurityDescriptorW(FILTER_LOG_FILE_SDDL, SDDL_REVISION_1, &SecurityDescriptor, NULL))
	{
		SecurityAttributes.lpSecurityDescriptor = SecurityDescriptor;
	}

	FileHandle = CreateFileW(FILTER_LOG_FILE_NAME, FILE_APPEND_DATA | READ_CONTROL | WRITE_DAC, FILE_SHARE_READ, &SecurityAttributes, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (FileHandle != INVALID_HANDLE_VALUE)
	{
		if (GetLastError() != ERROR_ALREADY_EXISTS)
		{
			// We just created it, with our security descriptor.
			IsSecured = (SecurityDescriptor != NULL);
		}
		else if ((SecurityDescriptor != NULL) &&
			GetSecurityDescriptorDacl(SecurityDescriptor, &DaclPresent, &Dacl, &DaclDefaulted) &&
			DaclPresent)
		{
			// A log file that already existed, such as one created by an older version, still has its old permissions, so fix them.
			IsSecured = (SetSecurityInfo(FileHandle, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, Dacl, NULL) == ERROR_SUCCESS);
		}
	}
	else
	{
		// We might not be allowed to change the permissions of an existing log file. Try again without asking to.
		FileHandle = CreateFileW(FILTER_LOG_FILE_NAME, FILE_APPEND_DATA, FILE_SHARE_READ, &SecurityAttributes, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		IsSecured = ((FileHandle != INVALID_HANDLE_VALUE) && (GetLastError() != ERROR_ALREADY_EXISTS) && (SecurityDescriptor != NULL));
	}

	if (SecurityDescriptor != NULL)
	{
		LocalFree(SecurityDescriptor);
	}

	if (Secured != NULL)
	{
		*Secured = IsSecured;
	}

	return(FileHandle);
}

void LogMessageW(_In_ LOG_LEVEL LogLevel, _In_ _Printf_format_string_ wchar_t* Message, _In_ ...)
{
	size_t MessageLength = 0;
	SYSTEMTIME Time = { 0 };
	LARGE_INTEGER FileSize = { 0 };
	DWORD NumberOfBytesWritten = 0;
	wchar_t DateTimeString[96] = { 0 };
	wchar_t FormattedMessage[2048] = { 0 };	
	int Error = 0;

	if (!gDebug && (LogLevel == LOG_DEBUG))
	{
		return;
	}

	MessageLength = wcslen(Message);
	if ((MessageLength < 1) || (MessageLength > 2047))
	{
		OutputDebugStringW(L"ERROR: LogMessageW tried to log a message that was either too long or too short!\n");
		ASSERT(0);
		return;
	}

	GetLocalTime(&Time);
	va_list ArgPointer = NULL;
	va_start(ArgPointer, Message);
	_vsnwprintf_s(FormattedMessage, ARRAYSIZE(FormattedMessage), _TRUNCATE, Message, ArgPointer);
	va_end(ArgPointer);

	Error = _snwprintf_s(
		DateTimeString, 
		ARRAYSIZE(DateTimeString), 
		_TRUNCATE, 
		L"[%02d/%02d/%d %02d:%02d:%02d.%03d]", 
		Time.wMonth, 
		Time.wDay, 
		Time.wYear, 
		Time.wHour, 
		Time.wMinute, 
		Time.wSecond, 
		Time.wMilliseconds);
	if (Error < 1)
	{
		OutputDebugStringW(L"ERROR: LogMessageW: _snwprintf_s returned -1. Buffer too small?\n");
		ASSERT(0);
		return;
	}

	// Synchronize file access, hold the crit sec for as little time as possible.
	EnterCriticalSection(&gLogCritSec);

	if (gLogFileHandle == INVALID_HANDLE_VALUE)
	{
		// The log file couldn't be opened earlier. Try again.
		if ((gLogFileHandle = OpenLogFile(NULL)) == INVALID_HANDLE_VALUE)
		{
			goto Exit;
		}
	}

	if (GetFileSizeEx(gLogFileHandle, &FileSize) == 0)
	{
		OutputDebugStringW(L"ERROR: LogMessageW: GetFileSizeEx failed.\n");
		goto Exit;
	}

	if (FileSize.QuadPart >= FILTER_LOG_MAX_SIZE)
	{
		// Log is big; start a new one.
		wchar_t ArchivedFileName[96] = { 0 };
		CloseHandle(gLogFileHandle);
		_snwprintf_s(
			ArchivedFileName, 
			ARRAYSIZE(ArchivedFileName), 
			_TRUNCATE, 
			L"%s_%02d.%02d.%02d.%02d.%02d.%02d.log",
			L"PassFiltEx", 
			Time.wMonth, 
			Time.wDay, 
			Time.wYear, 
			Time.wHour, 
			Time.wMinute, 
			Time.wSecond);
		MoveFileW(FILTER_LOG_FILE_NAME, ArchivedFileName);
		if ((gLogFileHandle = OpenLogFile(NULL)) == INVALID_HANDLE_VALUE)
		{
			OutputDebugStringW(L"ERROR: LogMessageW: Failed to open a new log file!\n");
			goto Exit;
		}

		// If the log file couldn't be renamed, this is still the same old file, so get its size again.
		if (GetFileSizeEx(gLogFileHandle, &FileSize) == 0)
		{
			OutputDebugStringW(L"ERROR: LogMessageW: GetFileSizeEx failed.\n");
			goto Exit;
		}
	}

	if (FileSize.QuadPart == 0)
	{
		// UTF16 BOM if this is the beginning of a new file.
		wchar_t BOM = 0xFEFF;
		WriteFile(gLogFileHandle, &BOM, 2, &NumberOfBytesWritten, NULL);
	}

	WriteFile(gLogFileHandle, DateTimeString, (DWORD)wcslen(DateTimeString) * sizeof(wchar_t), &NumberOfBytesWritten, NULL);	
	WriteFile(gLogFileHandle, FormattedMessage, (DWORD)wcslen(FormattedMessage) * sizeof(wchar_t), &NumberOfBytesWritten, NULL);
	WriteFile(gLogFileHandle, L"\n", 2, &NumberOfBytesWritten, NULL);
#ifdef _DEBUG
	wprintf(L"%s", DateTimeString);
	wprintf(L"%s", FormattedMessage);
	wprintf(L"\n");
#endif
Exit:
	LeaveCriticalSection(&gLogCritSec);
}
