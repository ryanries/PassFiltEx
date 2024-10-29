/*
PassFiltEx.c
PassFiltEx by Joseph Ryan Ries
Author: Joseph Ryan Ries 2019-2024 <ryanries09@gmail.com>,<ryan.ries@microsoft.com>
A password filter for Active Directory that uses a blacklist of bad passwords/character sequences 
and also has some other options for a more robust password policy.

Technical Reference: https://msdn.microsoft.com/en-us/library/windows/desktop/ms721882(v=vs.85).aspx
********************************************************************************************
# READ ME
This is a personal project and is NOT endorsed or supported by Microsoft in any way.
Use at your own risk. This code is not guaranteed to be free of errors, and comes
with no guarantees, liability, warranties or support.
********************************************************************************************

Installation:
- Copy PassFiltEx.dll into the C:\Windows\System32 (i.e. %SystemRoot%\System32) directory on your domain controller.
- Copy the PassFiltExBlacklist.txt file into the C:\Windows\System32 (or %SystemRoot%\System32) directory.
- Replace the text file with a list of your own. This project does not include a complete production ready blacklist file - you must supply your own.
- Edit the registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa => Notification Packages
- Add PassFiltEx to the end of the list. (Do not include the file extension.) The whole list of notification packages will read
  "rassfm scecli PassFiltEx" with newlines between each one.
- Reboot the domain controller.
- Repeat the above procedure on all domain controllers.

Operation:
- Any time a user attempts to change his or her password, or any time an administrator attempts to set a user's password, the
  callback in this password filter will be invoked.
- It is possible to have multiple password filters installed simultaneously.
  All password filters must say yes in order for the password change to be accepted. If any password filter says no, the password change
  is rejected. Therefore, PassFiltEx does not need to check for password length, password complexity, password
  age, etc., because those things are already checked for using the in-box Windows password policy.
- Optionally, you can set the following registry values:
  Subkey: HKLM\SOFTWARE\PassFiltEx
	BlacklistFileName			REG_SZ		Default: PassFiltExBlacklist.txt
	TokenPercentageOfPassword	REG_DWORD	Default: 60
	RequireEitherLowerOrUpper	REG_DWORD	Default: 0
	MinLower					REG_DWORD	Default: 0
	MinUpper					REG_DWORD	Default: 0
	MinDigit					REG_DWORD	Default: 0
	MinSpecial					REG_DWORD	Default: 0
	MinUnicode					REG_DWORD	Default: 0
	BlockSequentialChars		REG_DWORD	Default: 0
	Debug						REG_DWORD	Default: 0

  BlacklistFileName 
  Allows you to specify a custom path to a blacklist file. By default if there is nothing specified, it is
  PassFiltExBlacklist.txt. The current working directory of the password filter is %SystemRoot%\System32, but you can specify
  a fully-qualified path name too. Even a UNC path (such as something in SYSVOL) if you want. WARNING: You are responsible
  for properly securing the blacklist file so that it may only be edited and viewed by authorized users.
  You can store the blacklist file in SYSVOL if you want, but you must ask yourself whether you want all Authenticated Users
  to have the ability to read your blacklist file or not.

  TokenPercentageOfPassword
  Allows you specify how much of the entire password must consist of the blacklisted token
  before the password change is rejected. The default is 60% if nothing is specified. The registry value is REG_DWORD, with
  the value 60 decimal representing 60%, which is converted to floating point 0 to 1.0 at runtime. For example, if the character sequence
  starwars appeared in the blacklist file, and TokenPercentageOfPassword was set to 60, then the password Starwars1! would
  be rejected, because more than 60% of the proposed password is made up of the blacklisted term starwars. However, the
  password starwars1!DarthVader88 would be accepted, because even though it contains the blacklisted sequence starwars, more
  than 60% of the proposed password is NOT starwars.

  MinLower/MinUpper/etc. 
  Allows you to specify if you require the user's password to contain multiple instances of any
  given character class. For example setting MinDigit to 2 will require passwords to contain at least 2 digits.

  BlockSequentialChars
  0 means it is off, 1 means it is on. This will block sequences of characters such as 'abc' or '123'.

  Debug
  0 means it's off, 1 means it is on. If Debug is on, additional log messages will be written to the log file.
  If Debug is off, then only serious errors will be logged.



- Comparisons are NOT case sensitive. (Though the final password will of course still be case sensitive.)

- The blacklist is reloaded every 60 seconds, so feel free to edit the blacklist file at will. 
  The password filter will read the new updates within a minute.

- Registry settings are re-read every 60 seconds as well so you can change the registry settings without having to restart the whole machine.

- All registry settings are optional. They do not need to exist. If a registry setting does not exist, the default is used.

- Unicode support is not thoroughly tested. Everything is assumed ASCII/ANSI. You can still use Unicode characters in your passwords, but Unicode
  characters will not match against anything in the blacklist.

- Either Windows or Unix line endings (either \r\n or \n) in the blacklist file should both work.

- For example, if the blacklist contains the token "abc", then the passwords abc and abc123 and AbC123 and 123Abc will all be
  rejected. But Abc123! will be accepted, because the token abc does not make up 60% or more of the full password. Unless
  BlockSequentialChars is enabled, in which case the password still be rejected because it contains 3 sequential characters, a b and c in a row.

- FAQ: Can you/will you integrate with Troy Hunt's "haveibeenpwned" API? Answer: Probably not. First, I'm pretty sure that has
  already been done by someone else. And you are free to use multiple password filters simultaneously if you want. Second,
  haveibeenpwned is about matching password hashes to identify passwords that have _already_ been owned. This password filter aims
  to solve a different problem by preventing not just passwords that have already been owned, but also preventing the use
  of passwords that could easily be owned because they contain common patterns, even if those password hashes are not known yet.


The debug log is Windows\system32\PassFiltEx.log. A new log file is automatically started once the current log file reaches 1MB.

You can use the command "tasklist /m PassFiltEx.dll" to verify whether the module is indeed loaded into the lsass process. Certain
security features such as RunAsPPL, antivirus, etc., might try to prevent lsass from loading the module.


Coding Guidelines:

- Want to contribute? Cool! Just remember: This code ABSOLUTELY MUST NOT CRASH. 
  If it crashes, it will crash the lsass process of the domain controller, which will in turn
  reboot the domain controller. It can even render a domain controller unbootable by putting the system into a boot loop.
  You'd need to boot the machine from alternate media and edit the registry offline to remove the password filter from the registry. 
  Therefore, this code must be immaculate and as reliable as you can possibly imagine. Avoid being "clever" and just write "boring", stable code.
  If you don't feel very comfortable with that, just leave me a note on what you want to see added and I'll see about it.
  That means /Wall, /WX and static analyzer at a minimum.
*/

#define WIN32_LEAN_AND_MEAN
#pragma warning(disable: 4710)	// Disable warnings about functions being inlined or not inlined.
#pragma warning(disable: 4711)
#pragma warning(disable: 5045)	// Disable warning about /Qspectre compiler switch
#pragma warning(disable: 4820)	// Disable warning about padding bytes being added to structs
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <intrin.h>
#include <NTSecAPI.h>
#include <ntstatus.h>
#include <stdio.h>
#include "PassFiltEx.h"

HANDLE gLogFileHandle = INVALID_HANDLE_VALUE;
HANDLE gBlacklistThread;
CRITICAL_SECTION gBlacklistCritSec;
CRITICAL_SECTION gLogCritSec;
BADSTRING* gBlacklistHead;
FILETIME gBlackListOldFileTime;
FILETIME gBlackListNewFileTime;
LARGE_INTEGER gPerformanceFrequency;
DWORD gTokenPercentageOfPassword = TOKEN_PERCENTAGE_OF_PASSWORD_DEFAULT;
wchar_t gBlacklistFileName[256] = { L"PassFiltExBlacklist.txt" };
DWORD gRequireEitherUpperOrLower;
DWORD gMinLower;
DWORD gMinUpper;
DWORD gMinDigit;
DWORD gMinSpecial;
DWORD gMinUnicode;
DWORD gBlockSequential;
DWORD gDebug;

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
	if ((gLogFileHandle = CreateFileW(FILTER_LOG_FILE_NAME, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
	{
		OutputDebugStringW(L"ERROR: Failed to create or open log file " FILTER_LOG_FILE_NAME L"!\n");
		ASSERT(0);
		return(FALSE);
	}

	// DO NOT ATTEMPT TO LOG ANYTHING UNTIL THESE CRITICAL SECTIONS ARE INITIALIZED
	(void)InitializeCriticalSectionAndSpinCount(&gBlacklistCritSec, 100);
	(void)InitializeCriticalSectionAndSpinCount(&gLogCritSec, 100);
	QueryPerformanceFrequency(&gPerformanceFrequency);

	LogMessageW(
		LOG_DEBUG, 
		L"[%s:%s@%d] %s %s is starting.",
		__FILENAMEW__,
		__FUNCTIONW__,
		__LINE__,
		L"PassFiltEx",
		FILTER_VERSION_STRING);

	if ((gBlacklistThread = CreateThread(NULL, 0, BlacklistThreadProc, NULL, 0, NULL)) == NULL)
	{
		LogMessageW(
			LOG_ERROR,
			L"[%s:%s@%d] Failed to create blacklist update thread! Error 0x%08lx",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__, 
			GetLastError());
		ASSERT(0);
		return(FALSE);
	}

	LogMessageW(
		LOG_DEBUG,
		L"[%s:%s@%d] Blacklist update thread created.", 
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

	// UNICODE_STRINGs might not be null-terminated.
	// Let's make a null-terminated copy of it.
	// MSDN says that the upper limit of sAMAccountName is 256
	// but SAM is AFAIK restricted to <= 20 characters. Let's pick a safe buffer size.

	wchar_t UserNameCopy[257] = { 0 };

	memcpy_s(&UserNameCopy, sizeof(UserNameCopy) - 1, UserName->Buffer, UserName->Length);
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
	size_t PasswordCopyLen = 0;
	DWORD NumLowers = 0;
	DWORD NumUppers = 0;
	DWORD NumDigits = 0;
	DWORD NumSpecials = 0;
	DWORD NumUnicodes = 0;
	LARGE_INTEGER StartTime = { 0 };
	LARGE_INTEGER EndTime = { 0 };
	LARGE_INTEGER ElapsedMicroseconds = { 0 };

	EnterCriticalSection(&gBlacklistCritSec);
	QueryPerformanceCounter(&StartTime);
	BADSTRING* CurrentNode = gBlacklistHead;

	// UNICODE_STRINGs are usually not null-terminated.
	// Let's make a null-terminated copy of it.
	// MSDN says that the upper limit of sAMAccountName is 256
	// but SAM is AFAIK restricted to <= 20 characters.
	// Anyway, let's pick a safe buffer size.

	wchar_t AccountNameCopy[257] = { 0 };
	wchar_t PasswordCopy[257] = { 0 };
	memcpy_s(&AccountNameCopy, sizeof(AccountNameCopy) - 1, AccountName->Buffer, AccountName->Length);
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

	if (wcsncmp(L"krbtgt_", AccountNameCopy, wcslen(L"krbtgt_")) == 0)
	{
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Always allowing password change for RODC krbtgt account.", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__);
		goto End;
	}

	memcpy_s(&PasswordCopy, sizeof(PasswordCopy) - 1, Password->Buffer, Password->Length);
	PasswordCopyLen = wcslen(PasswordCopy);
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

	if (Password->Length > 0) 
	{
		for (size_t Counter = 0; Counter < PasswordCopyLen; Counter++)
		{
			PasswordCopy[Counter] = towlower(PasswordCopy[Counter]);			
		}	
	}
	else
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

	while (CurrentNode != NULL && CurrentNode->Next != NULL)
	{
		CurrentNode = CurrentNode->Next;

		if (wcsnlen(CurrentNode->String, MAX_BLACKLIST_STRING_SIZE) == 0)
		{
			LogMessageW(
				LOG_ERROR,
				L"[%s:%s@%d] ERROR: This blacklist token is 0 characters long. It will be skipped. Remove blank lines from your blacklist file!", 
				__FILENAMEW__, 
				__FUNCTIONW__, 
				__LINE__);
			continue;
		}

		// the password copy has already been towlower'd at this point; this is a case-insensitive search
		if (wcsstr(PasswordCopy, CurrentNode->String))
		{
			if (((float)wcslen(CurrentNode->String) / (float)wcslen(PasswordCopy)) >= (float)gTokenPercentageOfPassword / 100)
			{
				LogMessageW(
					LOG_DEBUG,
					L"[%s:%s@%d] Rejecting password because it contains the blacklisted string \"%s\" and it is at least %lu%% of the full password!", 
					__FILENAMEW__, 
					__FUNCTIONW__, 
					__LINE__, 
					CurrentNode->String, 
					gTokenPercentageOfPassword);
				PasswordIsOK = FALSE;
				goto End;
			}
		}
	}
	
	for (size_t Character = 0; Character < PasswordCopyLen; Character++)
	{
		if ((Password->Buffer[Character] >= 97) && (Password->Buffer[Character] <= 122))
		{			
			NumLowers++;			
		}

		if ((Password->Buffer[Character] >= 65) && (Password->Buffer[Character] <= 90))
		{			
			NumUppers++;
		}

		if ((Password->Buffer[Character] >= 48) && (Password->Buffer[Character] <= 57))
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
		L"[%s:%s@%d] Password composition: %d lowers, %d uppers, %d digits, %d specials, %d unicode.", 
		__FILENAMEW__, 
		__FUNCTIONW__, 
		__LINE__,
		NumLowers,
		NumUppers,
		NumDigits,
		NumSpecials,
		NumUnicodes);
#endif

	if (gRequireEitherUpperOrLower)
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

	if (NumLowers < gMinLower)
	{		
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Rejecting password because %s is set to require %d lowercase letters, but the password contained %d lowercase letters.", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__, 
			FILTER_REG_MIN_LOWER,
			gMinLower,
			NumLowers);
		PasswordIsOK = FALSE;
		goto End;
	}

	if (NumUppers < gMinUpper)
	{		
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Rejecting password because %s is set to require %d uppercase letters, but the password contained %d uppercase letters.",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__,
			FILTER_REG_MIN_UPPER,
			gMinUpper,
			NumUppers);
		PasswordIsOK = FALSE;
		goto End;
	}

	if (NumDigits < gMinDigit)
	{
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Rejecting password because %s is set to require %d digits, but the password contained %d digits.",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__,
			FILTER_REG_MIN_DIGIT,
			gMinDigit,
			NumDigits);
		PasswordIsOK = FALSE;
		goto End;
	}

	if (NumSpecials < gMinSpecial)
	{		
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Rejecting password because %s is set to require %d special symbols, but the password contained %d special characters.",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__,
			FILTER_REG_MIN_SPECIAL,
			gMinSpecial,
			NumSpecials);
		PasswordIsOK = FALSE;
		goto End;
	}
	
	if (NumUnicodes < gMinUnicode)
	{		
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Rejecting password because %s is set to require %d unicode symbols, but the password contained %d unicode symbols.",
			__FILENAMEW__,
			__FUNCTIONW__,
			__LINE__,
			FILTER_REG_MIN_UNICODE,
			gMinUnicode,
			NumUnicodes);
		PasswordIsOK = FALSE;
		goto End;
	}

	if (gBlockSequential)
	{
		for (size_t Character = 0; Character < PasswordCopyLen - 2; Character++)
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

	
End:
	QueryPerformanceCounter(&EndTime);
	ElapsedMicroseconds.QuadPart = EndTime.QuadPart - StartTime.QuadPart;
	ElapsedMicroseconds.QuadPart *= 1000000;
	ElapsedMicroseconds.QuadPart /= gPerformanceFrequency.QuadPart;
	LogMessageW(
		LOG_DEBUG,
		L"[%s:%s@%d] Finished in %llu microseconds. Will accept new password: %s", 
		__FILENAMEW__, 
		__FUNCTIONW__, 
		__LINE__, 
		ElapsedMicroseconds.QuadPart, 
		(PasswordIsOK == 0 ? L"FALSE" : L"TRUE"));
	
	// NOTE: Despite what the MSDN documentation says, we should NOT be clearing the original password buffer that was passed in to us by Windows.
	// We only need to clear any copies of the password that we have made.
	//RtlSecureZeroMemory(&Password, Password->Length);

	RtlSecureZeroMemory(PasswordCopy, sizeof(PasswordCopy));
	LeaveCriticalSection(&gBlacklistCritSec);
	return(PasswordIsOK);
}

DWORD WINAPI BlacklistThreadProc(_In_ LPVOID Args)
{
	UNREFERENCED_PARAMETER(Args);

	while (TRUE)
	{
		HANDLE BlacklistFileHandle = INVALID_HANDLE_VALUE;
		LARGE_INTEGER StartTime = { 0 };
		LARGE_INTEGER EndTime = { 0 };
		LARGE_INTEGER ElapsedMicroseconds = { 0 };
		EnterCriticalSection(&gBlacklistCritSec);
		QueryPerformanceCounter(&StartTime);

		if (UpdateConfigurationFromRegistry() != ERROR_SUCCESS)
		{
			LogMessageW(
				LOG_ERROR,
				L"[%s:%s@%d] Failed to update configuration from registry! Something is very wrong!", 
				__FILENAMEW__, 
				__FUNCTIONW__, 
				__LINE__);
			ASSERT(0);
			goto Sleep;
		}

		// We are being loaded by lsass.exe. The current working directory of lsass should be C:\Windows\System32
		if ((BlacklistFileHandle = CreateFileW(gBlacklistFileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
		{
			wchar_t CurrentDir[MAX_PATH] = { 0 };
			GetCurrentDirectoryW(MAX_PATH, CurrentDir);
			LogMessageW(
				LOG_ERROR,
				L"[%s:%s@%d] Unable to open file %s! Current working directory: %s. Error 0x%08lx", 
				__FILENAMEW__, 
				__FUNCTIONW__, 
				__LINE__, 
				gBlacklistFileName, 
				CurrentDir, 
				GetLastError());			
			goto Sleep;
		}

		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] %s opened for read.", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__, 
			gBlacklistFileName);

		if (GetFileTime(BlacklistFileHandle, NULL, NULL, &gBlackListNewFileTime) == 0)
		{
			LogMessageW(
				LOG_ERROR,
				L"[%s:%s@%d] Failed to call GetFileTime on %s! Error 0x%08lx", 
				__FILENAMEW__, 
				__FUNCTIONW__, 
				__LINE__, 
				gBlacklistFileName, 
				GetLastError());
			ASSERT(0);
			goto Sleep;
		}

		if ((CompareFileTime(&gBlackListNewFileTime, &gBlackListOldFileTime) != 0) || gBlackListOldFileTime.dwLowDateTime == 0)
		{
			LogMessageW(
				LOG_DEBUG,
				L"[%s:%s@%d] The last modified time of %s has changed since the last time we looked. Reloading the file.", 
				__FILENAMEW__, 
				__FUNCTIONW__, 
				__LINE__, 
				gBlacklistFileName);
			// Initialize list head if we're here for the first time.
			if (gBlacklistHead == NULL)
			{
				if ((gBlacklistHead = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(BADSTRING))) == NULL)
				{
					LogMessageW(
						LOG_ERROR,
						L"[%s:%s@%d] ERROR: Failed to allocate memory for list head!", 
						__FILENAMEW__, 
						__FUNCTIONW__, 
						__LINE__);
					ASSERT(0);
					goto Sleep;
				}
			}

			// Need to clear blacklist and free memory first.
			BADSTRING* CurrentNode = gBlacklistHead;
			BADSTRING* NextNode = CurrentNode->Next;

			while (NextNode != NULL)
			{
				CurrentNode = NextNode;
				NextNode = CurrentNode->Next;

				if (HeapFree(GetProcessHeap(), 0, CurrentNode) == 0)
				{
					LogMessageW(
						LOG_ERROR,
						L"[%s:%s@%d] HeapFree failed while clearing blacklist! Error 0x%08lx", 
						__FILENAMEW__, 
						__FUNCTIONW__, 
						__LINE__, 
						GetLastError());
					ASSERT(0);
					goto Sleep;
				}
			}

			// Create a new node for the first line of text in the file.
			if ((CurrentNode = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(BADSTRING))) == NULL)
			{
				LogMessageW(
					LOG_ERROR,
					L"[%s:%s@%d] ERROR: Failed to allocate memory for list node!", 
					__FILENAMEW__, 
					__FUNCTIONW__,
					__LINE__);
				ASSERT(0);
				goto Sleep;
			}

			gBlacklistHead->Next = CurrentNode;

			DWORD TotalBytesRead = 0;
			DWORD BytesRead = 0;
			BYTE Read = 0;
			DWORD BytesOnThisLine = 0;
			DWORD LinesRead = 1;

			while (TRUE)
			{
				if (ReadFile(BlacklistFileHandle, &Read, 1, &BytesRead, NULL) == FALSE)
				{
					break;
				}

				if (BytesRead == 0)
				{
					break;
				}

				if (BytesOnThisLine >= MAX_BLACKLIST_STRING_SIZE - 1)
				{
					LogMessageW(
						LOG_ERROR,
						L"[%s:%s@%d] WARNING: Line longer than max length of %d! Will truncate this line and attempt to resume reading the next line.", 
						__FILENAMEW__, 
						__FUNCTIONW__, 
						__LINE__, 
						MAX_BLACKLIST_STRING_SIZE);
					Read = 0x0A;
				}

				// Ignore unprintable characters
				if (Read < 0x20)
				{
					// Unless it's \n
					if (Read != 0x0A)
					{
						TotalBytesRead++;
						continue;
					}
				}

				if (Read == 0x0A)
				{
					BytesOnThisLine = 0;
					BADSTRING* NewNode = NULL;
					if ((NewNode = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(BADSTRING))) == NULL)
					{
						LogMessageW(
							LOG_ERROR,
							L"[%s:%s@%d] ERROR: Failed to allocate memory for list node!", 
							__FILENAMEW__, 
							__FUNCTIONW__, 
							__LINE__);
						ASSERT(0);
						goto Sleep;
					}

					CurrentNode->Next = NewNode;
					CurrentNode = NewNode;
					TotalBytesRead++;
					LinesRead++;					
					continue;
				}

				CurrentNode->String[BytesOnThisLine] = (wchar_t)towlower(Read);
				TotalBytesRead++;
				BytesOnThisLine++;
			}

			LogMessageW(
				LOG_DEBUG,
				L"[%s:%s@%d] Read %lu bytes, %lu lines from file %s.", 
				__FILENAMEW__, 
				__FUNCTIONW__, 
				__LINE__, 
				TotalBytesRead, 
				LinesRead, 
				gBlacklistFileName);
		}	

	Sleep:
		if (BlacklistFileHandle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(BlacklistFileHandle);
		}

		gBlackListOldFileTime = gBlackListNewFileTime;
		QueryPerformanceCounter(&EndTime);
		ElapsedMicroseconds.QuadPart = EndTime.QuadPart - StartTime.QuadPart;		
		ElapsedMicroseconds.QuadPart *= 1000000;		
		ElapsedMicroseconds.QuadPart /= gPerformanceFrequency.QuadPart;
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Finished in %llu microseconds.", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__, 
			ElapsedMicroseconds.QuadPart);
		LeaveCriticalSection(&gBlacklistCritSec);
		Sleep(BLACKLIST_THREAD_RUN_FREQUENCY);
	}

	return(0);
}

DWORD UpdateConfigurationFromRegistry(void)
{
	DWORD Status = ERROR_SUCCESS;
	HKEY SubKeyHandle = NULL;
	DWORD SubKeyDisposition = 0;
	DWORD RegDataSize = 0;

	typedef struct DWORD_REG_SETTING
	{
		wchar_t* Name;
		void* Destination;
		DWORD MinValue;
		DWORD MaxValue;
		DWORD DefaultValue;
	} DWORD_REG_SETTING;

	DWORD_REG_SETTING DwordRegValues[] = { 
		{ .Name = FILTER_REG_DEBUG, .Destination = &gDebug, .MinValue = 0, .MaxValue = 1, .DefaultValue = 0 },
		{ .Name = FILTER_REG_REQUIRE_EITHER_LOWER_OR_UPPER, .Destination = &gRequireEitherUpperOrLower, .MinValue = 0, .MaxValue = 1, .DefaultValue = 0 },
		{ .Name = FILTER_REG_TOKEN_PERCENTAGE_OF_PASSWORD, .Destination = &gTokenPercentageOfPassword, .MinValue = 0, .MaxValue = 100, .DefaultValue = TOKEN_PERCENTAGE_OF_PASSWORD_DEFAULT },
		{ .Name = FILTER_REG_MIN_LOWER, .Destination = &gMinLower, .MinValue = 0, .MaxValue = 16, .DefaultValue = 0 },
		{ .Name = FILTER_REG_MIN_UPPER, .Destination = &gMinUpper, .MinValue = 0, .MaxValue = 16, .DefaultValue = 0 },
		{ .Name = FILTER_REG_MIN_DIGIT, .Destination = &gMinDigit, .MinValue = 0, .MaxValue = 16, .DefaultValue = 0 },
		{ .Name = FILTER_REG_MIN_SPECIAL, .Destination = &gMinSpecial, .MinValue = 0, .MaxValue = 16, .DefaultValue = 0 },
		{ .Name = FILTER_REG_MIN_UNICODE, .Destination = &gMinUnicode, .MinValue = 0, .MaxValue = 16, .DefaultValue = 0 },
		{ .Name = FILTER_REG_BLOCK_SEQUENTIAL, .Destination = &gBlockSequential, .MinValue = 0, .MaxValue = 1, .DefaultValue = 0 }
	};

	if ((Status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, FILTER_REG_SUBKEY, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &SubKeyHandle, &SubKeyDisposition)) != ERROR_SUCCESS)
	{
		LogMessageW(
			LOG_ERROR,
			L"[%s:%s@%d] Failed to open or create registry key HKLM\\%s! Error 0x%08lx", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__, 
			FILTER_REG_SUBKEY, 
			Status);
		ASSERT(0);
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

	for (unsigned int setting = 0; setting < __crt_countof(DwordRegValues); setting++)
	{
		RegDataSize = (DWORD)sizeof(DWORD);
		if ((Status = RegGetValueW(SubKeyHandle, NULL, DwordRegValues[setting].Name, RRF_RT_DWORD, NULL, DwordRegValues[setting].Destination, &RegDataSize)) != ERROR_SUCCESS)
		{
			if (Status == ERROR_FILE_NOT_FOUND)
			{
				LogMessageW(
					LOG_DEBUG,
					L"[%s:%s@%d] Registry value %s was not found. Using previous or default value %lu", 
					__FILENAMEW__, 
					__FUNCTIONW__, 
					__LINE__, 
					DwordRegValues[setting].Name, 
					*(DWORD*)DwordRegValues[setting].Destination);
				Status = ERROR_SUCCESS;
			}
			else
			{
				LogMessageW(
					LOG_ERROR,
					L"[%s:%s@%d] ERROR: Failed to read registry value %s! Error 0x%08lx", 
					__FILENAMEW__, 
					__FUNCTIONW__, 
					__LINE__, 
					DwordRegValues[setting].Name, 
					Status);
			}
		}
		else
		{
			LogMessageW(
				LOG_DEBUG,
				L"[%s:%s@%d] Successfully read registry value %s. Data: %lu", 
				__FILENAMEW__, 
				__FUNCTIONW__, 
				__LINE__, 
				DwordRegValues[setting].Name, 
				*(DWORD*)DwordRegValues[setting].Destination);

			if (*(DWORD*)DwordRegValues[setting].Destination > DwordRegValues[setting].MaxValue)
			{
				LogMessageW(
					LOG_ERROR,
					L"[%s:%s@%d] WARNING: %s was greater than the max allowed value %d. Defaulting to %d.", 
					__FILENAMEW__, 
					__FUNCTIONW__, 
					__LINE__, 
					DwordRegValues[setting].Name,
					DwordRegValues[setting].MaxValue, 
					DwordRegValues[setting].DefaultValue);

				*(DWORD*)DwordRegValues[setting].Destination = DwordRegValues[setting].DefaultValue;
			}
			else if (*(DWORD*)DwordRegValues[setting].Destination < DwordRegValues[setting].MinValue)
			{
				LogMessageW(
					LOG_ERROR,
					L"[%s:%s@%d] WARNING: %s was less than the minimum allowed value %d. Defaulting to %d.",
					__FILENAMEW__,
					__FUNCTIONW__,
					__LINE__,
					DwordRegValues[setting].Name,
					DwordRegValues[setting].MinValue,
					DwordRegValues[setting].DefaultValue);

				*(DWORD*)DwordRegValues[setting].Destination = DwordRegValues[setting].DefaultValue;
			}
		}
	}

	RegDataSize = (DWORD)sizeof(gBlacklistFileName);
	if ((Status = RegGetValueW(SubKeyHandle, NULL, FILTER_REG_BLACKLIST_FILENAME, RRF_RT_REG_SZ, NULL, &gBlacklistFileName, &RegDataSize)) != ERROR_SUCCESS)
	{
		if (Status == ERROR_FILE_NOT_FOUND)
		{
			LogMessageW(
				LOG_DEBUG,
				L"[%s:%s@%d] Registry value %s was not found. Using previous value %s", 
				__FILENAMEW__, 
				__FUNCTIONW__, 
				__LINE__, 
				FILTER_REG_BLACKLIST_FILENAME, 
				gBlacklistFileName);
			Status = ERROR_SUCCESS;
		}
		else
		{
			LogMessageW(
				LOG_ERROR,
				L"[%s:%s@%d] Failed to read registry value %s! Error 0x%08lx", 
				__FILENAMEW__, 
				__FUNCTIONW__, 
				__LINE__, 
				FILTER_REG_BLACKLIST_FILENAME, 
				Status);
		}
	}
	else
	{
		LogMessageW(
			LOG_DEBUG,
			L"[%s:%s@%d] Successfully read registry value %s. Data: %s", 
			__FILENAMEW__, 
			__FUNCTIONW__, 
			__LINE__, 
			FILTER_REG_BLACKLIST_FILENAME, 
			gBlacklistFileName);

		if (wcslen(gBlacklistFileName) == 0)
		{
			LogMessageW(
				LOG_ERROR,
				L"[%s:%s@%d] WARNING: %s was blank!", 
				__FILENAMEW__, 
				__FUNCTIONW__, 
				__LINE__, 
				FILTER_REG_BLACKLIST_FILENAME);
		}
	}	

Exit:

	if (SubKeyHandle != NULL)
	{
		RegCloseKey(SubKeyHandle);
	}

	LogMessageW(
		(Status == 0 ? LOG_DEBUG : LOG_ERROR),
		L"[%s:%s@%d] Returning 0x%08lx", 
		__FILENAMEW__, 
		__FUNCTIONW__, 
		__LINE__, 
		Status);

	return(Status);
}

void LogMessageW(_In_ LOG_LEVEL LogLevel, _In_ wchar_t* Message, _In_ ...)
{
	size_t MessageLength = 0;
	SYSTEMTIME Time = { 0 };
	DWORD EndOfFile = 0;
	DWORD NumberOfBytesWritten = 0;
	wchar_t DateTimeString[96] = { 0 };
	wchar_t FormattedMessage[2048] = { 0 };	
	int Error = 0;
	BOOL CritSecOwned = FALSE;

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
	_vsnwprintf_s(FormattedMessage, sizeof(FormattedMessage) / sizeof(wchar_t), _TRUNCATE, Message, ArgPointer);
	va_end(ArgPointer);
	// Synchronize file access, hold the crit sec for as little time as possible.
	EnterCriticalSection(&gLogCritSec);
	CritSecOwned = TRUE;
	EndOfFile = SetFilePointer(gLogFileHandle, 0, NULL, FILE_END);
	if (EndOfFile == INVALID_SET_FILE_POINTER)
	{
		OutputDebugStringW(L"ERROR: LogMessageW: SetFilePointer returned INVALID_SET_FILE_POINTER.\n");
		ASSERT(0);
		goto Exit;
	}
	if (EndOfFile >= 1024 * 1024)
	{
		// Log is big; start a new one.
		wchar_t ArchivedFileName[96] = { 0 };
		EndOfFile = 0;
		CloseHandle(gLogFileHandle);
		_snwprintf_s(
			ArchivedFileName, 
			__crt_countof(ArchivedFileName), 
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
		if ((gLogFileHandle = CreateFileW(FILTER_LOG_FILE_NAME, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
		{
			OutputDebugStringW(L"ERROR: LogMessageW: CreateFileW returned INVALID_HANDLE_VALUE!\n");
			ASSERT(0);
			goto Exit;
		}
	}
	if (EndOfFile == 0)
	{
		// UTF16 BOM if this is the beginning of a new file.
		wchar_t BOM = 0xFEFF;
		WriteFile(gLogFileHandle, &BOM, 2, &NumberOfBytesWritten, NULL);
	}
	Error = _snwprintf_s(
		DateTimeString, 
		sizeof(DateTimeString) / sizeof(wchar_t), 
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
		goto Exit;
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
	if (CritSecOwned)
	{
		LeaveCriticalSection(&gLogCritSec);
	}
}