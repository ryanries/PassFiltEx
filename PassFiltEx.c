/*
PassFiltEx.c
# PassFiltEx by Joseph Ryan Ries
Author: Joseph Ryan Ries 2019 <ryanries09@gmail.com> <ryan.ries@microsoft.com>

A password filter for Active Directory that uses a blacklist of bad passwords/character sequences.
Reference: https://msdn.microsoft.com/en-us/library/windows/desktop/ms721882(v=vs.85).aspx
********************************************************************************************
# READ ME
This is a personal project and is NOT endorsed or supported by Microsoft in any way.
Use at your own risk. This code is not guaranteed to be free of errors, and comes
with no guarantees, liability, warranties or support.
********************************************************************************************

I wrote this just to join the club of people who can say that they've done it. Programming is fun.

Installation:

- Copy PassFiltEx.dll into the C:\Windows\System32 (or %SystemRoot%\System32) directory.
- Copy the PassFiltExBlacklist.txt file into the C:\Windows\System32 (or %SystemRoot%\System32) directory.
- (Or replace the text file with a list of your own. You are free to edit the blacklist file if you want.)
- Edit the registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa => Notification Packages
- Add PassFiltEx to the end of the list. (Do not include the file extension.) So the whole list of notification packages will read
  "rassfm scecli PassFiltEx" with newlines between each one.
- Reboot the domain controller.
- Repeat the above procedure on all domain controllers.
![files](files1.png "files")

![regedit](regedit1.png "register the filter")

Operation:

- Any time a user attempts to change his or her password, or any time an administrator attempts to set a user's password, the
  callback in this password filter will be invoked.
- All password filters must say yes in order for the password change to be accepted. If any password filter says no, the password
  is not accepted. Therefore, this password filter does not need to check for password length, password complexity, password
  age, etc., because those things are already checked for using the in-box Windows password policy.

- Optionally, you can set the following registry values:
  Subkey: HKLM\SOFTWARE\PassFiltEx
	**BlacklistFileName**, REG_SZ, Default: PassFiltExBlacklist.txt
	**TokenPercentageOfPassword**, REG_DWORD, Default: 60
	**RequireCharClasses**, REG_DWORD, Default: 0

![regedit](regedit2.png "optional reg entries")

  **BlacklistFileName** allows you to specify a custom path to a blacklist file. By default if there is nothing specified, it is
  PassFiltExBlacklist.txt. The current working directory of the password filter is %SystemRoot%\System32, but you can specify
  a fully-qualified path name too. Even a UNC path (such as something in SYSVOL) if you want. WARNING: You are responsible
  for properly setting the permissions on the blacklist file so that it may only be edited and viewed by authorized users.
  You can store the blacklist file in SYSVOL if you want, but you must ask yourself whether you want all Authenticated Users
  to have the ability to read your blacklist file.

  **TokenPercentageOfPassword** allows you specify how much of the entire password must consist of the blacklisted token
  before the password change is rejected. The default is 60% if nothing is specified. The registry value is REG_DWORD, with
  the value 60 decimal representing 60%, which is converted to float 0 - 1.0 at runtime. For example, if the character sequence
  starwars appeared in the blacklist file, and TokenPercentageOfPassword was set to 60, then the password Starwars1! would
  be rejected, because more than 60% of the proposed password is made up of the blacklisted term starwars. However, the
  password starwars1!DarthVader88 would be accepted, because even though it contains the blacklisted sequence starwars, more
  than 60% of the proposed password is NOT starwars.

  **RequireCharClasses** allows you to require even more categories of characters over the built-in Active Directory
  password complexity rules configured via Group Policy. The built-in AD password complexity rules only require 3 out of 5
  possible different types of characters: Uppercase, Lowercase, Digit, Special, and Unicode. This registry setting allows you
  to require 4 or even 5 out of the 5 possible different character types. You may use this registry setting either in combination
  with the built-in AD password complexity, or without it. The value is a bitfield where 1 = require lower, 2 = require upper,
  4 = require digit, 8 = require special, 16 = require unicode, and 32 = require either lower or upper. You can add these flags together to make combinations. E.g.,
  a value of 15 (decimal) means "require lower AND upper AND digit AND special, but not unicode."


- Comparisons are NOT case sensitive. The user's final password, once approved, will of course remain case sensitive though.
- The blacklist is reloaded every 60 seconds, so feel free to edit the blacklist file at will. The password filter will read the
  new updates within a minute.
- No Unicode support at this time. Everything is ASCII/ANSI. (You can still use Unicode characters in your passwords, but Unicode
  characters will not match against anything in the blacklist.)
- Either Windows or Unix line endings (either \r\n or \n) in the blacklist file should both work. (Notepad++ is a good editor for
  finding unprintable characters in your text file.)
- For example, if the blacklist contains the token "abc", then the passwords abc and abc123 and AbC123 and 123Abc will all be
  rejected. But Abc123! will be accepted, because the token abc does not make up 60% or more of the full password.
- Question: Can you/will you integrate with Troy Hunt's "haveibeenpwned" API? Answer: Probably not. First, I'm pretty sure that has
  already been done by someone else. And you are free to use multiple password filters simultaneously if you want. Second,
  haveibeenpwned is about matching password hashes to identify passwords that have _already_ been owned. This password filter aims
  to solve a slightly different problem by preventing not just passwords that have already been owned, but also preventing the use
  of passwords that could easily be owned because they contain common patterns, even if those password hashes are not known yet.


Debugging:

- The RELEASE build of the password filter uses only ETW event logging. The DEBUG build logs to ETW, stdout console and also DebugOut.
  (You can use Sysinternal's DbgView to view DebugOut messages.)
  WARNING: Debug builds print the passwords out into the logging, which is a security risk. Release builds do not print passwords.
- The password filter utilizes Event Tracing for Windows (ETW). ETW is fast, lightweight, and there is no concern over managing
  text-based log files which are slow and consume disk space.
- The ETW provider for this password filter is 07d83223-7594-4852-babc-784803fdf6c5. So for example, you can enable tracing of the
  password filter on the next boot of the machine with: logman create trace autosession\PassFiltEx -o
  %SystemRoot%\Debug\PassFiltEx.etl -p "{07d83223-7594-4852-babc-784803fdf6c5}" 0xFFFFFFFF -ets
- The trace will start when you reboot. To stop the trace, run:
  logman stop PassFiltEx -ets && logman delete autosession\PassFiltEx -ets
- The StartTracingAtBoot.cmd and StopTracingAtBoot.cmd files provided contain these commands.
- The other files, StartTracing.cmd and StopTracing.cmd will also enable the tracing, but the tracing will not persist across reboots.
- Collect the *.etl file that is generated in the C:\Windows\debug directory. Then open the ETL file with a tool such as Microsoft
  Message Analyzer. (There are other tools that understand ETW as well. Use what you like.) Add the "payload" as a Column, and
  decode the payload column as Unicode. Then it should look like a normal, human-readable text log.

![starttrace](trace1.png "start the trace")

![etw1](ma1.png "view trace with Message Analyzer")

![etw2](ma2.png "view trace with Message Analyzer")

![etw1](ma3.png "view trace with Message Analyzer")

- In the trace log above, you see an administrator attempting to set the password for the user hunter2.
  If the user had been attempting to reset their own password, the log would say "CHANGE password" instead of "SET password".
  Notice that the password is rejected numerous times. I tried to set the password to starwars, starwars1, Starwars1!, etc., but
  they all were rejected because the blacklist contains the token starwars. However, I eventually attempted to set the password
  to Starwars1!DarthVader, and that password was accepted because even though it contains the token starwars, more than 50% of the
  password is NOT starwars.

Coding Guidelines:

- Want to contribute? Cool! I'd like to stick to these rules:
- C only. (No C++, at least not in the filter itself.)
- Compile with All Warnings (/Wall). Project should compile with 0 warnings. You MAY temporarily disable warnings with #pragmas if
  the warnings are too pedantic (e.g. don't warn me about adding padding bytes to structs or that a function was inlined.)
- MSVC 2017 was the IDE I used originally. You can use something else if you have a good reason to though.
- Use a static analyzer. The MSVC IDE comes with Code Analysis. Put it on "All Rules". You shouldn't trigger any Code Analysis
  warnings.
- Define UNICODE.
- Prefix global symbols with a lower-case g, no underscore. (E.g. gGlobalVar, not g_GlobalVar)
- Hungarian notation not necessary. Use descriptive variable names. We don't use 80-character terminals anymore; it's OK to type
  it out.
- Comments are good but don't make a lot of comments about what the code does - instead write comments about _why_ you're doing
  what you're doing.
- This code ABSOLUTELY MUST NOT CRASH. If it crashes, it will crash the lsass process of the domain controller, which will in turn
  reboot the domain controller. It can even render a domain controller unbootable. You'd need to boot the machine from alternate
  media and edit the registry offline to remove the password filter from the registry. Therefore, this code must be immaculate
  and as reliable as you can possibly imagine. Avoid being "clever" and just write "boring" code.
*/

#define WIN32_LEAN_AND_MEAN

// Disable warnings about functions being inlined or not inlined.
#pragma warning(disable: 4710)
#pragma warning(disable: 4711)
// Disable warning about /Qspectre comiler switch
#pragma warning(disable: 5045)
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <NTSecAPI.h>
#include <ntstatus.h>
#include <evntprov.h>
#include <stdio.h>
#include "PassFiltEx.h"

REGHANDLE gEtwRegHandle;
HANDLE gBlacklistThread;
CRITICAL_SECTION gBlacklistCritSec;
BADSTRING* gBlacklistHead;
FILETIME gBlackListOldFileTime;
FILETIME gBlackListNewFileTime;
LARGE_INTEGER gPerformanceFrequency;
DWORD gTokenPercentageOfPassword = 60;
wchar_t gBlacklistFileName[256] = { L"PassFiltExBlacklist.txt" };
DWORD gRequireCharClasses;

/*
DllMain
-------
https://msdn.microsoft.com/en-us/library/windows/desktop/ms682583(v=vs.85).aspx
The only winning move is not to play.
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
Any process exception that is not handled within this function may cause security-related failures system-wide. Structured exception handling should be used when appropriate.
*/
__declspec(dllexport) BOOL CALLBACK InitializeChangeNotify(void)
{
	const GUID ETWProviderGuid = { 0x07d83223, 0x7594, 0x4852, { 0xba, 0xbc, 0x78, 0x48, 0x03, 0xfd, 0xf6, 0xc5 } };
	
	if (EventRegister(&ETWProviderGuid, NULL, NULL, &gEtwRegHandle) != ERROR_SUCCESS)
	{
		return(FALSE);
	}
	EventWriteStringW2(L"[%s:%s@%d] ETW provider registered.", __FILENAMEW__, __FUNCTIONW__, __LINE__);
#pragma warning(push)
#pragma warning(disable: 6031) 
	// MSDN states that this call never fails so no need to bother with the return value.
	InitializeCriticalSectionAndSpinCount(&gBlacklistCritSec, 4000);	
	// Same as above.
	QueryPerformanceFrequency(&gPerformanceFrequency);
#pragma warning(pop)
	if ((gBlacklistThread = CreateThread(NULL, 0, BlacklistThreadProc, NULL, 0, NULL)) == NULL)
	{
		EventWriteStringW2(L"[%s:%s@%d] Failed to create blacklist update thread! Error 0x%08lx", __FILENAMEW__, __FUNCTIONW__, __LINE__, GetLastError());
		return(FALSE);
	}

	EventWriteStringW2(L"[%s:%s@%d] Blacklist update thread created.", __FILENAMEW__, __FUNCTIONW__, __LINE__);
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
	UNREFERENCED_PARAMETER(UserName);
	UNREFERENCED_PARAMETER(RelativeId);
	UNREFERENCED_PARAMETER(NewPassword);

	// UNICODE_STRINGs are usually not null-terminated.
	// Let's make a null-terminated copy of it.
	// MSDN says that the upper limit of sAMAccountName is 256
	// but SAM is AFAIK restricted to <= 20 characters. Anyway, let's pick a safe buffer size.

	wchar_t UserNameCopy[257] = { 0 };

	memcpy_s(&UserNameCopy, sizeof(UserNameCopy) - 1, UserName->Buffer, UserName->Length);
	EventWriteStringW2(L"[%s:%s@%d] Password for %s (RID %lu) was changed.", __FILENAMEW__, __FUNCTIONW__, __LINE__, UserNameCopy, RelativeId);
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
	BOOL ContainsLower = FALSE;
	BOOL ContainsUpper = FALSE;
	BOOL ContainsDigit = FALSE;
	BOOL ContainsSpecial = FALSE;
	BOOL ContainsUnicode = FALSE;
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
	if (_wcsicmp(AccountNameCopy, L"krbtgt") == 0)
	{
		EventWriteStringW2(L"[%s:%s@%d] Always allowing password change for krbtgt account.", __FILENAMEW__, __FUNCTIONW__, __LINE__);
		goto End;
	}

	if (wcsncmp(L"krbtgt_", AccountNameCopy, wcslen(L"krbtgt_")) == 0)
	{
		EventWriteStringW2(L"[%s:%s@%d] Always allowing password change for RODC krbtgt account.", __FILENAMEW__, __FUNCTIONW__, __LINE__);
		goto End;
	}

	memcpy_s(&PasswordCopy, sizeof(PasswordCopy) - 1, Password->Buffer, Password->Length);
	// Only print out the password in DEBUG builds. It is a security risk.
	if (SetOperation)
	{
		#ifdef DEBUG	
		EventWriteStringW2(L"[%s:%s@%d] Attempting to SET password for user %s to new value: %s", __FILENAMEW__, __FUNCTIONW__, __LINE__, AccountNameCopy, PasswordCopy);
		#else
		EventWriteStringW2(L"[%s:%s@%d] Attempting to SET password for user %s.", __FILENAMEW__, __FUNCTIONW__, __LINE__, AccountNameCopy);
		#endif
	}
	else
	{
		#ifdef DEBUG
		EventWriteStringW2(L"[%s:%s@%d] Attempting to CHANGE password for user %s to new value: %s", __FILENAMEW__, __FUNCTIONW__, __LINE__, AccountNameCopy, PasswordCopy);
		#else
		EventWriteStringW2(L"[%s:%s@%d] Attempting to CHANGE password for user %s.", __FILENAMEW__, __FUNCTIONW__, __LINE__, AccountNameCopy);
		#endif
	}

	if (Password->Length > 0) 
	{
		for (unsigned int Counter = 0; Counter < wcslen(PasswordCopy); Counter++)
		{
			PasswordCopy[Counter] = towlower(PasswordCopy[Counter]);
		}	
	}
	else
	{
		EventWriteStringW2(L"[%s:%s@%d] Empty password! Cannot continue.", __FILENAMEW__, __FUNCTIONW__, __LINE__);
		PasswordIsOK = FALSE;
		goto End;
	}

	while (CurrentNode != NULL && CurrentNode->Next != NULL)
	{
		CurrentNode = CurrentNode->Next;

		if (wcslen(CurrentNode->String) == 0)
		{
			EventWriteStringW2(L"[%s:%s@%d] ERROR: This blacklist token is 0 characters long. It will be skipped. Check your blacklist file for blank lines!", __FILENAMEW__, __FUNCTIONW__, __LINE__);
			continue;
		}

		if (wcsstr(PasswordCopy, CurrentNode->String))
		{
			if (((float)wcslen(CurrentNode->String) / (float)wcslen(PasswordCopy)) >= (float)gTokenPercentageOfPassword / 100)
			{
				EventWriteStringW2(L"[%s:%s@%d] Rejecting password because it contains the blacklisted string \"%s\" and it is at least %lu%% of the full password!", __FILENAMEW__, __FUNCTIONW__, __LINE__, CurrentNode->String, gTokenPercentageOfPassword);
				PasswordIsOK = FALSE;
				goto End;
			}
		}
	}

	for (unsigned int Character = 0; Character < wcslen(PasswordCopy); Character++)
	{
		if ((ContainsLower == FALSE) && (Password->Buffer[Character] >= 97) && (Password->Buffer[Character] <= 122))
		{
			EventWriteStringW2(L"[%s:%s@%d]\t - Found a lowercase letter.", __FILENAMEW__, __FUNCTIONW__, __LINE__);
			ContainsLower = TRUE;
		}

		if ((ContainsUpper == FALSE) && (Password->Buffer[Character] >= 65) && (Password->Buffer[Character] <= 90))
		{
			EventWriteStringW2(L"[%s:%s@%d]\t - Found an uppercase letter.", __FILENAMEW__, __FUNCTIONW__, __LINE__);
			ContainsUpper = TRUE;
		}

		if ((ContainsDigit == FALSE) && (Password->Buffer[Character] >= 48) && (Password->Buffer[Character] <= 57))
		{
			EventWriteStringW2(L"[%s:%s@%d]\t - Found a digit character.", __FILENAMEW__, __FUNCTIONW__, __LINE__);
			ContainsDigit = TRUE;
		}

		if ((ContainsSpecial == FALSE) && 
			((Password->Buffer[Character] >= 32 && Password->Buffer[Character] <= 47) || 
			(Password->Buffer[Character] >= 58 && Password->Buffer[Character] <= 64) ||
			(Password->Buffer[Character] >= 91 && Password->Buffer[Character] <= 96) ||
			(Password->Buffer[Character] >= 123 && Password->Buffer[Character] <= 126) ||
			(Password->Buffer[Character] >= 128 && Password->Buffer[Character] <= 255)))
		{
			EventWriteStringW2(L"[%s:%s@%d]\t - Found a special character.", __FILENAMEW__, __FUNCTIONW__, __LINE__);

			ContainsSpecial = TRUE;
		}

		if ((ContainsUnicode == FALSE) && (Password->Buffer[Character] > 255))
		{
			EventWriteStringW2(L"[%s:%s@%d]\t - Found a unicode character.", __FILENAMEW__, __FUNCTIONW__, __LINE__);
			ContainsUnicode = TRUE;
		}
	}

	if ((gRequireCharClasses & CHARACTER_CLASS_LOWERCASE) && (ContainsLower == FALSE))
	{
		if ((gRequireCharClasses & CHARACTER_CLASS_EITHER_UPPER_OR_LOWER) && (ContainsUpper == TRUE))
		{
			EventWriteStringW2(L"[%s:%s@%d] The %s registry key is set to require either uppercase or lowercase letters. Password contains uppercase letters but no lowercase letters. Password is OK so far.", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_REQUIRE_CHAR_CLASSES);
		}
		else
		{
			PasswordIsOK = FALSE;
			EventWriteStringW2(L"[%s:%s@%d] The %s registry key is set to require lowercase letters, but the password contained none.", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_REQUIRE_CHAR_CLASSES);
			goto End;
		}
	}

	if ((gRequireCharClasses & CHARACTER_CLASS_UPPERCASE) && (ContainsUpper == FALSE))
	{
		if ((gRequireCharClasses & CHARACTER_CLASS_EITHER_UPPER_OR_LOWER) && (ContainsLower == TRUE))
		{
			EventWriteStringW2(L"[%s:%s@%d] The %s registry key is set to require either uppercase or lowercase letters. Password contains lowercase letters but no uppercase letters. Password is OK so far.", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_REQUIRE_CHAR_CLASSES);
		}
		else
		{
			PasswordIsOK = FALSE;
			EventWriteStringW2(L"[%s:%s@%d] The %s registry key is set to require uppercase letters, but the password contained none.", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_REQUIRE_CHAR_CLASSES);
			goto End;
		}
	}

	if ((gRequireCharClasses & CHARACTER_CLASS_DIGIT) && ContainsDigit == FALSE)
	{
		PasswordIsOK = FALSE;
		EventWriteStringW2(L"[%s:%s@%d] The %s registry key is set to require digits, but the password contained none.", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_REQUIRE_CHAR_CLASSES);
		goto End;
	}

	if ((gRequireCharClasses & CHARACTER_CLASS_SPECIAL) && ContainsSpecial == FALSE)
	{
		PasswordIsOK = FALSE;
		EventWriteStringW2(L"[%s:%s@%d] The %s registry key is set to require special characters, but the password contained none.", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_REQUIRE_CHAR_CLASSES);
		goto End;
	}

	if ((gRequireCharClasses & CHARACTER_CLASS_UNICODE) && ContainsUnicode == FALSE)
	{
		PasswordIsOK = FALSE;
		EventWriteStringW2(L"[%s:%s@%d] The %s registry key is set to require unicode characters, but the password contained none.", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_REQUIRE_CHAR_CLASSES);
		goto End;
	}

	End:
	QueryPerformanceCounter(&EndTime);
	ElapsedMicroseconds.QuadPart = EndTime.QuadPart - StartTime.QuadPart;
	ElapsedMicroseconds.QuadPart *= 1000000;
	ElapsedMicroseconds.QuadPart /= gPerformanceFrequency.QuadPart;
	EventWriteStringW2(L"[%s:%s@%d] Finished in %llu microseconds. Will accept new password: %d", __FILENAMEW__, __FUNCTIONW__, __LINE__, ElapsedMicroseconds.QuadPart, PasswordIsOK);
	
	// NOTE: Despite what the MSDN documentation says, we should NOT be clearing the original password buffer that was passed in to us by Windows.
	// We only need to clear any _copies_ of the password that we have made.
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
			EventWriteStringW2(L"[%s:%s@%d] Failed to update configuration from registry! Something is very wrong!", __FILENAMEW__, __FUNCTIONW__, __LINE__);
			goto Sleep;
		}

		// We are being loaded by lsass.exe. The current working directory of lsass should be C:\Windows\System32
		if ((BlacklistFileHandle = CreateFile(gBlacklistFileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
		{
			wchar_t CurrentDir[MAX_PATH] = { 0 };
			GetCurrentDirectoryW(MAX_PATH, CurrentDir);
			EventWriteStringW2(L"[%s:%s@%d] Unable to open %s in directory %s! Error 0x%08lx", __FILENAMEW__, __FUNCTIONW__, __LINE__, gBlacklistFileName, CurrentDir, GetLastError());
			goto Sleep;
		}

		EventWriteStringW2(L"[%s:%s@%d] %s opened for read.", __FILENAMEW__, __FUNCTIONW__, __LINE__, gBlacklistFileName);
		if (GetFileTime(BlacklistFileHandle, NULL, NULL, &gBlackListNewFileTime) == 0)
		{
			EventWriteStringW2(L"[%s:%s@%d] Failed to call GetFileTime on %s! Error 0x%08lx", __FILENAMEW__, __FUNCTIONW__, __LINE__, gBlacklistFileName, GetLastError());
			goto Sleep;
		}

		if (CompareFileTime(&gBlackListNewFileTime, &gBlackListOldFileTime) != 0)
		{
			EventWriteStringW2(L"[%s:%s@%d] The last modified time of %s has changed since the last time we looked. Let's reload it.", __FILENAMEW__, __FUNCTIONW__, __LINE__, gBlacklistFileName);			
			// Initialize list head if we're here for the first time.
			if (gBlacklistHead == NULL)
			{
				if ((gBlacklistHead = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(BADSTRING))) == NULL)
				{
					EventWriteStringW2(L"[%s:%s@%d] ERROR: Failed to allocate memory for list head!", __FILENAMEW__, __FUNCTIONW__, __LINE__);
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
					EventWriteStringW2(L"[%s:%s@%d] HeapFree failed while clearing blacklist! Error 0x%08lx", __FILENAMEW__, __FUNCTIONW__, __LINE__, GetLastError());
					goto Sleep;
				}
			}

			// Create a new node for the first line of text in the file.
			if ((CurrentNode = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(BADSTRING))) == NULL)
			{
				EventWriteStringW2(L"[%s:%s@%d] ERROR: Failed to allocate memory for list node!", __FILENAMEW__, __FUNCTIONW__, __LINE__);
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
					EventWriteStringW2(L"[%s:%s@%d] WARNING: Line longer than max length of %d! Will truncate this line and attempt to resume reading the next line.", __FILENAMEW__, __FUNCTIONW__, __LINE__, MAX_BLACKLIST_STRING_SIZE);
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
						EventWriteStringW2(L"[%s:%s@%d] ERROR: Failed to allocate memory for list node!", __FILENAMEW__, __FUNCTIONW__, __LINE__);
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

			EventWriteStringW2(L"[%s:%s@%d] Read %lu bytes, %lu lines from file %s", __FILENAMEW__, __FUNCTIONW__, __LINE__, TotalBytesRead, LinesRead, gBlacklistFileName);
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
		EventWriteStringW2(L"[%s:%s@%d] Finished in %llu microseconds.", __FILENAMEW__, __FUNCTIONW__, __LINE__, ElapsedMicroseconds.QuadPart);
		LeaveCriticalSection(&gBlacklistCritSec);
		Sleep(BLACKLIST_THREAD_RUN_FREQUENCY);
	}

	return(0);
}

ULONG EventWriteStringW2(_In_ PCWSTR String, _In_ ...)
{
	wchar_t FormattedString[ETW_MAX_STRING_SIZE] = { 0 };
	va_list ArgPointer = NULL;
	va_start(ArgPointer, String);
	_vsnwprintf_s(FormattedString, sizeof(FormattedString) / sizeof(wchar_t), _TRUNCATE, String, ArgPointer);
	va_end(ArgPointer);	
#if DEBUG
	wprintf(L"%ls\r\n", FormattedString);	// Also print to console for easier debugging.
	OutputDebugStringW(FormattedString);	// Also print to DebugOut for easier debugging.
#endif
	return(EventWriteString(gEtwRegHandle, 0, 0, FormattedString));
}

DWORD UpdateConfigurationFromRegistry(void)
{
	DWORD Status = ERROR_SUCCESS;
	HKEY SubKeyHandle = NULL;
	DWORD SubKeyDisposition = 0;
	DWORD RegDataSize = 0;

	if ((Status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, FILTER_REG_SUBKEY, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &SubKeyHandle, &SubKeyDisposition)) != ERROR_SUCCESS)
	{
		EventWriteStringW2(L"[%s:%s@%d] Failed to open or create registry key HKLM\\%s! Error 0x%08lx", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_SUBKEY, Status);
		goto Exit;
	}

	if (SubKeyDisposition == REG_CREATED_NEW_KEY)
	{
		EventWriteStringW2(L"[%s:%s@%d] Created new registry subkey HKLM\\%s.", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_SUBKEY);
	}
	else if (SubKeyDisposition == REG_OPENED_EXISTING_KEY)
	{
		EventWriteStringW2(L"[%s:%s@%d] Opened existing registry subkey HKLM\\%s.", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_SUBKEY);
	}

	RegDataSize = (DWORD)sizeof(gBlacklistFileName);

	if ((Status = RegGetValueW(SubKeyHandle, NULL, FILTER_REG_BLACKLIST_FILENAME, RRF_RT_REG_SZ, NULL, &gBlacklistFileName, &RegDataSize)) != ERROR_SUCCESS)
	{
		if (Status == ERROR_FILE_NOT_FOUND)
		{
			EventWriteStringW2(L"[%s:%s@%d] Registry value %s was not found. Using previous value %s", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_BLACKLIST_FILENAME, gBlacklistFileName);
			Status = ERROR_SUCCESS;
		}
		else
		{
			EventWriteStringW2(L"[%s:%s@%d] Failed to read registry value %s! Error 0x%08lx", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_BLACKLIST_FILENAME, Status);			
		}
	}
	else
	{
		EventWriteStringW2(L"[%s:%s@%d] Successfully read registry value %s. Data: %s", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_BLACKLIST_FILENAME, gBlacklistFileName);

		if (wcslen(gBlacklistFileName) == 0)
		{
			EventWriteStringW2(L"[%s:%s@%d] WARNING: %s was blank!", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_BLACKLIST_FILENAME);
		}
	}	

	RegDataSize = (DWORD)sizeof(DWORD);	

	if ((Status = RegGetValueW(SubKeyHandle, NULL, FILTER_REG_TOKEN_PERCENTAGE_OF_PASSWORD, RRF_RT_DWORD, NULL, &gTokenPercentageOfPassword, &RegDataSize)) != ERROR_SUCCESS)
	{
		if (Status == ERROR_FILE_NOT_FOUND)
		{
			EventWriteStringW2(L"[%s:%s@%d] Registry value %s was not found. Using previous value %lu", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_TOKEN_PERCENTAGE_OF_PASSWORD, gTokenPercentageOfPassword);
			Status = ERROR_SUCCESS;
		}
		else
		{
			EventWriteStringW2(L"[%s:%s@%d] Failed to read registry value %s! Error 0x%08lx", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_TOKEN_PERCENTAGE_OF_PASSWORD, Status);			
		}
	}
	else
	{
		EventWriteStringW2(L"[%s:%s@%d] Successfully read registry value %s. Data: %lu", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_TOKEN_PERCENTAGE_OF_PASSWORD, gTokenPercentageOfPassword);

		if (gTokenPercentageOfPassword > 100)
		{
			EventWriteStringW2(L"[%s:%s@%d] WARNING: %s was greater than 100%%, which does not make sense. Defaulting to 60%%.", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_TOKEN_PERCENTAGE_OF_PASSWORD);
			gTokenPercentageOfPassword = 60;
		}
	}

	RegDataSize = (DWORD)sizeof(DWORD);

	if ((Status = RegGetValueW(SubKeyHandle, NULL, FILTER_REG_REQUIRE_CHAR_CLASSES, RRF_RT_DWORD, NULL, &gRequireCharClasses, &RegDataSize)) != ERROR_SUCCESS)
	{
		if (Status == ERROR_FILE_NOT_FOUND)
		{
			EventWriteStringW2(L"[%s:%s@%d] Registry value %s was not found. Using previous value %lu", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_REQUIRE_CHAR_CLASSES, gRequireCharClasses);
			Status = ERROR_SUCCESS;
		}
		else
		{
			EventWriteStringW2(L"[%s:%s@%d] Failed to read registry value %s! Error 0x%08lx", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_REQUIRE_CHAR_CLASSES, Status);
		}
	}
	else
	{
		EventWriteStringW2(L"[%s:%s@%d] Successfully read registry value %s. Data: %lu", __FILENAMEW__, __FUNCTIONW__, __LINE__, FILTER_REG_REQUIRE_CHAR_CLASSES, gRequireCharClasses);
	}

Exit:

	if (SubKeyHandle != NULL)
	{
		RegCloseKey(SubKeyHandle);
	}

	EventWriteStringW2(L"[%s:%s@%d] Returning 0x%08lx", __FILENAMEW__, __FUNCTIONW__, __LINE__, Status);
	return(Status);
}
