// PassFiltExTest.c
// Joseph Ryan Ries - 2022
// For testing the PassFiltEx Active Directory Password Filter without having to install it on a domain controller.
//
// Usage:
//   PassFiltExTest.exe <username>
//     Type a password, and the program prints PASS if the filter would accept it, or FAIL if not.
//     Passwords can also be piped in, one per line, as UTF-8 text. The program exits at the end of the input.
//   PassFiltExTest.exe <username> --edgecases [number]
//     Calls the filter with unusual or malformed input that it must handle without crashing, such as
//     NULL pointers, very long strings and strings that contain null characters, and prints the results.
//     Give a case number to run only that case.
#pragma comment(lib, "Advapi32.lib")
#include <Windows.h>
#include <subauth.h>
#include <stdio.h>
#include <stdlib.h>
#include <io.h>
#include <fcntl.h>

typedef BOOL(CALLBACK* _PasswordFilter)(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOL SetOperation);
typedef BOOL(CALLBACK* _InitializeChangeNotify)(void);
typedef LONG(CALLBACK* _PasswordChangeNotify)(PUNICODE_STRING UserName, ULONG RelativeId, PUNICODE_STRING NewPassword);

#define EDGE_CASE_COUNT 24
// The longest string that a UNICODE_STRING can hold, in characters.
#define MAX_UNICODE_STRING_CHARS 32767

static _PasswordFilter PasswordFilter;
static _PasswordChangeNotify PasswordChangeNotify;

BOOL IsElevated(void) 
{
	BOOL Result = FALSE;
	HANDLE Token = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &Token)) 
	{
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);

		if (GetTokenInformation(Token, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) 
		{
			Result = Elevation.TokenIsElevated;
		}
	}
	
	if (Token) 
	{
		CloseHandle(Token);
	}

	return Result;
}

// Copies Length bytes into a new heap buffer that is exactly that big, with no null terminator, which is how LSA
// passes strings to password filters. Run this program with page heap or ASan enabled, and any attempt by the
// filter to read past the end of a string will crash right away instead of going unnoticed.
static BOOL MakeUnicodeString(_Out_ PUNICODE_STRING String, _In_reads_bytes_(Length) const void* Source, _In_ USHORT Length)
{
	String->Length = Length;
	String->MaximumLength = Length;

	if ((String->Buffer = HeapAlloc(GetProcessHeap(), 0, Length)) == NULL)
	{
		return(FALSE);
	}

	memcpy(String->Buffer, Source, Length);
	return(TRUE);
}

// Makes a UNICODE_STRING that is Count characters long by repeating Pattern.
static BOOL MakeRepeatedString(_Out_ PUNICODE_STRING String, _In_z_ const wchar_t* Pattern, _In_ size_t Count)
{
	BOOL Result = FALSE;
	size_t PatternLength = wcslen(Pattern);
	wchar_t* Temp = HeapAlloc(GetProcessHeap(), 0, (Count + 1) * sizeof(wchar_t));

	if (Temp == NULL)
	{
		String->Buffer = NULL;
		return(FALSE);
	}

	for (size_t Index = 0; Index < Count; Index++)
	{
		Temp[Index] = Pattern[Index % PatternLength];
	}

	Result = MakeUnicodeString(String, Temp, (USHORT)(Count * sizeof(wchar_t)));
	HeapFree(GetProcessHeap(), 0, Temp);
	return(Result);
}

static void FreeUnicodeString(_Inout_ PUNICODE_STRING String)
{
	if (String->Buffer != NULL)
	{
		SecureZeroMemory(String->Buffer, String->MaximumLength);
		HeapFree(GetProcessHeap(), 0, String->Buffer);
		String->Buffer = NULL;
	}

	String->Length = 0;
	String->MaximumLength = 0;
}

static int RunEdgeCases(_In_ PUNICODE_STRING TestUser, _In_ int OnlyCase)
{
	// This password has every kind of character and no sequences or repeats, so it passes every rule.
	static const wchar_t GoodPassword[] = L"Xq7#Lm2$";
	// The sample blocklist and the README both use starwars as an example.
	static const wchar_t WeakPassword[] = L"starwars";
	static const wchar_t NullThenWeakPassword[] = L"\0starwars";
	static const wchar_t NullInMiddlePassword[] = L"Xq7#\0Lm2$";
	static const wchar_t KrbtgtWithNull[] = L"krbtgt\0evil";

	for (int Case = 1; Case <= EDGE_CASE_COUNT; Case++)
	{
		UNICODE_STRING Account = { 0 };
		UNICODE_STRING Password = { 0 };
		UNICODE_STRING FullName = { 0 };
		PUNICODE_STRING AccountArg = TestUser;
		PUNICODE_STRING PasswordArg = &Password;
		const wchar_t* Description = NULL;
		BOOL Notify = FALSE;
		BOOL Ready = TRUE;

		if ((OnlyCase != 0) && (Case != OnlyCase))
		{
			continue;
		}

		switch (Case)
		{
			case 1:
				Description = L"PasswordFilter: AccountName is NULL";
				AccountArg = NULL;
				Ready = MakeUnicodeString(&Password, GoodPassword, sizeof(GoodPassword) - sizeof(wchar_t));
				break;
			case 2:
				Description = L"PasswordFilter: Password is NULL";
				PasswordArg = NULL;
				break;
			case 3:
				Description = L"PasswordFilter: Password.Buffer is NULL and Length is 0";
				break;
			case 4:
				Description = L"PasswordFilter: Password.Buffer is NULL but Length is 16";
				Password.Length = 16;
				Password.MaximumLength = 16;
				break;
			case 5:
				Description = L"PasswordFilter: AccountName.Buffer is NULL but Length is 16";
				Account.Length = 16;
				Account.MaximumLength = 16;
				AccountArg = &Account;
				Ready = MakeUnicodeString(&Password, GoodPassword, sizeof(GoodPassword) - sizeof(wchar_t));
				break;
			case 6:
				Description = L"PasswordFilter: empty password";
				Ready = MakeUnicodeString(&Password, L"", 0);
				break;
			case 7:
				Description = L"PasswordFilter: 1-character password";
				Ready = MakeUnicodeString(&Password, L"a", 1 * sizeof(wchar_t));
				break;
			case 8:
				Description = L"PasswordFilter: 2-character password";
				Ready = MakeUnicodeString(&Password, L"ab", 2 * sizeof(wchar_t));
				break;
			case 9:
				Description = L"PasswordFilter: password with an odd number of bytes";
				Ready = MakeUnicodeString(&Password, GoodPassword, sizeof(GoodPassword) - sizeof(wchar_t) + 1);
				break;
			case 10:
				Description = L"PasswordFilter: 256-character password";
				Ready = MakeRepeatedString(&Password, GoodPassword, 256);
				break;
			case 11:
				Description = L"PasswordFilter: 257-character password";
				Ready = MakeRepeatedString(&Password, GoodPassword, 257);
				break;
			case 12:
				Description = L"PasswordFilter: 32767-character password";
				Ready = MakeRepeatedString(&Password, GoodPassword, MAX_UNICODE_STRING_CHARS);
				break;
			case 13:
				Description = L"PasswordFilter: password is a null character followed by a blocklisted string";
				Ready = MakeUnicodeString(&Password, NullThenWeakPassword, sizeof(NullThenWeakPassword) - sizeof(wchar_t));
				break;
			case 14:
				Description = L"PasswordFilter: password with a null character in the middle";
				Ready = MakeUnicodeString(&Password, NullInMiddlePassword, sizeof(NullInMiddlePassword) - sizeof(wchar_t));
				break;
			case 15:
				Description = L"PasswordFilter: 256-character account name";
				AccountArg = &Account;
				Ready = MakeRepeatedString(&Account, L"user", 256) && MakeUnicodeString(&Password, GoodPassword, sizeof(GoodPassword) - sizeof(wchar_t));
				break;
			case 16:
				Description = L"PasswordFilter: 257-character account name";
				AccountArg = &Account;
				Ready = MakeRepeatedString(&Account, L"user", 257) && MakeUnicodeString(&Password, GoodPassword, sizeof(GoodPassword) - sizeof(wchar_t));
				break;
			case 17:
				Description = L"PasswordFilter: 32767-character account name";
				AccountArg = &Account;
				Ready = MakeRepeatedString(&Account, L"user", MAX_UNICODE_STRING_CHARS) && MakeUnicodeString(&Password, GoodPassword, sizeof(GoodPassword) - sizeof(wchar_t));
				break;
			case 18:
				Description = L"PasswordFilter: account name is krbtgt, a null character, and more text, with a blocklisted password";
				AccountArg = &Account;
				Ready = MakeUnicodeString(&Account, KrbtgtWithNull, sizeof(KrbtgtWithNull) - sizeof(wchar_t)) && MakeUnicodeString(&Password, WeakPassword, sizeof(WeakPassword) - sizeof(wchar_t));
				break;
			case 19:
				Description = L"PasswordFilter: account name krbtgt with a blocklisted password";
				AccountArg = &Account;
				Ready = MakeUnicodeString(&Account, L"krbtgt", 6 * sizeof(wchar_t)) && MakeUnicodeString(&Password, WeakPassword, sizeof(WeakPassword) - sizeof(wchar_t));
				break;
			case 20:
				Description = L"PasswordFilter: account name krbtgt_12345 (an RODC's krbtgt) with a blocklisted password";
				AccountArg = &Account;
				Ready = MakeUnicodeString(&Account, L"krbtgt_12345", 12 * sizeof(wchar_t)) && MakeUnicodeString(&Password, WeakPassword, sizeof(WeakPassword) - sizeof(wchar_t));
				break;
			case 21:
				Description = L"PasswordFilter: account name krbtgt_evil with a blocklisted password";
				AccountArg = &Account;
				Ready = MakeUnicodeString(&Account, L"krbtgt_evil", 11 * sizeof(wchar_t)) && MakeUnicodeString(&Password, WeakPassword, sizeof(WeakPassword) - sizeof(wchar_t));
				break;
			case 22:
				Description = L"PasswordChangeNotify: UserName and NewPassword are NULL";
				Notify = TRUE;
				AccountArg = NULL;
				PasswordArg = NULL;
				break;
			case 23:
				Description = L"PasswordChangeNotify: 32767-character user name";
				Notify = TRUE;
				AccountArg = &Account;
				Ready = MakeRepeatedString(&Account, L"user", MAX_UNICODE_STRING_CHARS) && MakeUnicodeString(&Password, GoodPassword, sizeof(GoodPassword) - sizeof(wchar_t));
				break;
			case 24:
				Description = L"PasswordChangeNotify: UserName.Buffer is NULL but Length is 16";
				Notify = TRUE;
				Account.Length = 16;
				Account.MaximumLength = 16;
				AccountArg = &Account;
				PasswordArg = NULL;
				break;
		}

		if (Ready == FALSE)
		{
			wprintf_s(L"EDGE %2d: Out of memory!\n", Case);
			return(1);
		}

		// Print the description first, so that if the filter crashes, it's clear which case did it.
		wprintf_s(L"EDGE %2d: %s\n", Case, Description);
		fflush(stdout);

		if (Notify)
		{
			wprintf_s(L"EDGE %2d RESULT: 0x%08lx\n", Case, (unsigned long)PasswordChangeNotify(AccountArg, 1234, PasswordArg));
		}
		else
		{
			wprintf_s(L"EDGE %2d RESULT: %s\n", Case, PasswordFilter(AccountArg, &FullName, PasswordArg, TRUE) ? L"TRUE" : L"FALSE");
		}
		fflush(stdout);

		FreeUnicodeString(&Account);
		FreeUnicodeString(&Password);
	}

	wprintf_s(L"EDGE CASES COMPLETED\n");
	return(0);
}

int wmain(int argc, wchar_t* argv[])
{
	HMODULE DllHandle = NULL;
	_InitializeChangeNotify InitializeChangeNotify = NULL;
	UNICODE_STRING TestUser = { 0 };
	UNICODE_STRING FullName = { 0 };
	BOOL EdgeCases = FALSE;
	int OnlyCase = 0;
	size_t UserNameLength = 0;
	// Room for the longest password that a UNICODE_STRING can hold, plus a newline and the null terminator.
	static wchar_t Line[MAX_UNICODE_STRING_CHARS + 2];

	if ((argc < 2) || (argc > 4) || ((argc >= 3) && (_wcsicmp(argv[2], L"--edgecases") != 0)))
	{
		wprintf_s(L"Must supply username!\n");
		wprintf_s(L"Usage: PassFiltExTest.exe <username> [--edgecases [number]]\n");
		return(1);
	}

	if (argc >= 3)
	{
		EdgeCases = TRUE;
		if (argc == 4)
		{
			OnlyCase = _wtoi(argv[3]);
		}
	}

	UserNameLength = wcslen(argv[1]);
	if (UserNameLength > 256)
	{
		wprintf_s(L"The username is too long!\n");
		return(1);
	}

	if (MakeUnicodeString(&TestUser, argv[1], (USHORT)(UserNameLength * sizeof(wchar_t))) == FALSE)
	{
		wprintf_s(L"Out of memory!\n");
		return(1);
	}

	wprintf_s(L"PassFiltExTest - Press Ctrl+C to quit.\n");
	wprintf_s(L"*** This program is for testing purposes only! ***\n");

	if (IsElevated() == FALSE)
	{
		wprintf_s(L"ERROR: You must run this app as administrator!\n");
		return(1);
	}

	if ((DllHandle = LoadLibraryW(L"PassFiltEx.dll")) == NULL)
	{
		DWORD LastError = GetLastError();
		wprintf_s(L"LoadLibraryW(\"PassFiltEx.dll\") failed with error 0x%08lx!\n", LastError);
		if (LastError == ERROR_MOD_NOT_FOUND)
		{
			wprintf_s(L"Make sure the filter DLL is in the same directory.\n");
		}
		return(1);
	}

	if ((PasswordFilter = (_PasswordFilter)GetProcAddress(DllHandle, "PasswordFilter")) == NULL)
	{
		wprintf_s(L"GetProcAddress(DllHandle, \"PasswordFilter\") failed with 0x%08lx!\n", GetLastError());
		return(1);
	}

	if ((InitializeChangeNotify = (_InitializeChangeNotify)GetProcAddress(DllHandle, "InitializeChangeNotify")) == NULL)
	{
		wprintf_s(L"GetProcAddress(DllHandle, \"InitializeChangeNotify\") failed with 0x%08lx!\n", GetLastError());
		return(1);
	}

	if ((PasswordChangeNotify = (_PasswordChangeNotify)GetProcAddress(DllHandle, "PasswordChangeNotify")) == NULL)
	{
		wprintf_s(L"GetProcAddress(DllHandle, \"PasswordChangeNotify\") failed with 0x%08lx!\n", GetLastError());
		return(1);
	}

	if (InitializeChangeNotify() == FALSE)
	{
		wprintf_s(L"InitializeChangeNotify failed! LSA would not use this password filter.\n");
		return(1);
	}

	if (EdgeCases)
	{
		return(RunEdgeCases(&TestUser, OnlyCase));
	}

	// Read piped or redirected input as UTF-8, so that passwords with Unicode characters can be tested.
	// Console input is left alone.
	if (GetFileType(GetStdHandle(STD_INPUT_HANDLE)) != FILE_TYPE_CHAR)
	{
		(void)_setmode(_fileno(stdin), _O_U8TEXT);
	}

	while (TRUE)
	{
		UNICODE_STRING NewPassword = { 0 };
		size_t Length = 0;
		BOOL LineComplete = FALSE;

		wprintf_s(L"Password:");
		if (fgetws(Line, ARRAYSIZE(Line), stdin) == NULL)
		{
			// End of input.
			wprintf_s(L"\n");
			break;
		}

		// fgetws keeps the newline at the end of the line, but it's not part of the password.
		Length = wcslen(Line);
		LineComplete = (((Length > 0) && (Line[Length - 1] == L'\n')) || feof(stdin));
		while ((Length > 0) && ((Line[Length - 1] == L'\n') || (Line[Length - 1] == L'\r')))
		{
			Line[--Length] = L'\0';
		}

		if ((LineComplete == FALSE) || (Length > MAX_UNICODE_STRING_CHARS))
		{
			// The password doesn't fit. Skip the rest of the line instead of testing the pieces as separate passwords.
			while ((LineComplete == FALSE) && (fgetws(Line, ARRAYSIZE(Line), stdin) != NULL))
			{
				size_t Remaining = wcslen(Line);
				LineComplete = ((Remaining > 0) && (Line[Remaining - 1] == L'\n'));
			}
			wprintf_s(L"TOO LONG (the maximum is %d characters)\n", MAX_UNICODE_STRING_CHARS);
			fflush(stdout);
			SecureZeroMemory(Line, sizeof(Line));
			continue;
		}

		if (MakeUnicodeString(&NewPassword, Line, (USHORT)(Length * sizeof(wchar_t))) == FALSE)
		{
			wprintf_s(L"Out of memory!\n");
			break;
		}

		if (PasswordFilter(&TestUser, &FullName, &NewPassword, TRUE) == TRUE)
		{
			wprintf_s(L"PASS\n");
		}
		else
		{
			wprintf_s(L"FAIL\n");
		}
		fflush(stdout);

		FreeUnicodeString(&NewPassword);
		SecureZeroMemory(Line, sizeof(Line));
	}

	FreeUnicodeString(&TestUser);
	return(0);
}
