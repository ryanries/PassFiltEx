// PassFiltExTest.c
// Joseph Ryan Ries - 2022
// For testing the PassFiltEx Active Directory Password Filter without having 
#pragma comment(lib, "Advapi32.lib")
#include <Windows.h>
#include <subauth.h>
#include <stdio.h>

typedef long long(CALLBACK* _PasswordFilter)(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOL SetOperation);
typedef long long(CALLBACK* _InitializeChangeNotify)(void);

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



int wmain(int argc, wchar_t* argv[])
{
	HANDLE DllHandle = NULL;
	_PasswordFilter PasswordFilter = NULL;
	_InitializeChangeNotify InitializeChangeNotify = NULL;

	if (argc != 2)
	{
		wprintf_s(L"Must supply username!\n");
		return(0);
	}

	UNICODE_STRING TestUser = { 0 };	
	TestUser.Buffer = argv[1];
	TestUser.Length = wcslen(argv[1]) * sizeof(wchar_t);
	TestUser.Length = wcslen(argv[1]) * sizeof(wchar_t);

	UNICODE_STRING FullName = { 0 };

	wprintf_s(L"PassFiltExTest - Press Ctrl+C to quit.\n");
	wprintf_s(L"*** This program is for testing purposes only! ***\n");

	if (IsElevated() == FALSE)
	{
		wprintf_s(L"ERROR: You must run this app as administrator!\n");
		return(0);
	}

	if ((DllHandle = LoadLibraryW(L"PassFiltEx.dll")) == NULL)
	{
		wprintf_s(L"LoadLibraryW(\"PassFiltEx.dll\") failed with error 0x%08lx!\n", GetLastError());
		if (GetLastError() == ERROR_MOD_NOT_FOUND)
		{
			wprintf_s(L"Make sure the filter DLL is in the same directory.\n");
		}
		return(0);
	}

	if ((PasswordFilter = (_PasswordFilter)GetProcAddress(DllHandle, "PasswordFilter")) == NULL)
	{
		wprintf_s(L"GetProcAddress(DllHandle, \"PasswordFilter\" failed with 0x%08lx!\n", GetLastError());
		return(0);
	}

	if ((InitializeChangeNotify = (_InitializeChangeNotify)GetProcAddress(DllHandle, "InitializeChangeNotify")) == NULL)
	{
		wprintf_s(L"GetProcAddress(DllHandle, \"InitializeChangeNotify\" failed with 0x%08lx!\n", GetLastError());
		return(0);
	}

	InitializeChangeNotify();
	
	while (TRUE)
	{
		UNICODE_STRING NewPassword = { .Buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 512), .Length = 0, .MaximumLength = 512 };
		wprintf_s(L"Password:");		
		fgetws(NewPassword.Buffer, 256, stdin);
		NewPassword.Length = (USHORT)wcslen(NewPassword.Buffer) * sizeof(wchar_t);

		if (PasswordFilter(&TestUser, &FullName, &NewPassword, TRUE) == TRUE)
		{
			wprintf_s(L"PASS\n");
		}
		else
		{
			wprintf_s(L"FAIL\n");
		}

		if (NewPassword.Buffer)
		{
			HeapFree(GetProcessHeap(), 0, NewPassword.Buffer);
		}
	}

	return(0);
}
