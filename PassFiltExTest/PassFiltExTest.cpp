// PassFiltExTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include <string>

#include <Windows.h>
#include <SubAuth.h>
extern "C" {
#include <PassFiltEx.h>
}

UNICODE_STRING toUnicodeString(const std::wstring& str) {
	UNICODE_STRING lsaWStr;
	DWORD len = 0;

	len = str.length();
	LPWSTR cstr = new WCHAR[len + 1];
	memcpy(cstr, str.c_str(), (len + 1) * sizeof(WCHAR));
	lsaWStr.Buffer = cstr;
	lsaWStr.Length = (USHORT)((len) * sizeof(WCHAR));
	lsaWStr.MaximumLength = (USHORT)((len + 1) * sizeof(WCHAR));
	return lsaWStr;
}

void freeUnicodeString(UNICODE_STRING& str) {
	delete[] str.Buffer;
	str.Buffer = 0;
	str.Length = 0;
	str.MaximumLength = 0;
}

int main(int argc, char **argv)
{
	std::wstring value;
	UNICODE_STRING accountName = toUnicodeString(L"TestAccount");
	UNICODE_STRING fullName = toUnicodeString(L"TestFullName");
	InitializeChangeNotify();
	while (std::getline(std::wcin, value)) {
		UNICODE_STRING u = toUnicodeString(value);
		std::wcout << L"Running PasswordFilter on " << value << std::endl;
		if (PasswordFilter(&accountName, &fullName, &u, 0)) {
			std::wcout << L"Password allowed" << std::endl;
		}
		else {
			std::wcout << L"Password denied" << std::endl;
		}
		freeUnicodeString(u);
	}
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
