/*
 *  File: DemonionRedirect.cpp
 *  Copyright (c) 2025 Sinflower
 *
 *  MIT License
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 *
 */

#include <fstream>
#include <stdio.h>
#include <vector>
#include <windows.h>

#include <detours.h>
#include <nlohmann/json.hpp>

#include "Utils.hpp"

#include "Logging.hpp"

//////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////

VOID DetAttach(PVOID* ppbReal, PVOID pbMine, const char* psz);
VOID DetDetach(PVOID* ppbReal, PVOID pbMine, const char* psz);

#define ATTACH(x) DetAttach(&(PVOID&)Real_##x, Mine_##x, #x)
#define DETACH(x) DetDetach(&(PVOID&)Real_##x, Mine_##x, #x)

nlohmann::json g_translations;

static const std::string TRANSLATIONS_FILE = "tr.json";

static const std::vector<BYTE> EXE_STRING_FUNC = { 0x53, 0x56, 0x8B, 0xF1, 0x8B, 0x4C, 0x24, 0x0C, 0x57, 0x85, 0xC9, 0x74, 0x49, 0x8B, 0x7E, 0x18, 0x8D, 0x46, 0x04, 0x83, 0xFF, 0x08, 0x72, 0x04, 0x8B, 0x10, 0xEB, 0x02, 0x8B, 0xD0, 0x3B, 0xCA, 0x72, 0x34, 0x83, 0xFF, 0x08, 0x72, 0x04, 0x8B, 0x10, 0xEB, 0x02, 0x8B, 0xD0, 0x8B, 0x5E, 0x14, 0x8D, 0x14, 0x5A, 0x3B, 0xD1, 0x76, 0x1F, 0x83, 0xFF, 0x08, 0x72, 0x02, 0x8B, 0x00, 0x8B, 0x54, 0x24, 0x14, 0x2B, 0xC8, 0x52, 0xD1, 0xF9, 0x51, 0x56, 0x8B, 0xCE, 0xE8, 0x00, 0xFD, 0xFF, 0xFF };

// RVA Offsets for the SEH functions to hook
static const uint32_t EXE_STRING_FUNC_2_OFFSET  = 0x1CF050;
static const uint32_t FORMAT_STRING_FUNC_OFFSET = 0x1C2C40;

//////////////////////////////////////////////////////////////////////////////
//
// Real function pointers for detoured functions

extern "C"
{
	DWORD*(__fastcall* Real_ExeStringFunc)(DWORD* a1, int32_t a2, BYTE* Source, uint32_t a4)                       = nullptr;
	int*(__cdecl* Real_ExeStringFunc2)(int* a1, int a2, WORD* a3, int* a4, int a5, int a6, int a7, int a8, int a9) = nullptr;
	int(WINAPI* Real_FormatStringFunc)(int a1, wchar_t* Format, ...)                                               = nullptr;
}

//
//
//////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////
// Detours
//

DWORD* __fastcall Mine_ExeStringFunc(DWORD* a1, int32_t a2, BYTE* pSource, uint32_t a4)
{
	std::wstring unicodeStr = reinterpret_cast<const wchar_t*>(pSource);
	std::string utf8String  = unicode2utf8(unicodeStr);

	// Check if this string exists in the translations
	if (g_translations.contains(utf8String))
	{
		const std::string trStr = g_translations[utf8String].get<std::string>();
		if (trStr == "")
			return Real_ExeStringFunc(a1, a2, pSource, a4);

#if INCLUDE_DEBUG_LOGGING
		//_Print("Using Translated String: %s\n", trStr.c_str());
#endif

		unicodeStr = utf82unicode(trStr);
		return Real_ExeStringFunc(a1, a2, reinterpret_cast<BYTE*>(const_cast<wchar_t*>(unicodeStr.c_str())), unicodeStr.size());
	}
	else
		return Real_ExeStringFunc(a1, a2, pSource, a4);
}

int* __cdecl Mine_ExeStringFunc2(int* a1, int a2, WORD* a3, int* a4, int a5, int a6, int a7, int a8, int a9)
{
	std::wstring unicodeStr = reinterpret_cast<const wchar_t*>(a3);
	std::string utf8String  = unicode2utf8(unicodeStr);

	// Check if this string exists in the translations
	if (g_translations.contains(utf8String))
	{
		const std::string trStr = g_translations[utf8String].get<std::string>();
		if (trStr == "")
			return Real_ExeStringFunc2(a1, a2, a3, a4, a5, a6, a7, a8, a9);

#if INCLUDE_DEBUG_LOGGING
		//_Print("Using Translated String: %s\n", trStr.c_str());
#endif

		unicodeStr = utf82unicode(trStr);
		return Real_ExeStringFunc2(a1, a2, reinterpret_cast<WORD*>(const_cast<wchar_t*>(unicodeStr.c_str())), a4, a5, a6, a7, a8, a9);
	}
	else
		return Real_ExeStringFunc2(a1, a2, a3, a4, a5, a6, a7, a8, a9);
}

int WINAPI Mine_FormatStringFunc(int a1, wchar_t* Format, ...)
{
	const std::size_t BUFFER_SIZE = 4096;
	wchar_t buffer[BUFFER_SIZE];
	std::string utf8FmtStr = unicode2utf8(Format);
	std::wstring fmtStr    = Format;

	if (g_translations.contains(utf8FmtStr))
	{
		const std::string trStr = g_translations[utf8FmtStr].get<std::string>();
		if (trStr != "")
		{
			fmtStr = utf82unicode(trStr);
#if INCLUDE_DEBUG_LOGGING
			//_Print("Using Translated Format String: %s\n", trStr.c_str());
#endif
		}
	}

	va_list args;
	va_start(args, Format);
	_vsnwprintf_s(buffer, BUFFER_SIZE, fmtStr.c_str(), args);
	va_end(args);
	int result = Real_FormatStringFunc(a1, buffer);
	return result;
}

//
// Detours
//////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////
// AttachDetours
//
PCHAR DetRealName(const char* psz)
{
	PCHAR locPsz = const_cast<PCHAR>(psz);
	PCHAR pszBeg = const_cast<PCHAR>(psz);
	// Move to end of name.
	while (*locPsz)
		locPsz++;

	// Move back through A-Za-z0-9 names.
	while (locPsz > pszBeg && ((locPsz[-1] >= 'A' && locPsz[-1] <= 'Z') || (locPsz[-1] >= 'a' && locPsz[-1] <= 'z') || (locPsz[-1] >= '0' && locPsz[-1] <= '9')))
		locPsz--;

	return locPsz;
}

VOID DetAttach(PVOID* ppbReal, PVOID pbMine, const char* psz)
{
	if (*ppbReal == nullptr || pbMine == nullptr)
	{
#if INCLUDE_DEBUG_LOGGING
		if (ppbReal == nullptr)
			Syelog(SYELOG_SEVERITY_NOTICE, "Attach failed: `%s': ppbReal is nullptr\n", DetRealName(psz));
		if (pbMine == nullptr)
			Syelog(SYELOG_SEVERITY_NOTICE, "Attach failed: `%s': pbMine is nullptr\n", DetRealName(psz));
#endif

		return;
	}

	LONG l = DetourAttach(ppbReal, pbMine);
#if INCLUDE_DEBUG_LOGGING
	if (l != 0)
		Syelog(SYELOG_SEVERITY_NOTICE, "Attach failed: `%s': error %d\n", DetRealName(psz), l);
#endif
}

VOID DetDetach(PVOID* ppbReal, PVOID pbMine, const char* psz)
{
	if (*ppbReal == nullptr || pbMine == nullptr)
	{
#if INCLUDE_DEBUG_LOGGING
		if (ppbReal == nullptr)
			Syelog(SYELOG_SEVERITY_NOTICE, "Detach failed: `%s': ppbReal is nullptr\n", DetRealName(psz));
		if (pbMine == nullptr)
			Syelog(SYELOG_SEVERITY_NOTICE, "Detach failed: `%s': pbMine is nullptr\n", DetRealName(psz));
#endif
		return;
	}

	LONG l = DetourDetach(ppbReal, pbMine);
#if INCLUDE_DEBUG_LOGGING
	if (l != 0)
		Syelog(SYELOG_SEVERITY_NOTICE, "Detach failed: `%s': error %d\n", DetRealName(psz), l);
#endif
}

LONG AttachDetours(VOID)
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	ATTACH(ExeStringFunc);
	ATTACH(ExeStringFunc2);
	ATTACH(FormatStringFunc);

	return DetourTransactionCommit();
}

LONG DetachDetours(VOID)
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	DETACH(ExeStringFunc);
	DETACH(ExeStringFunc2);
	DETACH(FormatStringFunc);

	return DetourTransactionCommit();
}

//
//////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////
//
// DLL module information
//
BOOL ThreadAttach([[maybe_unused]] HMODULE hDll)
{
#if INCLUDE_DEBUG_LOGGING
	logging::ThreadAttach();
#endif

	return TRUE;
}

BOOL ThreadDetach([[maybe_unused]] HMODULE hDll)
{
#if INCLUDE_DEBUG_LOGGING
	logging::ThreadDetach();
#endif

	return TRUE;
}

template<typename T>
void SetupHook(T& realFuncPtr, const std::vector<BYTE>& funcBytes, const char* funcName)
{
	realFuncPtr        = nullptr;
	uintptr_t funcAddr = findFunction(funcBytes);

	if (funcAddr == ~0)
	{
#if INCLUDE_DEBUG_LOGGING
		Syelog(SYELOG_SEVERITY_FATAL, "### Error: Unable to find the %s function\n", funcName);
#endif
		return;
	}
	else
	{
#if INCLUDE_DEBUG_LOGGING
		Syelog(SYELOG_SEVERITY_INFORMATION, "### Found %s function at address: 0x%p\n", funcName, reinterpret_cast<void*>(funcAddr));
#endif
	}

	realFuncPtr = reinterpret_cast<T>(funcAddr);
}

template<typename T>
void SetupHook(T& realFuncPtr, const uint32_t& funcOffset, const char* funcName)
{
	realFuncPtr        = nullptr;
	uintptr_t funcAddr = calcFunctionAddress(funcOffset);

	if (funcAddr == ~0)
	{
#if INCLUDE_DEBUG_LOGGING
		Syelog(SYELOG_SEVERITY_FATAL, "### Error: Unable to find the %s function\n", funcName);
#endif
		return;
	}
	else
	{
#if INCLUDE_DEBUG_LOGGING
		Syelog(SYELOG_SEVERITY_INFORMATION, "### Found %s function at address: 0x%p\n", funcName, reinterpret_cast<void*>(funcAddr));
#endif
	}

	realFuncPtr = reinterpret_cast<T>(funcAddr);
}

BOOL ProcessAttach(HMODULE hDll)
{
#if INCLUDE_DEBUG_LOGGING
	WCHAR wzExeName[MAX_PATH];

	GetModuleFileNameW(NULL, wzExeName, ARRAYSIZE(wzExeName));

	SyelogOpen("demon" DETOURS_STRINGIFY(DETOURS_BITS), SYELOG_FACILITY_APPLICATION);
	Syelog(SYELOG_SEVERITY_INFORMATION, "##################################################################\n");
	Syelog(SYELOG_SEVERITY_INFORMATION, "### %ls\n", wzExeName);

	Syelog(SYELOG_SEVERITY_INFORMATION, "### Loading translations...\n");
#endif

	try
	{
		std::ifstream i(TRANSLATIONS_FILE);
		if (i.is_open())
		{
			i >> g_translations;

#if INCLUDE_DEBUG_LOGGING
			Syelog(SYELOG_SEVERITY_INFORMATION, "### Loaded %d translations.\n", g_translations.size());
#endif
		}
		else
		{
#if INCLUDE_DEBUG_LOGGING
			Syelog(SYELOG_SEVERITY_WARNING, "### Warning: Could not open %s\n", TRANSLATIONS_FILE.c_str());
#endif
		}
	}
	catch ([[maybe_unused]] const std::exception& e)
	{
#if INCLUDE_DEBUG_LOGGING
		Syelog(SYELOG_SEVERITY_FATAL, "### Error loading translations: %s\n", e.what());
#endif
		MessageBox(NULL, L"Failed to load the interface translation. Please make sure the corresponding JSON file is present and valid. Parts of the interface will not be translated.", L"Demonion 2 Redirect", MB_OK | MB_ICONERROR);
	}

	SetupHook(Real_ExeStringFunc, EXE_STRING_FUNC, "ExeStringFunc");
	SetupHook(Real_ExeStringFunc2, EXE_STRING_FUNC_2_OFFSET, "ExeStringFunc2");
	SetupHook(Real_FormatStringFunc, FORMAT_STRING_FUNC_OFFSET, "FormatStringFunc");

	LONG error = AttachDetours();

#if INCLUDE_DEBUG_LOGGING
	if (error != NO_ERROR)
		Syelog(SYELOG_SEVERITY_FATAL, "### Error attaching detours: %d\n", error);

	Syelog(SYELOG_SEVERITY_NOTICE, "### Attached.\n");
#endif

	ThreadAttach(hDll);

	logging::SetBLog(TRUE);

	return TRUE;
}

BOOL ProcessDetach(HMODULE hDll)
{
	ThreadDetach(hDll);

	logging::SetBLog(FALSE);

	LONG error = DetachDetours();

#if INCLUDE_DEBUG_LOGGING
	if (error != NO_ERROR)
		Syelog(SYELOG_SEVERITY_FATAL, "### Error detaching detours: %d\n", error);

	Syelog(SYELOG_SEVERITY_NOTICE, "### Closing.\n");
	SyelogClose(FALSE);

	logging::Cleanup();
#endif

	return TRUE;
}

BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD dwReason, PVOID lpReserved)
{
	(void)hModule;
	(void)lpReserved;

	if (DetourIsHelperProcess())
		return TRUE;

	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
			DetourRestoreAfterWith();
			return ProcessAttach(hModule);
		case DLL_PROCESS_DETACH:
			return ProcessDetach(hModule);
		case DLL_THREAD_ATTACH:
			return ThreadAttach(hModule);
		case DLL_THREAD_DETACH:
			return ThreadDetach(hModule);
	}

	return TRUE;
}
//
///////////////////////////////////////////////////////////////// End of File.
