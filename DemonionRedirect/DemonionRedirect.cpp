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

class DetourEntry
{
public:
	DetourEntry(const std::vector<BYTE>& searchPattern, PVOID* ppRealFunc, PVOID pMineFunc, const std::string& name = "") :
		m_searchPattern(searchPattern),
		m_ppRealFunc(ppRealFunc),
		m_pMineFunc(pMineFunc),
		m_name(name)
	{
	}

	DetourEntry(const intptr_t& rva, PVOID* ppRealFunc = nullptr, PVOID pMineFunc = nullptr, const std::string& name = "") :
		m_rva(rva),
		m_ppRealFunc(ppRealFunc),
		m_pMineFunc(pMineFunc),
		m_name(name)
	{
	}

	void Setup()
	{
		calcVA();
		if (m_va != -1)
			*m_ppRealFunc = reinterpret_cast<PVOID>(m_va);
	}

	bool Attach() const
	{
		return attach();
	}

	bool Detach() const
	{
		return detach();
	}

	PVOID* GetRealFuncPtrPtr() const
	{
		return m_ppRealFunc;
	}

	PVOID GetMineFuncPtr() const
	{
		return m_pMineFunc;
	}

	const std::string& GetName() const
	{
		return m_name;
	}

private:
	void calcVA()
	{
		if (m_rva != -1)
			m_va = calcFunctionAddress(m_rva);
		else if (!m_searchPattern.empty())
			m_va = findFunction(m_searchPattern);
		else
			m_va = -1;

		if (m_va == -1)
		{
#if INCLUDE_DEBUG_LOGGING
			Syelog(SYELOG_SEVERITY_FATAL, "### Error: Unable to find the %s function\n", m_name.c_str());
#endif
			return;
		}
		else
		{
#if INCLUDE_DEBUG_LOGGING
			Syelog(SYELOG_SEVERITY_INFORMATION, "### Found %s function at address: 0x%p\n", m_name.c_str(), m_va);
#endif
		}
	}

	bool attach() const
	{
		if (*m_ppRealFunc == nullptr || m_pMineFunc == nullptr)
		{
#if INCLUDE_DEBUG_LOGGING
			if (m_ppRealFunc == nullptr)
				Syelog(SYELOG_SEVERITY_NOTICE, "Attach failed: `%s': m_ppRealFunc is nullptr\n", m_name.c_str());
			if (m_pMineFunc == nullptr)
				Syelog(SYELOG_SEVERITY_NOTICE, "Attach failed: `%s': m_pMineFunc is nullptr\n", m_name.c_str());
#endif
			return false;
		}

		LONG l = DetourAttach(m_ppRealFunc, m_pMineFunc);
		if (l != 0)
		{
#if INCLUDE_DEBUG_LOGGING
			Syelog(SYELOG_SEVERITY_NOTICE, "Attach failed: `%s': error %d\n", m_name.c_str(), l);
#endif
			return false;
		}

		return true;
	}

	bool detach() const
	{
		if (*m_ppRealFunc == nullptr || m_pMineFunc == nullptr)
		{
#if INCLUDE_DEBUG_LOGGING
			if (m_ppRealFunc == nullptr)
				Syelog(SYELOG_SEVERITY_NOTICE, "Detach failed: `%s': m_ppRealFunc is nullptr\n", m_name.c_str());
			if (m_pMineFunc == nullptr)
				Syelog(SYELOG_SEVERITY_NOTICE, "Detach failed: `%s': m_pMineFunc is nullptr\n", m_name.c_str());
#endif
			return false;
		}

		LONG l = DetourDetach(m_ppRealFunc, m_pMineFunc);
		if (l != 0)
		{
#if INCLUDE_DEBUG_LOGGING
			Syelog(SYELOG_SEVERITY_NOTICE, "Detach failed: `%s': error %d\n", m_name.c_str(), l);
#endif
			return false;
		}

		return true;
	}

private:
	std::vector<BYTE> m_searchPattern = {};

	intptr_t m_rva = -1;
	intptr_t m_va  = -1;

	PVOID* m_ppRealFunc = nullptr;
	PVOID m_pMineFunc   = nullptr;
	std::string m_name  = "";
};

//////////////////////////////////////////////////////////////////////////////

nlohmann::json g_translations;

static const std::string TRANSLATIONS_FOLDER = "redirects";

// RVA Offsets for the functions to hook
static const uint32_t EXE_STRING_FUNC_1_OFFSET  = 0x41E0;
static const uint32_t EXE_STRING_FUNC_2_OFFSET  = 0x34F0;
static const uint32_t EXE_STRING_FUNC_3_OFFSET  = 0x1CF050;
static const uint32_t FORMAT_STRING_FUNC_OFFSET = 0x1C2C40;

//////////////////////////////////////////////////////////////////////////////
//
// Real function pointers for detoured functions

extern "C"
{
	DWORD*(__fastcall* Real_ExeStringFunc1)(DWORD* a1, int32_t a2, BYTE* Source, uint32_t a4)                      = nullptr;
	DWORD*(__fastcall* Real_ExeStringFunc2)(DWORD* a1, int32_t a2, BYTE* Source, uint32_t a4)                      = nullptr;
	int*(__cdecl* Real_ExeStringFunc3)(int* a1, int a2, WORD* a3, int* a4, int a5, int a6, int a7, int a8, int a9) = nullptr;
	int(WINAPI* Real_FormatStringFunc)(int a1, wchar_t* Format, ...)                                               = nullptr;

	DWORD* __fastcall Mine_ExeStringFunc1(DWORD* a1, int32_t a2, BYTE* pSource, uint32_t a4);
	DWORD* __fastcall Mine_ExeStringFunc2(DWORD* a1, int32_t a2, BYTE* pSource, uint32_t a4);
	int* __cdecl Mine_ExeStringFunc3(int* a1, int a2, WORD* a3, int* a4, int a5, int a6, int a7, int a8, int a9);
	int WINAPI Mine_FormatStringFunc(int a1, wchar_t* Format, ...);
}

//
//
//////////////////////////////////////////////////////////////////////////////

static std::vector<DetourEntry> g_detours = {
	DetourEntry(EXE_STRING_FUNC_1_OFFSET, (PVOID*)&Real_ExeStringFunc1, (PVOID)Mine_ExeStringFunc1, "ExeStringFunc1"),
	DetourEntry(EXE_STRING_FUNC_2_OFFSET, (PVOID*)&Real_ExeStringFunc2, (PVOID)Mine_ExeStringFunc2, "ExeStringFunc2"),
	DetourEntry(EXE_STRING_FUNC_3_OFFSET, (PVOID*)&Real_ExeStringFunc3, (PVOID)Mine_ExeStringFunc3, "ExeStringFunc3"),
	DetourEntry(FORMAT_STRING_FUNC_OFFSET, (PVOID*)&Real_FormatStringFunc, (PVOID)Mine_FormatStringFunc, "FormatStringFunc"),
};

//////////////////////////////////////////////////////////////////////////////
// Detours
//

DWORD* __fastcall Mine_ExeStringFunc1(DWORD* a1, int32_t a2, BYTE* pSource, uint32_t a4)
{
	std::wstring unicodeStr = reinterpret_cast<const wchar_t*>(pSource);
	std::string utf8String  = unicode2utf8(unicodeStr);

	// Check if this string exists in the translations
	if (g_translations.contains(utf8String))
	{
		const std::string trStr = g_translations[utf8String].get<std::string>();
		if (trStr == "")
			return Real_ExeStringFunc1(a1, a2, pSource, a4);

#if INCLUDE_DEBUG_LOGGING
		_Print("[ExeStringFunc1]: %s\n", trStr.c_str());
#endif

		unicodeStr = utf82unicode(trStr);
		return Real_ExeStringFunc1(a1, a2, reinterpret_cast<BYTE*>(const_cast<wchar_t*>(unicodeStr.c_str())), unicodeStr.size());
	}
	else
		return Real_ExeStringFunc1(a1, a2, pSource, a4);
}

DWORD* __fastcall Mine_ExeStringFunc2(DWORD* a1, int32_t a2, BYTE* pSource, uint32_t a4)
{
	std::wstring unicodeStr = reinterpret_cast<const wchar_t*>(pSource);
	std::string utf8String  = unicode2utf8(unicodeStr);

	// Check if this string exists in the translations
	if (g_translations.contains(utf8String))
	{
		const std::string trStr = g_translations[utf8String].get<std::string>();
		if (trStr == "")
			return Real_ExeStringFunc2(a1, a2, pSource, a4);

#if INCLUDE_DEBUG_LOGGING
		_Print("[ExeStringFunc2]: %s\n", trStr.c_str());
#endif

		unicodeStr = utf82unicode(trStr);
		return Real_ExeStringFunc2(a1, a2, reinterpret_cast<BYTE*>(const_cast<wchar_t*>(unicodeStr.c_str())), unicodeStr.size());
	}
	else
		return Real_ExeStringFunc2(a1, a2, pSource, a4);
}

int* __cdecl Mine_ExeStringFunc3(int* a1, int a2, WORD* a3, int* a4, int a5, int a6, int a7, int a8, int a9)
{
	std::wstring unicodeStr = reinterpret_cast<const wchar_t*>(a3);
	std::string utf8String  = unicode2utf8(unicodeStr);

	// Check if this string exists in the translations
	if (g_translations.contains(utf8String))
	{
		const std::string trStr = g_translations[utf8String].get<std::string>();
		if (trStr == "")
			return Real_ExeStringFunc3(a1, a2, a3, a4, a5, a6, a7, a8, a9);

#if INCLUDE_DEBUG_LOGGING
		_Print("[ExeStringFunc3]: %s\n", trStr.c_str());
#endif

		unicodeStr = utf82unicode(trStr);
		return Real_ExeStringFunc3(a1, a2, reinterpret_cast<WORD*>(const_cast<wchar_t*>(unicodeStr.c_str())), a4, a5, a6, a7, a8, a9);
	}
	else
		return Real_ExeStringFunc3(a1, a2, a3, a4, a5, a6, a7, a8, a9);
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
			_Print("[FormatStringFunc]: %s\n", trStr.c_str());
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

LONG AttachDetours(VOID)
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	for (const DetourEntry& detour : g_detours)
		detour.Attach();

	return DetourTransactionCommit();
}

LONG DetachDetours(VOID)
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	for (const DetourEntry& detour : g_detours)
		detour.Detach();

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
		g_translations = LoadTranslations(TRANSLATIONS_FOLDER);
#if INCLUDE_DEBUG_LOGGING
			Syelog(SYELOG_SEVERITY_INFORMATION, "### Loaded %d translations.\n", g_translations.size());
#endif
	}
	catch ([[maybe_unused]] const std::exception& e)
	{
#if INCLUDE_DEBUG_LOGGING
		Syelog(SYELOG_SEVERITY_FATAL, "### Error loading translations: %s\n", e.what());
#endif
		MessageBox(NULL, L"Failed to load the interface translation. Please make sure the corresponding JSON file is present and valid. Parts of the interface will not be translated.", L"Demonion 2 Redirect", MB_OK | MB_ICONERROR);
	}

	for (DetourEntry& detour : g_detours)
		detour.Setup();

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
