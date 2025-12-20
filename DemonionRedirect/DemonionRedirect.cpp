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

#include "Constants.hpp"
#include "DetourEntry.hpp"
#include "Globals.hpp"
#include "Logging.hpp"
#include "Redirects.hpp"
#include "TranslationManager.hpp"
#include "Utils.hpp"

//////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////

DetourEntries g_detours;

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

	SetupRedirects();

	SyelogOpen("demon" DETOURS_STRINGIFY(DETOURS_BITS), SYELOG_FACILITY_APPLICATION);
	Syelog(SYELOG_SEVERITY_INFORMATION, "##################################################################\n");
	Syelog(SYELOG_SEVERITY_INFORMATION, "### %ls\n", wzExeName);

	Syelog(SYELOG_SEVERITY_INFORMATION, "### Loading translations...\n");
#endif

	try
	{
		TranslationManager::LoadTranslations(TRANSLATIONS_FOLDER);
#if INCLUDE_DEBUG_LOGGING
		Syelog(SYELOG_SEVERITY_INFORMATION, "### Loaded %d translations.\n", TranslationManager::GetTranslationCount());
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
