#include "Redirects.hpp"

#include <cstdint>
#include <windows.h>

#include "Globals.hpp"
#include "Logging.hpp"
#include "Utils.hpp"

// RVA Offsets for the functions to hook
inline constexpr uint32_t EXE_STRING_FUNC_1_OFFSET  = 0x41E0;
inline constexpr uint32_t EXE_STRING_FUNC_2_OFFSET  = 0x34F0;
inline constexpr uint32_t EXE_STRING_FUNC_3_OFFSET  = 0x1CF050;
inline constexpr uint32_t FORMAT_STRING_FUNC_OFFSET = 0x1C2C40;

extern "C"
{
	DWORD*(__fastcall* Real_ExeStringFunc1)(DWORD* a1, int32_t a2, BYTE* Source, uint32_t a4)                      = nullptr;
	DWORD*(__fastcall* Real_ExeStringFunc2)(DWORD* a1, int32_t a2, BYTE* Source, uint32_t a4)                      = nullptr;
	int*(__cdecl* Real_ExeStringFunc3)(int* a1, int a2, WORD* a3, int* a4, int a5, int a6, int a7, int a8, int a9) = nullptr;
	int(WINAPI* Real_FormatStringFunc)(int a1, wchar_t* Format, ...)                                               = nullptr;
}

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

/////////////////////////////////////////////////////////////////////////////////////////
///// Setup the redirects

void SetupRedirects()
{
	ADD_REDIRECT(EXE_STRING_FUNC_1_OFFSET, ExeStringFunc1);
	ADD_REDIRECT(EXE_STRING_FUNC_2_OFFSET, ExeStringFunc2);
	ADD_REDIRECT(EXE_STRING_FUNC_3_OFFSET, ExeStringFunc3);
	ADD_REDIRECT(FORMAT_STRING_FUNC_OFFSET, FormatStringFunc);
}

/////
/////////////////////////////////////////////////////////////////////////////////////////