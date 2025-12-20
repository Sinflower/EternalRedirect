/*
 *  File: Utils.hpp
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

#pragma once

#include <filesystem>
#include <format>
#include <string>
#include <vector>
#include <windows.h>

#include <nlohmann/json.hpp>

std::string sjis2utf8(const char* sjis)
{
	int len = MultiByteToWideChar(932, 0, sjis, -1, NULL, 0);
	std::wstring wstr;
	wstr.resize(len);
	MultiByteToWideChar(932, 0, sjis, -1, &wstr[0], len);

	len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
	std::string utf8;
	utf8.resize(len);
	WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &utf8[0], len, NULL, NULL);

	// Remove the null terminator added by WideCharToMultiByte
	if (!utf8.empty() && utf8.back() == '\0')
		utf8.pop_back();

	return utf8;
}

std::string utf82sjis(const std::string& utf8)
{
	int len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
	std::wstring wstr;
	wstr.resize(len);
	MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &wstr[0], len);

	len = WideCharToMultiByte(932, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
	std::string sjis;
	sjis.resize(len);
	WideCharToMultiByte(932, 0, wstr.c_str(), -1, &sjis[0], len, NULL, NULL);

	// Remove the null terminator added by WideCharToMultiByte
	if (!sjis.empty() && sjis.back() == '\0')
		sjis.pop_back();

	return sjis;
}

std::string unicode2utf8(const std::wstring& unicode)
{
	int len = WideCharToMultiByte(CP_UTF8, 0, unicode.c_str(), -1, NULL, 0, NULL, NULL);
	std::string utf8;
	utf8.resize(len);
	WideCharToMultiByte(CP_UTF8, 0, unicode.c_str(), -1, &utf8[0], len, NULL, NULL);

	// Remove the null terminator added by WideCharToMultiByte
	if (!utf8.empty() && utf8.back() == '\0')
		utf8.pop_back();

	return utf8;
}

std::wstring utf82unicode(const std::string& utf8)
{
	int len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
	std::wstring unicode;
	unicode.resize(len);
	MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &unicode[0], len);

	// Remove the null terminator added by MultiByteToWideChar
	if (!unicode.empty() && unicode.back() == L'\0')
		unicode.pop_back();

	return unicode;
}

std::string replaceAll(const std::string& str, const std::string& from, const std::string& to)
{
	std::string result = str;
	size_t start_pos   = 0;
	while ((start_pos = result.find(from, start_pos)) != std::string::npos)
	{
		result.replace(start_pos, from.length(), to);
		start_pos += to.length(); // Move past the replacement
	}

	return result;
}

std::vector<std::string> splitString(const std::string& str, const char& delimiter = '\n')
{
	std::vector<std::string> tokens;
	size_t start = 0;
	size_t end   = str.find(delimiter);

	while (end != std::string::npos)
	{
		tokens.push_back(str.substr(start, end - start));
		start = end + 1;
		end   = str.find(delimiter, start);
	}

	tokens.push_back(str.substr(start));
	return tokens;
}

//
// Determine the offset for the given function
//
intptr_t findFunction(const std::vector<BYTE>& tarBytes)
{
	const intptr_t startAddress = reinterpret_cast<intptr_t>(GetModuleHandleW(nullptr));
	MEMORY_BASIC_INFORMATION info;
	intptr_t endAddress = startAddress;

	do
	{
		VirtualQuery(reinterpret_cast<void*>(endAddress), &info, sizeof(info));
		endAddress = reinterpret_cast<intptr_t>(info.BaseAddress) + info.RegionSize;
	} while (info.Protect > PAGE_NOACCESS);

	endAddress -= info.RegionSize;

	const std::size_t procMemLength = static_cast<std::size_t>(endAddress - startAddress);
	const std::size_t tarLength     = tarBytes.size();
	const BYTE* pProcData           = reinterpret_cast<BYTE*>(startAddress);

	for (std::size_t i = 0; i < procMemLength - tarLength; i++)
	{
		for (std::size_t j = 0; j <= tarLength; j++)
		{
			if (j == tarLength)
				return startAddress + i;
			else if (pProcData[i + j] != tarBytes[j])
				break;
		}
	}

	return -1;
}

intptr_t calcFunctionAddress(const intptr_t& funcOffset)
{
	const intptr_t baseAddress = reinterpret_cast<intptr_t>(GetModuleHandleW(nullptr));
	return baseAddress + funcOffset;
}

void PostProcessTranslations(nlohmann::json& translations)
{
	// Check if the JSON contains the "patterns" and "data" keys
	if (!translations.contains("patterns") || !translations.contains("data"))
		return;

	nlohmann::json newData = {};

	// Get the patterns objects
	nlohmann::json& patterns = translations["patterns"];
	nlohmann::json& data = translations["data"];

	for (auto& [key, value] : data.items())
	{
		std::string valueStr = value.get<std::string>();
		for (auto& [pK, pV] : patterns.items())
		{
			std::string pVStr = pV.get<std::string>();

			std::string k = std::vformat(pK, std::make_format_args(key, valueStr));
			std::string v = std::vformat(pVStr, std::make_format_args(key, valueStr));

			newData[k] = v;
		}
	}

	translations = newData;
}

nlohmann::json LoadTranslation(const std::filesystem::path& translationFilePath)
{
	nlohmann::json translations;

	if (!std::filesystem::exists(translationFilePath))
		return translations;

	std::ifstream fs(translationFilePath);
	if (!fs.is_open())
		return translations;

	try
	{
		fs >> translations;
	}
	catch (const nlohmann::json::parse_error&)
	{
	}

	PostProcessTranslations(translations);

	return translations;
}

nlohmann::json LoadTranslations(const std::filesystem::path& translationFilePath)
{
	nlohmann::json translations;
	if (!std::filesystem::exists(translationFilePath))
				return translations;

	if (std::filesystem::is_directory(translationFilePath))
	{
		for (const auto& tlFile : std::filesystem::directory_iterator(translationFilePath))
		{
			if (tlFile.is_regular_file() && tlFile.path().extension() == ".json")
			{
				nlohmann::json fileTranslations = LoadTranslation(tlFile.path());
				translations.update(fileTranslations);
			}
		}
	}
	else if (translationFilePath.extension() == ".json")
		translations = LoadTranslation(translationFilePath);

	return translations;
}