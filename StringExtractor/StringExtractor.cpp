#include <Windows.h>
#include <exception>
#include <format>
#include <fstream>
#include <iostream>
#include <vector>

#include <nlohmann/json.hpp>

#include "../EternalRedirect/Utils.hpp"

const std::string TARGET_SECTION_NAME = ".rdata";

IMAGE_SECTION_HEADER getRDataSection(std::ifstream& file)
{
	IMAGE_DOS_HEADER dosHeader;
	file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));

	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		throw std::runtime_error("Invalid DOS header signature");

	file.seekg(dosHeader.e_lfanew);
	IMAGE_NT_HEADERS64 ntHeaders;
	file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(ntHeaders));

	if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
		throw std::runtime_error("Invalid NT header signature");

	IMAGE_SECTION_HEADER sectionHeader;
	bool found = false;

	for (uint32_t i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
	{
		file.read(reinterpret_cast<char*>(&sectionHeader), sizeof(sectionHeader));

		const std::string secName = std::string(reinterpret_cast<char*>(sectionHeader.Name), strnlen_s(reinterpret_cast<char*>(sectionHeader.Name), IMAGE_SIZEOF_SHORT_NAME));
		if (secName == TARGET_SECTION_NAME)
			return sectionHeader;
	}

	throw std::runtime_error("Target section not found");
}

std::vector<char> getRData(const std::string& filename)
{
	std::ifstream file(filename, std::ios::binary);

	if (!file)
		throw std::runtime_error(std::format("Failed to open file: {}", filename));

	std::cout << "Getting rdata section information ... " << std::flush;
	IMAGE_SECTION_HEADER sec = getRDataSection(file);
	const DWORD dataPtr      = sec.PointerToRawData;
	const DWORD dataSize     = sec.SizeOfRawData;
	std::cout << "Done" << std::endl;

	std::cout << "Reading section data ... " << std::flush;
	std::vector<char> secData;
	secData.resize(dataSize);

	// Read the section data
	file.seekg(dataPtr);
	file.read(secData.data(), dataSize);
	file.close();
	std::cout << "Done" << std::endl;

	return secData;
}

bool isValidSJisString(const std::vector<char>& data)
{
	std::vector<char> validEscapeChars;
	validEscapeChars.push_back('\n'); // Newline
	validEscapeChars.push_back('\t'); // Tab
	validEscapeChars.push_back('\r'); // Carriage return

	for (char byte : data)
	{
		// Check for valid single-byte characters
		if ((byte >= 0x20 && byte <= 0x7F) || (byte >= static_cast<char>(0xA1) && byte <= static_cast<char>(0xDF)))
			continue;

		// Check for valid escape sequences
		if (std::find(validEscapeChars.begin(), validEscapeChars.end(), byte) != validEscapeChars.end())
			continue;

		// Check for valid lead bytes of double-byte characters
		if ((byte >= static_cast<char>(0x81) && byte <= static_cast<char>(0x9F)) || (byte >= static_cast<char>(0xE0) && byte <= static_cast<char>(0xFC)))
			continue;

		return false;
	}

	return true;
}

bool isPureAsciiString(const std::vector<char>& data)
{
	for (char byte : data)
	{
		if (static_cast<unsigned char>(byte) > 0x7F)
			return false;
	}
	return true;
}

int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		std::cout << std::format("Usage: {} <path_to_exe>", argv[0]) << std::endl;
		return 1;
	}

	const std::string target = argv[1];

	// Make sure the file exists
	if (!std::ifstream(target))
	{
		std::cerr << std::format("Error: Target file: \"{}\" not found", target) << std::endl;
		return 1;
	}

	try
	{
		std::vector<char> data = getRData(target);

		std::vector<std::vector<char>> outputs;
		std::vector<char> output;

		std::cout << "Extracting strings from section data ... " << std::flush;

		for (size_t i = 0; i < data.size(); i++)
		{
			if (data[i] == 0)
			{
				if (isValidSJisString(output) && !isPureAsciiString(output))
					outputs.push_back(output);

				output.clear();

				// Skip all consecutive zero bytes
				while (i + 1 < data.size() && data[i + 1] == 0)
					i++;

				continue;
			}

			output.push_back(data[i]);
		}

		std::cout << "Done" << std::endl;
		std::cout << "Total strings extracted: " << outputs.size() << std::endl;
		std::cout << "Creating JSON file ... " << std::flush;

		nlohmann::ordered_json j;

		for (const auto& segment : outputs)
		{
			std::string sjisStr(segment.begin(), segment.end());
			std::string utf8Str = sjis2utf8(sjisStr.c_str());
			if (!j.contains(utf8Str))
				j[utf8Str] = "";
		}

		std::ofstream jsonFile("output.json");
		if (!jsonFile)
		{
			std::cerr << "Error creating JSON file." << std::endl;
			return 1;
		}

		jsonFile << j.dump(4);
		jsonFile.close();

		std::cout << "Done" << std::endl;
	}
	catch (const std::exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
	}

	return 0;
}