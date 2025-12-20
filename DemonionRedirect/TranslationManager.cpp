#include "TranslationManager.hpp"
#include "Utils.hpp"

#include <format>
#include <fstream>

std::wstring TranslationManager::GetTranslationW(const std::wstring& key)
{
	const std::string utf8Key = unicode2utf8(key);
	const std::string trStr   = GetInstance().getTranslation(utf8Key);
	return utf82unicode(trStr);
}

std::string TranslationManager::getTranslation(const std::string& key)
{
	if (m_translations.contains(key))
		return m_translations[key].get<std::string>();

	return "";
}

void TranslationManager::postProcessTranslations(nlohmann::json& translations)
{
	if (!translations.contains("patterns") || !translations.contains("data"))
		return;

	nlohmann::json newData = {};

	nlohmann::json& patterns = translations["patterns"];
	nlohmann::json& data     = translations["data"];

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

nlohmann::json TranslationManager::loadTranslation(const std::filesystem::path& translationFilePath)
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

	postProcessTranslations(translations);

	return translations;
}

void TranslationManager::loadTranslations(const std::filesystem::path& translationFilePath)
{
	m_translations.clear();
	if (!std::filesystem::exists(translationFilePath))
		return;

	if (std::filesystem::is_directory(translationFilePath))
	{
		for (const auto& tlFile : std::filesystem::directory_iterator(translationFilePath))
		{
			if (tlFile.is_regular_file() && tlFile.path().extension() == ".json")
			{
				nlohmann::json fileTranslations = loadTranslation(tlFile.path());
				m_translations.update(fileTranslations);
			}
		}
	}
	else if (translationFilePath.extension() == ".json")
		m_translations = loadTranslation(translationFilePath);
}
