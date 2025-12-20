#pragma once

#include <filesystem>
#include <nlohmann/json.hpp>


class TranslationManager
{
public:
	static TranslationManager& GetInstance()
	{
		static TranslationManager instance;
		return instance;
	}

	static void LoadTranslations(const std::filesystem::path& translationFilePath = "redirects")
	{
		GetInstance().loadTranslations(translationFilePath);
	}

	static std::size_t GetTranslationCount()
	{
		return GetInstance().m_translations.size();
	}

	static std::string GetTranslation(const std::string& key)
	{
		return GetInstance().getTranslation(key);
	}

	static std::wstring GetTranslationW(const std::wstring& key);

private:
	TranslationManager() = default;

	std::string getTranslation(const std::string& key);

	void postProcessTranslations(nlohmann::json& translations);
	nlohmann::json loadTranslation(const std::filesystem::path& translationFilePath);
	void loadTranslations(const std::filesystem::path& translationFilePath);

private:
	nlohmann::json m_translations;
};
