#pragma once

#include <string>
#include <vector>
#include <windows.h>

class DetourEntry
{
public:
	DetourEntry(const std::vector<BYTE>& searchPattern, PVOID* ppRealFunc, PVOID pMineFunc, const std::string& name = "");
	DetourEntry(const intptr_t& rva, PVOID* ppRealFunc, PVOID pMineFunc, const std::string& name = "");
	void Setup();

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
	void calcVA();

	bool attach() const;

	bool detach() const;

	static intptr_t findFunction(const std::vector<BYTE>& tarBytes);
	static intptr_t calcFunctionAddress(const intptr_t& funcOffset);

private:
	std::vector<BYTE> m_searchPattern = {};

	intptr_t m_rva = -1;
	intptr_t m_va  = -1;

	PVOID* m_ppRealFunc;
	PVOID m_pMineFunc;
	std::string m_name;
};

using DetourEntries = std::vector<DetourEntry>;