#include "DetourEntry.hpp"

#include "Logging.hpp"

#include <detours.h>

DetourEntry::DetourEntry(const std::vector<BYTE>& searchPattern, PVOID* ppRealFunc, PVOID pMineFunc, const std::string& name) :
	m_searchPattern(searchPattern),
	m_ppRealFunc(ppRealFunc),
	m_pMineFunc(pMineFunc),
	m_name(name)
{
}

DetourEntry::DetourEntry(const intptr_t& rva, PVOID* ppRealFunc, PVOID pMineFunc, const std::string& name) :
	m_rva(rva),
	m_ppRealFunc(ppRealFunc),
	m_pMineFunc(pMineFunc),
	m_name(name)
{
}

void DetourEntry::Setup()
{
	calcVA();
	if (m_va != -1)
		*m_ppRealFunc = reinterpret_cast<PVOID>(m_va);
}

void DetourEntry::calcVA()
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

bool DetourEntry::attach() const
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

bool DetourEntry::detach() const
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

intptr_t DetourEntry::findFunction(const std::vector<BYTE>& tarBytes)
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

intptr_t DetourEntry::calcFunctionAddress(const intptr_t& funcOffset)
{
	const intptr_t baseAddress = reinterpret_cast<intptr_t>(GetModuleHandleW(nullptr));
	return baseAddress + funcOffset;
}
