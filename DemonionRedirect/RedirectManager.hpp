#pragma once

#include "DetourEntry.hpp"

class RedirectManager
{
public:
	static RedirectManager& GetInstance()
	{
		static RedirectManager instance;
		return instance;
	}

	static void AddDetour(const DetourEntry& detour)
	{
		GetInstance().m_detours.push_back(detour);
	}

	static void SetupAllDetours()
	{
		for (DetourEntry& detour : GetInstance().m_detours)
			detour.Setup();
	}

	static void AttachAllDetours()
	{
		for (DetourEntry& detour : GetInstance().m_detours)
			detour.Attach();
	}

	static void DetachAllDetours()
	{
		for (DetourEntry& detour : GetInstance().m_detours)
			detour.Detach();
	}

private:
	DetourEntries m_detours;
};
