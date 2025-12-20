#pragma once

#include <nlohmann/json.hpp>

#include "DetourEntry.hpp"

extern DetourEntries g_detours;

#define ADD_REDIRECT(PATTERN_OR_RVA, FUNC_NAME) \
	g_detours.push_back(DetourEntry(PATTERN_OR_RVA, (PVOID*)&Real_##FUNC_NAME, (PVOID)Mine_##FUNC_NAME, #FUNC_NAME))