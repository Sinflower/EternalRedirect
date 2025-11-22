#pragma once

#include <windows.h>

// syelog include needs to be after windows.h
#include <syelog.h>

#if INCLUDE_DEBUG_LOGGING
VOID _PrintEnter(const CHAR* psz, ...);
VOID _PrintExit(const CHAR* psz, ...);
VOID _Print(const CHAR* psz, ...);
#endif

namespace logging
{
void Setup();
void Cleanup();
void SetBLog(BOOL bLog);
void ThreadAttach();
void ThreadDetach();
} // namespace logging