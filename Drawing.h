#ifndef DRAWING_H
#define DRAWING_H

#include "pch.h"
#include "UI.h"
#include "Offsets.h"

// ============================================================
// CONFIGURATION — Change these for your target application
// ============================================================
#define TARGET_PROCESS  "redeclipse.exe"   // Process name to attach to
#define OVERLAY_TITLE   "Yasin C++ Overlay"        // Overlay window title (internal)
#define MENU_KEY        VK_INSERT              // Key to toggle the ImGui menu

class Drawing
{
private:
	static LPCSTR lpWindowName;
	static ImVec2 vWindowSize;
	static ImGuiWindowFlags WindowFlags;
	static bool bDraw;

public:
	static bool isActive();
	static void Draw();
};

#endif