; scripts/packaging/windows/citrate.nsi
; NSIS installer script for Citrate (Windows x86_64)
;
; Creates an installer that bundles:
;   - citrate.exe (unified CLI binary)
;   - Citrate GUI app (from Tauri NSIS/MSI build)
;   - Start Menu shortcuts
;   - PATH registration
;   - Uninstaller
;
; Build with:
;   makensis /DVERSION=0.1.0 /DCLI_DIR=..\..\target\release /DGUI_DIR=..\..\gui\citrate-core\src-tauri\target\release citrate.nsi

!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "nsDialogs.nsh"

; --- Configuration ---
!ifndef VERSION
  !define VERSION "0.1.0"
!endif

!define PRODUCT_NAME "Citrate"
!define PRODUCT_PUBLISHER "Citrate AI"
!define PRODUCT_WEB_SITE "https://citrate.ai"
!define PRODUCT_DIR_REGKEY "Software\Citrate"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"

Name "${PRODUCT_NAME} ${VERSION}"
OutFile "CitrateSetup-${VERSION}-x64.exe"
InstallDir "$PROGRAMFILES64\Citrate"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
RequestExecutionLevel admin
ShowInstDetails show
ShowUnInstDetails show

; --- Modern UI settings ---
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "Welcome to Citrate Setup"
!define MUI_WELCOMEPAGE_TEXT "This wizard will install Citrate ${VERSION} on your computer.$\r$\n$\r$\nCitrate is an AI-native Layer-1 BlockDAG blockchain with GhostDAG consensus, an EVM-compatible execution environment, and Model Context Protocol (MCP) layer.$\r$\n$\r$\nClick Next to continue."

; Installer pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${NSISDIR}\Docs\Modern UI\License.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Language
!insertmacro MUI_LANGUAGE "English"

; --- Installer sections ---

Section "Citrate CLI" SecCLI
  SectionIn RO  ; Required section

  SetOutPath "$INSTDIR"

  ; Copy CLI binary
  !ifdef CLI_DIR
    File "${CLI_DIR}\citrate.exe"
  !else
    File "..\..\target\release\citrate.exe"
  !endif

  ; Create uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  ; Registry entries
  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\citrate.exe"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr HKLM "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"

  ; Get installed size
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${PRODUCT_UNINST_KEY}" "EstimatedSize" "$0"

  ; Add to PATH
  EnVar::SetHKLM
  EnVar::AddValue "PATH" "$INSTDIR"

SectionEnd

Section "Citrate GUI" SecGUI

  SetOutPath "$INSTDIR"

  ; Copy GUI executable (Tauri builds produce an .exe)
  !ifdef GUI_DIR
    File /nonfatal "${GUI_DIR}\Citrate.exe"
  !else
    File /nonfatal "..\..\gui\citrate-core\src-tauri\target\release\Citrate.exe"
  !endif

  ; Copy WebView2 bootstrapper if needed
  !ifdef GUI_DIR
    File /nonfatal "${GUI_DIR}\WebView2Loader.dll"
  !endif

SectionEnd

Section "Start Menu Shortcuts" SecShortcuts

  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"

  ; CLI shortcut (opens terminal)
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Citrate CLI.lnk" \
    "cmd.exe" '/k "$INSTDIR\citrate.exe" --help' \
    "$INSTDIR\citrate.exe" 0

  ; GUI shortcut (if installed)
  IfFileExists "$INSTDIR\Citrate.exe" 0 +2
    CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Citrate.lnk" \
      "$INSTDIR\Citrate.exe" "" "$INSTDIR\Citrate.exe" 0

  ; Uninstaller shortcut
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk" \
    "$INSTDIR\Uninstall.exe" "" "$INSTDIR\Uninstall.exe" 0

SectionEnd

Section "Desktop Shortcut" SecDesktop

  ; GUI desktop shortcut (if GUI is installed)
  IfFileExists "$INSTDIR\Citrate.exe" 0 +2
    CreateShortCut "$DESKTOP\Citrate.lnk" \
      "$INSTDIR\Citrate.exe" "" "$INSTDIR\Citrate.exe" 0

SectionEnd

; --- Section descriptions ---
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCLI} \
    "The Citrate unified command-line tool (node, wallet, CLI tools). Required."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecGUI} \
    "The Citrate desktop GUI application for managing your node and wallet."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecShortcuts} \
    "Create Start Menu shortcuts for Citrate."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} \
    "Create a desktop shortcut for the Citrate GUI."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; --- Uninstaller ---

Section "Uninstall"

  ; Remove files
  Delete "$INSTDIR\citrate.exe"
  Delete "$INSTDIR\Citrate.exe"
  Delete "$INSTDIR\WebView2Loader.dll"
  Delete "$INSTDIR\Uninstall.exe"

  ; Remove shortcuts
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Citrate CLI.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Citrate.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk"
  RMDir "$SMPROGRAMS\${PRODUCT_NAME}"
  Delete "$DESKTOP\Citrate.lnk"

  ; Remove install directory (only if empty)
  RMDir "$INSTDIR"

  ; Remove from PATH
  EnVar::SetHKLM
  EnVar::DeleteValue "PATH" "$INSTDIR"

  ; Remove registry entries
  DeleteRegKey HKLM "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"

SectionEnd
