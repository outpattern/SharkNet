; ============================================================
;  SharkNet installer  (Inno Setup 6)
;
;  - installs the app from dist\SharkNet
;  - detects Npcap (external prerequisite); if missing, opens the official
;    download page (Gate 6.6 — SharkNet does NOT bundle Npcap)
;  - branded wizard: the artwork and the dark palette below are taken from the
;    APPLICATION's own theme, so the installer looks like part of SharkNet.
;    Colours are literal copies of the CSS custom properties in
;    frontend/css/1-base.css  (:root, dark theme). Artwork is generated from the
;    real app logo by make_installer_art.py — see that file before editing.
;
;  Build:  "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" installer.iss
;  (or the whole pipeline: powershell -ExecutionPolicy Bypass -File build.ps1)
; ============================================================

#define AppName    "SharkNet"
#define AppVersion "3.2.0"
#define AppExe     "SharkNet.exe"
#define AppPublisher "SharkNet"

; Npcap is an EXTERNAL PREREQUISITE — SharkNet does NOT bundle it (Gate 6.6).

[Setup]
AppId={{6F2C1A9E-3B4D-4E7A-9C21-A1B2C3D4E5F6}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppCopyright=For lawful use on networks you own or administer.
VersionInfoVersion={#AppVersion}.0
VersionInfoProductVersion={#AppVersion}.0
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} Setup — LAN control & network security
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
UninstallDisplayName={#AppName} {#AppVersion}
OutputDir=installer_output
OutputBaseFilename=SharkNet-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#AppExe}
SetupIconFile=assets\sharknet.ico
SetupLogging=yes

; ---- branded wizard ----
WizardStyle=modern
; Inno 6 defaults DisableWelcomePage to yes; SharkNet wants the branded welcome.
DisableWelcomePage=no
; ...and defaults DisableDirPage to 'auto', which SILENTLY HIDES the install
; location page once a previous version is installed. SharkNet's flow always
; offers the location (pre-filled with the previous path on an upgrade), so the
; wizard is the same every time and the Ready summary is never half-empty.
DisableDirPage=no
WizardSizePercent=120
; Multiple sizes: Inno picks the closest for the current DPI.
WizardImageFile=assets\installer\wizard-164x314.bmp,assets\installer\wizard-205x392.bmp,assets\installer\wizard-246x470.bmp,assets\installer\wizard-328x628.bmp
WizardSmallImageFile=assets\installer\wizard-small-55x58.bmp,assets\installer\wizard-small-83x87.bmp,assets\installer\wizard-small-110x116.bmp,assets\installer\wizard-small-165x174.bmp
WizardImageStretch=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
; Concise, SharkNet-voiced copy. Everything else falls back to Default.isl.
; %1 is AppVerName -> "SharkNet 3.2.0 Setup" in the title bar and taskbar.
SetupWindowTitle=%1 Setup
UninstallAppTitle=Uninstall
UninstallAppFullTitle=%1 Uninstall
WelcomeLabel1=Welcome to [name]
WelcomeLabel2=[name/ver] will be installed on your computer.%n%nSee every device on your network, then allow, limit or cut it — plus domain and service blocking, traffic intelligence and ARP-spoofing defence.%n%nSharkNet needs Administrator rights and the Npcap driver to capture and inject packets.
ClickNext=Click Next to continue, or Cancel to exit Setup.
WizardReady=Ready to install
ReadyLabel1=Setup is ready to install [name] on your computer.
ReadyLabel2a=Review the summary below, then click Install to continue.
FinishedHeadingLabel=[name] is installed
FinishedLabelNoIcons=Setup has finished installing [name] on your computer.
FinishedLabel=Setup has finished installing [name] on your computer.%n%nPick your network adapter, press Start control, and your devices appear. Use it only on networks you own or administer.
WizardSelectDir=Choose install location
SelectDirDesc=Where should [name] be installed?
SelectDirLabel3=Setup will install [name] into the following folder.
WizardSelectTasks=Choose additional options
SelectTasksDesc=Which extras should Setup set up?
SelectTasksLabel2=Select the options you want, then click Next.
WizardInstalling=Installing
InstallingLabel=Please wait while Setup installs [name] on your computer.

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
Source: "dist\SharkNet\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName}"; Flags: postinstall skipifsilent shellexec nowait

[Code]
{ ------------------------------------------------------------------
  SharkNet installer theme.

  The palette is copied verbatim from the app's dark theme
  (frontend/css/1-base.css :root). Only backgrounds, labels and the
  list/memo/edit controls are re-coloured — all through documented Inno Setup
  support classes. Push buttons and the progress bar are deliberately LEFT
  NATIVE: Windows visual styles own their painting, and forcing colours on them
  is the kind of brittle hack that breaks between Windows/Inno versions.
  ------------------------------------------------------------------ }

const
  { --bg-deep #0a0a0f, --bg-card #12121a, --bg-card-2 #171722,
    --line #23233a, --accent #00d4ff, --text #e6e6f5, --dim #7a7a97
    (TColor is BGR, so the byte order is reversed from the CSS hex.) }
  clSharkBgDeep   = $0F0A0A;
  clSharkBgCard   = $1A1212;
  clSharkBgCard2  = $221717;
  clSharkLine     = $3A2323;
  clSharkAccent   = $FFD400;
  clSharkText     = $F5E6E6;
  clSharkDim      = $977A7A;

{ ---- dark title bar -------------------------------------------------------
  Same supported API the application itself uses for its own window
  (see run.py::_apply_titlebar): DWM's immersive dark mode attribute, then a
  frame-change SetWindowPos so the caption repaints immediately.

  Attribute 20 = DWMWA_USE_IMMERSIVE_DARK_MODE on Windows 10 2004+ and Windows 11;
  Windows 10 1809-1903 used 19. We try 20 and fall back to 19.

  LIMITATION: this needs Windows 10 build 17763 or newer. On anything older the
  DWM call simply fails and the caption stays the default light one — the wizard
  is still perfectly usable, just with a native title bar. Windows owns the
  caption button glyphs, so they recolour themselves for a dark caption; we never
  custom-draw them (that WOULD be a brittle hack). }
function DwmSetWindowAttribute(hwnd: HWND; attr: Integer; var value: Integer;
  size: Integer): Integer;
  external 'DwmSetWindowAttribute@dwmapi.dll stdcall delayload';

function SetWindowPos(hWnd: HWND; hAfter: HWND; X, Y, cx, cy: Integer;
  uFlags: Cardinal): Boolean;
  external 'SetWindowPos@user32.dll stdcall delayload';

procedure ApplyDarkTitleBar(H: HWND);
var
  On: Integer;
begin
  if H = 0 then
    Exit;
  On := 1;
  try
    if DwmSetWindowAttribute(H, 20, On, SizeOf(On)) <> 0 then
      DwmSetWindowAttribute(H, 19, On, SizeOf(On));
    { SWP_NOSIZE|SWP_NOMOVE|SWP_NOZORDER|SWP_FRAMECHANGED }
    SetWindowPos(H, 0, 0, 0, 0, 0, $27);
  except
    { pre-17763 Windows, or dwmapi unavailable: keep the native caption }
  end;
end;

var
  ErrorCode: Integer;
  { Application-language selection (SharkNet's INITIAL UI language, distinct from
    the installer's own English UI). The choice is written as a one-time seed that
    the app consumes on its first launch; Settings -> Language changes it later. }
  AppLangPage: TInputOptionWizardPage;
  LangCodes: array[0..4] of String;

{ ---------------- Npcap (external prerequisite — unchanged behaviour) -------- }
function NpcapInstalled(): Boolean;
begin
  Result := FileExists(ExpandConstant('{sys}\Npcap\wpcap.dll')) or
            FileExists(ExpandConstant('{sys}\wpcap.dll'));
end;

function NeedNpcap(): Boolean;
begin
  Result := not NpcapInstalled();
end;

{ ---------------- application-language seed (initial SharkNet UI language) ----
  A valid preference already exists once the app has written its settings file.
  On an UPGRADE we must preserve the user's saved language (and theme), so the
  language page is skipped and no seed is written — the app keeps its own choice. }
function ExistingLanguagePref(): Boolean;
begin
  Result := FileExists(ExpandConstant('{localappdata}\SharkNet\settings.json'));
end;

{ Write the chosen INITIAL language as a one-time seed the app consumes on first
  launch. Never written on an upgrade (existing preference wins). The app also
  guards this (it only applies the seed on a fresh profile), so the two layers
  agree: the installer choice defines the language for NEW installs only. }
procedure WriteAppLanguageSeed();
var
  Dir, Code: String;
begin
  if ExistingLanguagePref() then Exit;            { upgrade -> preserve saved language }
  if AppLangPage = nil then Exit;
  Code := LangCodes[AppLangPage.SelectedValueIndex];
  if Code = '' then Code := 'en';                 { safety: never leave it blank }
  Dir := ExpandConstant('{localappdata}\SharkNet');
  if not DirExists(Dir) then
    if not ForceDirectories(Dir) then Exit;       { fail-safe: app defaults to English }
  SaveStringToFile(Dir + '\initial-language.txt', Code, False);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // record the chosen initial application language for the app's first launch
    WriteAppLanguageSeed();
    // Npcap is an external prerequisite -> if missing, point the user to it
    if NeedNpcap() then
    begin
      if MsgBox('Npcap is required but was not found on this PC.' + #13#10 +
                'Open the Npcap download page now?', mbConfirmation, MB_YESNO) = IDYES then
        ShellExec('open', 'https://npcap.com/#download', '', '', SW_SHOW, ewNoWait, ErrorCode);
    end;
  end;
end;

{ Skip the language page on an upgrade — the user's saved language is preserved. }
function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  if (AppLangPage <> nil) and (PageID = AppLangPage.ID) then
    Result := ExistingLanguagePref();
end;

{ ---------------- theming helpers ---------------- }
procedure PaintPage(Page: TNewNotebookPage);
begin
  if Page <> nil then
    Page.Color := clSharkBgDeep;
end;

procedure StyleText(Ctl: TNewStaticText; Col: TColor);
begin
  if Ctl <> nil then
  begin
    Ctl.Font.Color := Col;
    Ctl.Color := clSharkBgDeep;
  end;
end;

procedure StyleRadio(Ctl: TNewRadioButton; Col: TColor);
begin
  if Ctl <> nil then
  begin
    Ctl.Font.Color := Col;
    Ctl.Color := clSharkBgDeep;
  end;
end;

procedure InitializeWizard();
begin
  { ---- dark caption, so the title bar belongs to the same surface ---- }
  ApplyDarkTitleBar(WizardForm.Handle);

  { ---- form + page surfaces ---- }
  WizardForm.Color := clSharkBgDeep;

  PaintPage(WizardForm.WelcomePage);
  PaintPage(WizardForm.InnerPage);
  PaintPage(WizardForm.LicensePage);
  PaintPage(WizardForm.PasswordPage);
  PaintPage(WizardForm.InfoBeforePage);
  PaintPage(WizardForm.UserInfoPage);
  PaintPage(WizardForm.SelectDirPage);
  PaintPage(WizardForm.SelectComponentsPage);
  PaintPage(WizardForm.SelectProgramGroupPage);
  PaintPage(WizardForm.SelectTasksPage);
  PaintPage(WizardForm.ReadyPage);
  PaintPage(WizardForm.PreparingPage);
  PaintPage(WizardForm.InstallingPage);
  PaintPage(WizardForm.InfoAfterPage);
  PaintPage(WizardForm.FinishedPage);

  { ---- header strip (carries the small logo badge) ---- }
  WizardForm.MainPanel.Color := clSharkBgCard;
  StyleText(WizardForm.PageNameLabel, clSharkText);
  StyleText(WizardForm.PageDescriptionLabel, clSharkDim);
  WizardForm.PageNameLabel.Color := clSharkBgCard;
  WizardForm.PageDescriptionLabel.Color := clSharkBgCard;

  { the default 3D bevels read as bright scratches on a dark surface }
  if WizardForm.Bevel <> nil then WizardForm.Bevel.Visible := False;
  if WizardForm.Bevel1 <> nil then WizardForm.Bevel1.Visible := False;

  { ---- welcome ---- }
  StyleText(WizardForm.WelcomeLabel1, clSharkText);
  StyleText(WizardForm.WelcomeLabel2, clSharkDim);

  { ---- install location ---- }
  StyleText(WizardForm.SelectDirLabel, clSharkDim);
  StyleText(WizardForm.SelectDirBrowseLabel, clSharkDim);
  StyleText(WizardForm.DiskSpaceLabel, clSharkDim);
  if WizardForm.DirEdit <> nil then
  begin
    WizardForm.DirEdit.Color := clSharkBgCard2;
    WizardForm.DirEdit.Font.Color := clSharkText;
  end;

  { ---- options / tasks ---- }
  StyleText(WizardForm.SelectTasksLabel, clSharkDim);
  if WizardForm.TasksList <> nil then
  begin
    WizardForm.TasksList.Color := clSharkBgDeep;
    WizardForm.TasksList.Font.Color := clSharkText;
  end;
  StyleText(WizardForm.SelectStartMenuFolderLabel, clSharkDim);
  StyleText(WizardForm.SelectComponentsLabel, clSharkDim);
  if WizardForm.ComponentsList <> nil then
  begin
    WizardForm.ComponentsList.Color := clSharkBgDeep;
    WizardForm.ComponentsList.Font.Color := clSharkText;
  end;

  { ---- ready summary ---- }
  StyleText(WizardForm.ReadyLabel, clSharkDim);
  if WizardForm.ReadyMemo <> nil then
  begin
    WizardForm.ReadyMemo.Color := clSharkBgCard;
    WizardForm.ReadyMemo.Font.Color := clSharkText;
  end;

  { ---- installing ---- }
  StyleText(WizardForm.StatusLabel, clSharkText);
  StyleText(WizardForm.FilenameLabel, clSharkDim);

  { ---- finished ---- }
  StyleText(WizardForm.FinishedHeadingLabel, clSharkText);
  StyleText(WizardForm.FinishedLabel, clSharkDim);
  StyleRadio(WizardForm.YesRadio, clSharkText);
  StyleRadio(WizardForm.NoRadio, clSharkText);
  if WizardForm.RunList <> nil then
  begin
    WizardForm.RunList.Color := clSharkBgDeep;
    WizardForm.RunList.Font.Color := clSharkText;
  end;

  { ---- initial application-language page ----
    Shown on a fresh install (skipped on upgrade via ShouldSkipPage). The header
    uses the already-themed PageName/PageDescription labels; the subcaption is left
    empty so there is no unthemed black-on-dark label. The radio list is themed to
    the dark surface. This is the SharkNet APPLICATION language, not the installer's
    own (English) UI language. }
  AppLangPage := CreateInputOptionPage(wpSelectDir,
    'Application language',
    'Choose the language SharkNet starts in. You can change it any time in ' +
    'Settings, Language.',
    '', True, False);
  AppLangPage.Add('English');
  AppLangPage.Add('العربية  (Arabic)');
  AppLangPage.Add('Español  (Spanish)');
  AppLangPage.Add('Français  (French)');
  AppLangPage.Add('简体中文  (Simplified Chinese)');
  LangCodes[0] := 'en';
  LangCodes[1] := 'ar';
  LangCodes[2] := 'es';
  LangCodes[3] := 'fr';
  LangCodes[4] := 'zh-CN';
  AppLangPage.SelectedValueIndex := 0;              { default English (safe fallback) }
  AppLangPage.Surface.Color := clSharkBgDeep;
  if AppLangPage.CheckListBox <> nil then
  begin
    AppLangPage.CheckListBox.Color := clSharkBgDeep;
    AppLangPage.CheckListBox.Font.Color := clSharkText;
  end;
end;

{ A compact, SharkNet-styled summary instead of Inno's default block. }
function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo,
  MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
var
  S: String;
begin
  S := 'SharkNet {#AppVersion}' + NewLine + NewLine;
  { MemoDirInfo is empty whenever Inno skipped the location page, so fall back to
    the resolved path — the summary must never show a blank where the install
    folder should be. }
  if Trim(MemoDirInfo) <> '' then
    S := S + MemoDirInfo + NewLine + NewLine
  else
    S := S + 'Destination location:' + NewLine + Space +
         ExpandConstant('{app}') + NewLine + NewLine;
  S := S + 'Start Menu:' + NewLine + Space + '{#AppName}' + NewLine + NewLine;
  if MemoTasksInfo <> '' then
    S := S + MemoTasksInfo + NewLine + NewLine;
  if NpcapInstalled() then
    S := S + 'Npcap:' + NewLine + Space + 'Detected on this PC.'
  else
    S := S + 'Npcap:' + NewLine + Space +
         'Not found — Setup will open the download page when it finishes.';
  Result := S;
end;

{ Uninstall window gets the same treatment. }
procedure InitializeUninstallProgressForm();
begin
  ApplyDarkTitleBar(UninstallProgressForm.Handle);
  UninstallProgressForm.Color := clSharkBgDeep;
  PaintPage(UninstallProgressForm.InnerPage);
  PaintPage(UninstallProgressForm.InstallingPage);
  UninstallProgressForm.MainPanel.Color := clSharkBgCard;
  StyleText(UninstallProgressForm.PageNameLabel, clSharkText);
  StyleText(UninstallProgressForm.PageDescriptionLabel, clSharkDim);
  UninstallProgressForm.PageNameLabel.Color := clSharkBgCard;
  UninstallProgressForm.PageDescriptionLabel.Color := clSharkBgCard;
  StyleText(UninstallProgressForm.StatusLabel, clSharkText);
  if UninstallProgressForm.Bevel <> nil then
    UninstallProgressForm.Bevel.Visible := False;
end;
