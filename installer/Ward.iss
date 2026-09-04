; Inno Setup script for Ward (PC version).
;
; Builds a double-click installer that:
;   - shows a consent page (LicenseFile),
;   - collects the uninstall password (masked, with confirm),
;   - copies guard.exe + extension-ids.json to Program Files,
;   - runs `guard install-service` to install + harden + start the service,
;   - and on uninstall, requires that password via `guard uninstall-service`.
;
; Build with: ISCC.exe Ward.iss   (see README.md in this folder)
; NOTE: unsigned until a code-signing certificate is available (SignPath).

#define AppName "Ward"
; AppVersion is normally passed by build.ps1 (ISCC /DAppVersion=x.y.z from the
; repo-root VERSION file). The fallback keeps a bare `ISCC Ward.iss`
; working.
#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif

[Setup]
AppId={{6B2C9E4A-3F71-4B8E-9C2D-5A1E7F0D9C34}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=monolab
; The version resource on Setup.exe itself. AppVersion above does NOT supply
; it - Inno leaves VersionInfoVersion at 0.0.0.0 unless it is set explicitly -
; and Setup.exe was shipping as 0.0.0.0 with no publisher on its Details tab.
; That is the same problem cmd/guard/versioninfo.json exists to solve for
; guard.exe: an unsigned installer with no version and no company is exactly
; what antivirus heuristics score against, and the one binary a user is most
; likely to inspect the properties of before running it.
VersionInfoVersion={#AppVersion}
VersionInfoProductVersion={#AppVersion}
VersionInfoProductName={#AppName}
VersionInfoCompany=monolab
VersionInfoDescription={#AppName} Setup
VersionInfoCopyright=Copyright (c) monolab. MIT License.
; New installs land in "Ward"; installs made under the old name keep
; "Extension Guard", because the AppId below is unchanged and
; UsePreviousAppDir defaults to yes. That divergence is deliberate. Moving
; an existing install would mean stopping a hardened, auto-restarting
; service, relocating the binary the SCM has a recorded path to, and
; re-registering it - a lot of moving parts for a folder name nobody reads.
; The fleet converges on its own as machines are reinstalled.
DefaultDirName={autopf}\Ward
; Both binaries are 64-bit Go builds. Without these two lines Inno runs the
; installer in 32-bit mode, {autopf} resolves to "Program Files (x86)", and a
; 64-bit program lands in the directory Windows keeps for 32-bit ones. It works
; there, which is why this went unnoticed - it is just wrong, and it is the sort
; of wrong that makes someone reading the install path doubt everything else.
; x64compatible rather than x64os so ARM64 machines, which run x64 under
; emulation, still install. An existing install keeps the directory it already
; has: the AppId is unchanged and UsePreviousAppDir defaults to yes, so an
; upgrade over the x86 copy stays put rather than silently forking into two.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DisableProgramGroupPage=yes
PrivilegesRequired=admin
OutputDir=output
OutputBaseFilename=Ward-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
LicenseFile=consent.txt
SetupIconFile=..\statusui\build\windows\icon.ico
UninstallDisplayName={#AppName}
; Icon shown in Windows "Installed apps" / Apps & Features (the status exe carries
; the app icon; guard.exe is a console binary with no icon resource).
UninstallDisplayIcon={app}\extension-guard-status.exe

[Types]
Name: "full"; Description: "Lock all available extensions"
Name: "custom"; Description: "Choose which extensions to lock"; Flags: iscustom

[Components]
Name: "blocknsfw"; Description: "BlockNSFW - blocks pornography & adult content"; Types: full custom
Name: "sieve"; Description: "Sieve - blocks gambling, dark patterns & doomscrolling"; Types: full custom

[Files]
Source: "..\guard.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\statusui\build\bin\extension-guard-status.exe"; DestDir: "{app}"; Flags: ignoreversion
; The config is shipped from extension-ids.default.json - the clean template -
; rather than from the repo's own extension-ids.json, which is a working config
; carrying whatever blocks, sites and app rules the developer happens to have.
; Shipping that would hand every user someone else's schedule.
;
; onlyifdoesntexist is what makes an upgrade safe: an install that already has a
; config keeps it, so a new version cannot replace a household's blocks, limits
; and locked schedules with an empty template. The template is also laid down
; under its own name, so a later version can offer to adopt corrected extension
; ids from it without guessing what the user changed.
Source: "..\extension-ids.default.json"; DestDir: "{app}"; DestName: "extension-ids.json"; Flags: onlyifdoesntexist
Source: "..\extension-ids.default.json"; DestDir: "{app}"; Flags: ignoreversion

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut for the status window"; GroupDescription: "Additional shortcuts:"

; The product was renamed from "Extension Guard" to "Ward". Inno creates the
; new shortcuts but leaves the old ones alone, so an upgraded machine would
; show both names pointing at the same exe. Remove the old pair first.
; Harmless on a clean install - nothing is there to delete.
[InstallDelete]
Type: files; Name: "{autoprograms}\Extension Guard.lnk"
Type: files; Name: "{autodesktop}\Extension Guard.lnk"

[Icons]
Name: "{autoprograms}\Ward"; Filename: "{app}\extension-guard-status.exe"
Name: "{autodesktop}\Ward"; Filename: "{app}\extension-guard-status.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\extension-guard-status.exe"; Description: "Open the Ward status window"; Flags: postinstall nowait skipifsilent

[Code]
var
  PwPage: TInputQueryWizardPage;

{ ---- The 32-bit install this version supersedes ---- }
{
  ArchitecturesInstallIn64BitMode moved Setup into the 64-bit registry view, and
  an install made before that lives in the 32-bit one. Inno cannot see it from
  here - the AppId key it reads for UsePreviousAppDir is simply not there - so
  without help an upgrade becomes a second, parallel copy: two sets of binaries,
  two entries in Installed apps, and a service only one of them owns.

  So Setup migrates it instead of asking anybody to do anything. The config is
  carried across before the guard reads it, and the old copy is retired once the
  new service is confirmed running.

  Retiring it directly, rather than through its own uninstaller, is the whole
  point: that uninstaller is password-gated and clears the stored password and
  the trusted config with it. That is correct for someone removing protection and
  wrong for an upgrade that is keeping it - an upgrade must not ask for the
  password, and must not cost the machine its rules.
}
const
  LegacyUninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{6B2C9E4A-3F71-4B8E-9C2D-5A1E7F0D9C34}_is1';
  StateKey = 'SOFTWARE\ExtensionGuard';
  { The sentinel internal/guardsvc's watchdog already watches for, and the name
    of the service it guards. Read by the copy of the guard *already installed*,
    which is why this is done here in registry terms rather than through a new
    guard.exe verb: the binary on disk during an upgrade is the old one, and a
    verb it has never heard of is no use for the upgrade that needs it most. }
  UpdatingValue = 'GuardUpdating';
  GuardService  = 'ExtensionGuard';
  { watchdogInterval is five seconds; this gives it a full cycle and some slack
    to notice the sentinel and exit. }
  StandDownMs = 8000;

var
  LegacyDir: String;   { '' when there is no 32-bit install to migrate }
  IsUpgrade: Boolean;  { the guard has been set up on this machine before }
  StoodDown: Boolean;  { the sentinel was set and the service stopped }
  ServiceUp: Boolean;  { install-service ran and the service is back up }

function InitializeSetup(): Boolean;
var
  loc, hash: String;
begin
  Result := True;
  IsUpgrade := RegQueryStringValue(HKLM64, StateKey, 'PasswordHash', hash) and (hash <> '');

  LegacyDir := '';
  if not RegQueryStringValue(HKLM32, LegacyUninstallKey, 'InstallLocation', loc) then
    Exit;
  loc := RemoveBackslashUnlessRoot(loc);
  { Only ever treat a directory that actually holds this program as ours to
    remove. InstallLocation is just a string in a registry key, and the step it
    feeds is a recursive delete. }
  if (loc <> '') and FileExists(loc + '\guard.exe') then
    LegacyDir := loc;
end;

procedure InitializeWizard;
begin
  PwPage := CreateInputQueryPage(wpLicense,
    'Set uninstall password',
    'Choose the password required to remove this protection',
    'Give this password to the parent or accountability partner - NOT the person being filtered. ' +
    'It will be required to uninstall Ward.');
  PwPage.Add('Password:', True);          { True = masked }
  PwPage.Add('Confirm password:', True);
end;

{ An upgrade already has a password and a set of locked extensions, and asking
  again for either is friction that changes nothing: `guard install-service`
  keeps the password it already stored and ignores anything passed to it, and
  re-running `select` from the wizard defaults would quietly re-enable an
  extension the user had turned off. So on an upgrade neither page is shown. }
function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := IsUpgrade and ((PageID = PwPage.ID) or (PageID = wpSelectComponents));
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = PwPage.ID then
  begin
    if Length(PwPage.Values[0]) < 6 then
    begin
      MsgBox('Password must be at least 6 characters.', mbError, MB_OK);
      Result := False;
    end
    else if PwPage.Values[0] <> PwPage.Values[1] then
    begin
      MsgBox('The passwords do not match.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

{ Comma-separated list of the extension names the user chose to lock. }
function SelectedExtensions(): String;
var
  sel: String;
begin
  sel := '';
  if WizardIsComponentSelected('blocknsfw') then
    sel := 'blocknsfw';
  if WizardIsComponentSelected('sieve') then
  begin
    if sel <> '' then sel := sel + ',';
    sel := sel + 'sieve';
  end;
  Result := sel;
end;

{ ---- Stand the running guard down so its binary can be replaced ----

  Windows holds an image-section lock on a running executable: it can be renamed,
  but it cannot be deleted or written over. Both the service and its watchdog run
  from the installed guard.exe, so on an upgrade Setup's first [Files] entry failed
  with "An error occurred while trying to replace the existing file: DeleteFile
  failed; code 5. Access is denied", and the machine quietly stayed on the old
  build with the new one never installed.

  Stopping the service alone does not fix it, and is why this needs the sentinel:
  the watchdog notices a stopped service within watchdogInterval and starts it
  again, and the watchdog's own process holds the same binary open meanwhile. The
  sentinel is what makes the watchdog exit instead - it is the one the in-app
  updater sets for exactly this reason before it swaps the binaries itself, and
  the guard already on disk honours it.

  This has to happen here rather than in install-service, which knows how to take
  over from a previous registration but runs at ssPostInstall - after the copy
  that could not happen. PrepareToInstall is the last hook before any file is
  touched. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  resultCode: Integer;
begin
  Result := '';
  if not FileExists(ExpandConstant('{app}\guard.exe')) then
    Exit;  { a first install has nothing running to stand down }

  RegWriteDWordValue(HKLM64, StateKey, UpdatingValue, 1);
  StoodDown := True;
  Sleep(StandDownMs);

  { net stop rather than sc stop: sc returns as soon as the SCM accepts the
    request, which is not the same as the process having exited and let go of the
    file. A service that was not running reports an error here, and that is the
    state this wants anyway, so the result is not checked - the copy that follows
    is the real test of whether the binary is free. }
  Exec(ExpandConstant('{sys}\net.exe'), 'stop ' + GuardService,
    '', SW_HIDE, ewWaitUntilTerminated, resultCode);
end;

{ Setup can end at any point after that stand-down: a copy that still failed, a
  cancelled wizard, an install-service that could not run. Every one of those
  would otherwise leave the sentinel set and the service stopped - protection
  off, the watchdog gone, and nothing to turn either back on before the next
  reboot. Unless the post-install step got the service running again, put the
  machine back the way it was found. }
procedure DeinitializeSetup();
var
  resultCode: Integer;
begin
  if StoodDown and not ServiceUp then
  begin
    RegWriteDWordValue(HKLM64, StateKey, UpdatingValue, 0);
    Exec(ExpandConstant('{sys}\net.exe'), 'start ' + GuardService,
      '', SW_HIDE, ewWaitUntilTerminated, resultCode);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  resultCode: Integer;
  sel, pw: String;
begin
  if CurStep = ssPostInstall then
  begin
    { Carry the existing config across before anything reads it.

      The trusted copy in the registry survives a move of the install directory
      on its own - guard.exe is 64-bit either way and writes it to the registry,
      nowhere near the install directory - but an install old enough to predate
      the trusted store has only
      this file, and letting the shipped template stand would silently drop that
      machine's rules. }
    if (LegacyDir <> '') and FileExists(LegacyDir + '\extension-ids.json') then
      CopyFile(LegacyDir + '\extension-ids.json', ExpandConstant('{app}\extension-ids.json'), False);

    { The service is installed first, and everything below only runs if that
      succeeded. The other way round cost a real machine its blocks: `select`
      commits the config it writes to the trusted store, so when install-service
      then failed, Setup had already replaced what the machine enforces - and
      went on to report success over it. Nothing here may touch the enforced
      config, or retire the old install, until the step that can actually fail
      has passed. }
    pw := '';
    if not IsUpgrade then
      pw := ' -password "' + PwPage.Values[0] + '"';

    if not Exec(ExpandConstant('{app}\guard.exe'),
      '-config "' + ExpandConstant('{app}\extension-ids.json') + '"' + pw + ' install-service',
      '', SW_HIDE, ewWaitUntilTerminated, resultCode) then
      MsgBox('Could not start the guard service installer.' + #13#10#13#10 +
        'The files are installed, but nothing is being enforced yet. Nothing else on this machine was changed.',
        mbError, MB_OK)
    else if resultCode <> 0 then
      MsgBox('The guard service could not be installed (exit code ' + IntToStr(resultCode) + ').' + #13#10#13#10 +
        'The files are installed, but nothing is being enforced yet. Nothing else on this machine was changed.' + #13#10#13#10 +
        'Run this from an administrator command prompt to see why:' + #13#10 +
        ExpandConstant('"{app}\guard.exe" install-service'),
        mbError, MB_OK)
    else
    begin
      { The service is registered and started again, so the stand-down above is
        over: the service clears the sentinel itself as the first thing it does
        on start, and spawns a fresh watchdog from the new binary. Nothing for
        DeinitializeSetup to put back. }
      ServiceUp := True;

      { First install only: filter the config down to the chosen extensions, so
        only those stay force-installed and locked. An upgrade keeps whatever the
        machine is already enforcing - see ShouldSkipPage. }
      if not IsUpgrade then
      begin
        sel := SelectedExtensions();
        if sel <> '' then
          Exec(ExpandConstant('{app}\guard.exe'),
            '-config "' + ExpandConstant('{app}\extension-ids.json') + '" -extensions "' + sel + '" select',
            '', SW_HIDE, ewWaitUntilTerminated, resultCode);
      end;

      { The 32-bit copy is redundant now: its files are superseded, and the
        service registration it owned has just been replaced by install-service,
        which stops the old service before removing it - so nothing in there is
        still running. A file that is somehow still locked simply stays; the
        uninstall entry is what matters, because two of those in Installed apps
        is what makes somebody uninstall the wrong one. }
      if LegacyDir <> '' then
      begin
        DelTree(LegacyDir, True, True, True);
        RegDeleteKeyIncludingSubkeys(HKLM32, LegacyUninstallKey);
      end;
    end;
  end;
end;

{ ---- Uninstall: prompt for the password and gate removal on it ---- }

function AskPassword(): String;
var
  Form: TSetupForm;
  Lbl: TNewStaticText;
  Edit: TPasswordEdit;
  OKButton, CancelButton: TNewButton;
  W: Integer;
begin
  Result := '';
  Form := CreateCustomForm(ScaleX(380), ScaleY(140), False, True);
  try
    Form.Caption := 'Ward';

    Lbl := TNewStaticText.Create(Form);
    Lbl.Parent := Form;
    Lbl.Left := ScaleX(12);
    Lbl.Top := ScaleY(12);
    Lbl.Caption := 'Enter the uninstall password to remove protection:';

    Edit := TPasswordEdit.Create(Form);
    Edit.Parent := Form;
    Edit.Left := ScaleX(12);
    Edit.Top := ScaleY(40);
    Edit.Width := Form.ClientWidth - ScaleX(24);
    Edit.Height := ScaleY(23);

    OKButton := TNewButton.Create(Form);
    OKButton.Parent := Form;
    OKButton.Caption := 'OK';
    OKButton.ModalResult := mrOk;
    OKButton.Default := True;
    OKButton.Top := Form.ClientHeight - ScaleY(23 + 12);
    OKButton.Height := ScaleY(23);

    CancelButton := TNewButton.Create(Form);
    CancelButton.Parent := Form;
    CancelButton.Caption := 'Cancel';
    CancelButton.ModalResult := mrCancel;
    CancelButton.Cancel := True;
    CancelButton.Top := OKButton.Top;
    CancelButton.Height := ScaleY(23);

    W := Form.CalculateButtonWidth([OKButton.Caption, CancelButton.Caption]);
    OKButton.Width := W;
    CancelButton.Width := W;
    CancelButton.Left := Form.ClientWidth - ScaleX(12) - W;
    OKButton.Left := CancelButton.Left - ScaleX(6) - W;

    Form.ActiveControl := Edit;

    if Form.ShowModal() = mrOk then
      Result := Edit.Text;
  finally
    Form.Free();
  end;
end;

function InitializeUninstall(): Boolean;
var
  pw: String;
  resultCode: Integer;
begin
  pw := AskPassword();
  if pw = '' then
  begin
    MsgBox('Uninstall cancelled.', mbInformation, MB_OK);
    Result := False;
    Exit;
  end;
  if not Exec(ExpandConstant('{app}\guard.exe'),
    '-password "' + pw + '" uninstall-service', '', SW_HIDE, ewWaitUntilTerminated, resultCode) then
  begin
    MsgBox('Could not run the guard uninstaller.', mbError, MB_OK);
    Result := False;
    Exit;
  end;
  if resultCode <> 0 then
  begin
    MsgBox('Incorrect password, or the service could not be removed. Uninstall aborted.', mbError, MB_OK);
    Result := False;
    Exit;
  end;
  Result := True;
end;
