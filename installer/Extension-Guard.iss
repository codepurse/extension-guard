; Inno Setup script for the Extension Guard (PC version).
;
; Builds a double-click installer that:
;   - shows a consent page (LicenseFile),
;   - collects the uninstall password (masked, with confirm),
;   - copies guard.exe + extension-ids.json to Program Files,
;   - runs `guard install-service` to install + harden + start the service,
;   - and on uninstall, requires that password via `guard uninstall-service`.
;
; Build with: ISCC.exe Extension-Guard.iss   (see README.md in this folder)
; NOTE: unsigned until a code-signing certificate is available (SignPath).

#define AppName "Extension Guard"
; AppVersion is normally passed by build.ps1 (ISCC /DAppVersion=x.y.z from the
; repo-root VERSION file). The fallback keeps a bare `ISCC Extension-Guard.iss`
; working.
#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif

[Setup]
AppId={{6B2C9E4A-3F71-4B8E-9C2D-5A1E7F0D9C34}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=codepurse
DefaultDirName={autopf}\Extension Guard
DisableProgramGroupPage=yes
PrivilegesRequired=admin
OutputDir=output
OutputBaseFilename=Extension-Guard-Setup
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
Source: "..\extension-ids.json"; DestDir: "{app}"; Flags: ignoreversion

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut for the status window"; GroupDescription: "Additional shortcuts:"

[Icons]
Name: "{autoprograms}\Extension Guard"; Filename: "{app}\extension-guard-status.exe"
Name: "{autodesktop}\Extension Guard"; Filename: "{app}\extension-guard-status.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\extension-guard-status.exe"; Description: "Open the Extension Guard status window"; Flags: postinstall nowait skipifsilent

[Code]
var
  PwPage: TInputQueryWizardPage;

procedure InitializeWizard;
begin
  PwPage := CreateInputQueryPage(wpLicense,
    'Set uninstall password',
    'Choose the password required to remove this protection',
    'Give this password to the parent or accountability partner - NOT the person being filtered. ' +
    'It will be required to uninstall Extension Guard.');
  PwPage.Add('Password:', True);          { True = masked }
  PwPage.Add('Confirm password:', True);
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

procedure CurStepChanged(CurStep: TSetupStep);
var
  resultCode: Integer;
  sel: String;
begin
  if CurStep = ssPostInstall then
  begin
    { Filter the installed config down to the chosen extensions before the
      service reads it, so only those get force-installed and locked. }
    sel := SelectedExtensions();
    if sel <> '' then
      Exec(ExpandConstant('{app}\guard.exe'),
        '-config "' + ExpandConstant('{app}\extension-ids.json') + '" -extensions "' + sel + '" select',
        '', SW_HIDE, ewWaitUntilTerminated, resultCode);

    if not Exec(ExpandConstant('{app}\guard.exe'),
      '-config "' + ExpandConstant('{app}\extension-ids.json') + '" -password "' + PwPage.Values[0] + '" install-service',
      '', SW_HIDE, ewWaitUntilTerminated, resultCode) then
      MsgBox('Failed to launch the guard service installer.', mbError, MB_OK)
    else if resultCode <> 0 then
      MsgBox('The guard service could not be installed (exit code ' + IntToStr(resultCode) + ').', mbError, MB_OK);
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
    Form.Caption := 'Extension Guard';

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
