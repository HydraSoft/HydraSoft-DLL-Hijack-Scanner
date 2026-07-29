unit CredentialStore;

interface

type
  TCredentialStore = class
  public
    class procedure Save(const FileName, Credential: string); static;
    class function Load(const FileName: string): string; static;
  end;

implementation

uses
  Winapi.Windows, System.SysUtils, System.Classes, System.IOUtils;

const
  CRYPTPROTECT_UI_FORBIDDEN = $1;
  CRYPTPROTECT_LOCAL_MACHINE = $4;

type
  PDataBlob = ^DATA_BLOB;

function CryptProtectData(pDataIn: PDataBlob; szDataDescr: LPCWSTR;
  pOptionalEntropy: PDataBlob; pvReserved, pPromptStruct: Pointer;
  dwFlags: DWORD; pDataOut: PDataBlob): BOOL; stdcall;
  external 'crypt32.dll' name 'CryptProtectData';

function CryptUnprotectData(pDataIn: PDataBlob; ppszDataDescr: PPWideChar;
  pOptionalEntropy: PDataBlob; pvReserved, pPromptStruct: Pointer;
  dwFlags: DWORD; pDataOut: PDataBlob): BOOL; stdcall;
  external 'crypt32.dll' name 'CryptUnprotectData';

class procedure TCredentialStore.Save(const FileName, Credential: string);
var
  InputBlob, OutputBlob: DATA_BLOB;
  Plain, ProtectedBytes: TBytes;
begin
  Plain := TEncoding.UTF8.GetBytes(Credential);
  InputBlob.cbData := Length(Plain);
  InputBlob.pbData := nil;
  if Length(Plain) > 0 then
    InputBlob.pbData := @Plain[0];
  ZeroMemory(@OutputBlob, SizeOf(OutputBlob));
  if not CryptProtectData(@InputBlob, 'HydraAgent credential', nil, nil, nil,
    CRYPTPROTECT_LOCAL_MACHINE or CRYPTPROTECT_UI_FORBIDDEN, @OutputBlob) then
    RaiseLastOSError;
  try
    SetLength(ProtectedBytes, OutputBlob.cbData);
    if OutputBlob.cbData > 0 then
      Move(OutputBlob.pbData^, ProtectedBytes[0], OutputBlob.cbData);
    ForceDirectories(ExtractFileDir(FileName));
    TFile.WriteAllBytes(FileName, ProtectedBytes);
  finally
    if OutputBlob.pbData <> nil then
      LocalFree(HLOCAL(OutputBlob.pbData));
    if Length(Plain) > 0 then
      FillChar(Plain[0], Length(Plain), 0);
  end;
end;

class function TCredentialStore.Load(const FileName: string): string;
var
  InputBlob, OutputBlob: DATA_BLOB;
  ProtectedBytes, Plain: TBytes;
begin
  Result := '';
  if not TFile.Exists(FileName) then
    Exit;
  ProtectedBytes := TFile.ReadAllBytes(FileName);
  InputBlob.cbData := Length(ProtectedBytes);
  InputBlob.pbData := nil;
  if Length(ProtectedBytes) > 0 then
    InputBlob.pbData := @ProtectedBytes[0];
  ZeroMemory(@OutputBlob, SizeOf(OutputBlob));
  if not CryptUnprotectData(@InputBlob, nil, nil, nil, nil,
    CRYPTPROTECT_UI_FORBIDDEN, @OutputBlob) then
    RaiseLastOSError;
  try
    SetLength(Plain, OutputBlob.cbData);
    if OutputBlob.cbData > 0 then
      Move(OutputBlob.pbData^, Plain[0], OutputBlob.cbData);
    Result := TEncoding.UTF8.GetString(Plain);
  finally
    if OutputBlob.pbData <> nil then
      LocalFree(HLOCAL(OutputBlob.pbData));
    if Length(Plain) > 0 then
      FillChar(Plain[0], Length(Plain), 0);
  end;
end;

end.
