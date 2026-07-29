unit AgentConfig;

interface

type
  TAgentConfig = record
    ServerURL: string;
    BootstrapToken: string;
    ConfigFile: string;
    DataDirectory: string;
    BootstrapFile: string;
    CredentialFile: string;
    StartupReportFile: string;
    StartupCompleteFile: string;
    AgentVersion: string;
    PollSeconds: Cardinal;
    AllowedRoots: TArray<string>;
    StartupScanEnabled: Boolean;
    StartupScanPath: string;
    StartupImageType: string;
    StartupSign: string;
    StartupRate: string;
    StartupWritePerm: Boolean;
    StartupBestDLLCount: Integer;
    StartupBestExeSize: Integer;
    StartupGoodDLLCount: Integer;
    StartupGoodExeSize: Integer;
    class function Load: TAgentConfig; static;
    function IsPathAllowed(const Path: string): Boolean;
  end;

implementation

uses
  Winapi.Windows, System.SysUtils, System.IOUtils, System.JSON;

class function TAgentConfig.Load: TAgentConfig;
const
  MigratedFiles: array[0..1] of string =
    ('bootstrap.token', 'credential.bin');
var
  ProgramData, LegacyDirectory, ConfigFile, LegacyFile, TargetFile, Text: string;
  Json, StartupScan: TJSONObject;
  Roots: TJSONArray;
  I: Integer;
begin
  Result := Default(TAgentConfig);
  ProgramData := GetEnvironmentVariable('ProgramData');
  if ProgramData = '' then
    ProgramData := TPath.GetPublicPath;
  Result.DataDirectory := TPath.Combine(ProgramData, 'HydraAgent');
  LegacyDirectory := TPath.Combine(ProgramData, 'RobberAgent');
  ForceDirectories(Result.DataDirectory);
  for I := Low(MigratedFiles) to High(MigratedFiles) do
  begin
    LegacyFile := TPath.Combine(LegacyDirectory, MigratedFiles[I]);
    TargetFile := TPath.Combine(Result.DataDirectory, MigratedFiles[I]);
    if TFile.Exists(LegacyFile) and not TFile.Exists(TargetFile) then
      TFile.Copy(LegacyFile, TargetFile);
  end;
  Result.BootstrapFile := TPath.Combine(Result.DataDirectory, 'bootstrap.token');
  Result.CredentialFile := TPath.Combine(Result.DataDirectory, 'credential.bin');
  Result.StartupReportFile := TPath.Combine(Result.DataDirectory, 'startup-report.json');
  Result.StartupCompleteFile := TPath.Combine(Result.DataDirectory, 'startup-scan.complete');
  Result.ConfigFile := TPath.Combine(ExtractFilePath(ParamStr(0)), 'HydraAgent.json');
  Result.ServerURL := 'https://login.hydrapanel.vip';
  Result.AgentVersion := '2.0.0';
  Result.PollSeconds := 15;
  Result.AllowedRoots := TArray<string>.Create('C:\');
  Result.StartupScanEnabled := True;
  Result.StartupScanPath := 'C:\';
  Result.StartupImageType := 'x64';
  Result.StartupSign := 'signed';
  Result.StartupRate := 'best';
  Result.StartupWritePerm := True;
  Result.StartupBestDLLCount := 2;
  Result.StartupBestExeSize := 10240;
  Result.StartupGoodDLLCount := 5;
  Result.StartupGoodExeSize := 51200;

  ConfigFile := Result.ConfigFile;
  if not TFile.Exists(ConfigFile) then
    raise EFileNotFoundException.CreateFmt(
      'HydraAgent.json was not found next to the executable: %s', [ConfigFile]);
  Text := TFile.ReadAllText(ConfigFile, TEncoding.UTF8);
  Json := TJSONObject.ParseJSONValue(Text) as TJSONObject;
  if Json = nil then
    raise EConvertError.Create('Invalid agent.json');
  try
    if Json.GetValue<string>('server_url', '') <> '' then
      Result.ServerURL := Json.GetValue<string>('server_url');
    Result.BootstrapToken := Json.GetValue<string>('bootstrap_token', '').Trim;
    Result.PollSeconds := Json.GetValue<Integer>('poll_seconds', Result.PollSeconds);
    Roots := Json.GetValue<TJSONArray>('allowed_roots');
    if (Roots <> nil) and (Roots.Count > 0) then
    begin
      SetLength(Result.AllowedRoots, Roots.Count);
      for I := 0 to Roots.Count - 1 do
        Result.AllowedRoots[I] := Roots.Items[I].Value;
    end;
    StartupScan := Json.GetValue<TJSONObject>('startup_scan');
    if StartupScan <> nil then
    begin
      Result.StartupScanEnabled := StartupScan.GetValue<Boolean>(
        'enabled', Result.StartupScanEnabled);
      Result.StartupScanPath := StartupScan.GetValue<string>(
        'path', Result.StartupScanPath);
      Result.StartupImageType := StartupScan.GetValue<string>(
        'image_type', Result.StartupImageType);
      Result.StartupSign := StartupScan.GetValue<string>(
        'sign', Result.StartupSign);
      Result.StartupRate := StartupScan.GetValue<string>(
        'rate', Result.StartupRate);
      Result.StartupWritePerm := StartupScan.GetValue<Boolean>(
        'write_perm', Result.StartupWritePerm);
      Result.StartupBestDLLCount := StartupScan.GetValue<Integer>(
        'best_dll_count', Result.StartupBestDLLCount);
      Result.StartupBestExeSize := StartupScan.GetValue<Integer>(
        'best_exe_size', Result.StartupBestExeSize);
      Result.StartupGoodDLLCount := StartupScan.GetValue<Integer>(
        'good_dll_count', Result.StartupGoodDLLCount);
      Result.StartupGoodExeSize := StartupScan.GetValue<Integer>(
        'good_exe_size', Result.StartupGoodExeSize);
    end;
  finally
    Json.Free;
  end;
  if not Result.ServerURL.StartsWith('https://', True)
    and not Result.ServerURL.StartsWith('http://127.0.0.1', True)
    and not Result.ServerURL.StartsWith('http://localhost', True) then
    raise EConvertError.Create('server_url must use HTTPS (HTTP is allowed only for localhost)');
  if Result.PollSeconds < 5 then
    Result.PollSeconds := 5;
end;

function TAgentConfig.IsPathAllowed(const Path: string): Boolean;
var
  FullPath, Root, FullRoot: string;
begin
  Result := False;
  if Path.StartsWith('\\') then
    Exit;
  FullPath := IncludeTrailingPathDelimiter(TPath.GetFullPath(Path));
  for Root in AllowedRoots do
  begin
    FullRoot := IncludeTrailingPathDelimiter(TPath.GetFullPath(Root));
    if FullPath.StartsWith(FullRoot, True) or SameText(
      ExcludeTrailingPathDelimiter(FullPath), ExcludeTrailingPathDelimiter(FullRoot)) then
      Exit(True);
  end;
end;

end.
