unit AgentWorker;

interface

uses
  Winapi.Windows, AgentConfig;

type
  TAgentWorker = class
  private
    FConfig: TAgentConfig;
    FAgentID: Int64;
    FCredential: string;
    procedure EnsureEnrolled;
    procedure LoadState;
    procedure SaveState;
    procedure EnsureStartupReport;
    procedure ProcessOne;
  public
    constructor Create(const Config: TAgentConfig);
    procedure RunLoop(StopEvent: THandle);
    procedure RunOnce;
  end;

implementation

uses
  System.SysUtils, System.Classes, System.IOUtils, System.StrUtils,
  System.JSON, PanelClient, CredentialStore, CommandRegistry;

type
  THeartbeatThread = class(TThread)
  private
    FServerURL: string;
    FCredential: string;
    FJobID: Int64;
    FStopEvent: THandle;
    FCancelRequested: Integer;
  protected
    procedure Execute; override;
  public
    constructor Create(const ServerURL, Credential: string; JobID: Int64);
    destructor Destroy; override;
    procedure Stop;
    function CancelRequested: Boolean;
  end;

constructor THeartbeatThread.Create(const ServerURL, Credential: string; JobID: Int64);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FServerURL := ServerURL;
  FCredential := Credential;
  FJobID := JobID;
  FStopEvent := CreateEvent(nil, True, False, nil);
end;

destructor THeartbeatThread.Destroy;
begin
  CloseHandle(FStopEvent);
  inherited;
end;

procedure THeartbeatThread.Stop;
begin
  SetEvent(FStopEvent);
  WaitFor;
end;

function THeartbeatThread.CancelRequested: Boolean;
begin
  Result := InterlockedCompareExchange(FCancelRequested, 0, 0) <> 0;
end;

procedure THeartbeatThread.Execute;
var
  Client: TPanelClient;
begin
  Client := TPanelClient.Create(FServerURL);
  try
    Client.SetCredential(FCredential);
    while WaitForSingleObject(FStopEvent, 30000) = WAIT_TIMEOUT do
      try
        if Client.Heartbeat(FJobID) then
        begin
          InterlockedExchange(FCancelRequested, 1);
          Break;
        end;
      except
        { The worker will still submit the final result or failure. }
      end;
  finally
    Client.Free;
  end;
end;

constructor TAgentWorker.Create(const Config: TAgentConfig);
begin
  inherited Create;
  FConfig := Config;
  LoadState;
end;

procedure TAgentWorker.LoadState;
var
  State: string;
  Separator: Integer;
begin
  FAgentID := 0;
  FCredential := TCredentialStore.Load(FConfig.CredentialFile);
  Separator := Pos('|', FCredential);
  if Separator > 1 then
  begin
    State := FCredential;
    FAgentID := StrToInt64Def(Copy(State, 1, Separator - 1), 0);
    FCredential := Copy(State, Separator + 1, MaxInt);
  end
  else
    FCredential := '';
end;

procedure TAgentWorker.SaveState;
begin
  TCredentialStore.Save(FConfig.CredentialFile,
    IntToStr(FAgentID) + '|' + FCredential);
end;

procedure TAgentWorker.EnsureEnrolled;
var
  Client: TPanelClient;
  Enrollment: TEnrollment;
  BootstrapToken: string;
  ComputerNameBuffer: array[0..MAX_COMPUTERNAME_LENGTH] of Char;
  Size: DWORD;
  ComputerName: string;
begin
  if (FAgentID > 0) and (FCredential <> '') then
    Exit;
  BootstrapToken := FConfig.BootstrapToken;
  if (BootstrapToken = '') and TFile.Exists(FConfig.BootstrapFile) then
    BootstrapToken := Trim(TFile.ReadAllText(FConfig.BootstrapFile, TEncoding.ASCII));
  if BootstrapToken = '' then
    raise Exception.Create(
      'bootstrap_token is required in HydraAgent.json for first enrollment');
  Size := Length(ComputerNameBuffer);
  if not GetComputerName(ComputerNameBuffer, Size) then
    RaiseLastOSError;
  SetString(ComputerName, ComputerNameBuffer, Size);

  Client := TPanelClient.Create(FConfig.ServerURL);
  try
    Enrollment := Client.Enroll(BootstrapToken, ComputerName, FConfig.AgentVersion);
  finally
    Client.Free;
  end;
  FAgentID := Enrollment.AgentID;
  FCredential := Enrollment.Credential;
  SaveState;
  if TFile.Exists(FConfig.BootstrapFile) then
    TFile.Delete(FConfig.BootstrapFile);
end;

procedure TAgentWorker.EnsureStartupReport;
var
  Client: TPanelClient;
  Registry: TCommandRegistry;
  Job: TAgentJob;
  ReportJSON, TempFile, ComputerName: string;
begin
  if not FConfig.StartupScanEnabled
    or TFile.Exists(FConfig.StartupCompleteFile) then
    Exit;

  if not TFile.Exists(FConfig.StartupReportFile) then
  begin
    Registry := TCommandRegistry.Create(FConfig);
    Job := Default(TAgentJob);
    Job.Operation := 'robber.scan';
    Job.Params := TJSONObject.Create;
    try
      Job.Params.AddPair('path', FConfig.StartupScanPath);
      Job.Params.AddPair('image_type', FConfig.StartupImageType);
      Job.Params.AddPair('sign', FConfig.StartupSign);
      Job.Params.AddPair('rate', FConfig.StartupRate);
      Job.Params.AddPair('write_perm', TJSONBool.Create(FConfig.StartupWritePerm));
      Job.Params.AddPair('best_dll_count', TJSONNumber.Create(FConfig.StartupBestDLLCount));
      Job.Params.AddPair('best_exe_size', TJSONNumber.Create(FConfig.StartupBestExeSize));
      Job.Params.AddPair('good_dll_count', TJSONNumber.Create(FConfig.StartupGoodDLLCount));
      Job.Params.AddPair('good_exe_size', TJSONNumber.Create(FConfig.StartupGoodExeSize));
      ComputerName := GetEnvironmentVariable('COMPUTERNAME');
      ReportJSON := Registry.Execute(Job, FAgentID, ComputerName,
        FConfig.AgentVersion);
      TempFile := FConfig.StartupReportFile + '.tmp';
      if TFile.Exists(TempFile) then
        TFile.Delete(TempFile);
      TFile.WriteAllText(TempFile, ReportJSON, TEncoding.UTF8);
      TFile.Move(TempFile, FConfig.StartupReportFile);
    finally
      Job.Params.Free;
      Registry.Free;
    end;
  end;

  EnsureEnrolled;
  ReportJSON := TFile.ReadAllText(FConfig.StartupReportFile, TEncoding.UTF8);
  Client := TPanelClient.Create(FConfig.ServerURL);
  try
    Client.SetCredential(FCredential);
    Client.UploadStartupReport(ReportJSON);
  finally
    Client.Free;
  end;
  TFile.WriteAllText(FConfig.StartupCompleteFile, 'complete', TEncoding.ASCII);
  TFile.Delete(FConfig.StartupReportFile);
end;

procedure TAgentWorker.ProcessOne;
var
  Client: TPanelClient;
  Registry: TCommandRegistry;
  Job: TAgentJob;
  ReportJSON, ComputerName: string;
  Heartbeat: THeartbeatThread;
begin
  EnsureEnrolled;
  Client := TPanelClient.Create(FConfig.ServerURL);
  Registry := TCommandRegistry.Create(FConfig);
  try
    Client.SetCredential(FCredential);
    if not Client.Claim(Job) then
      Exit;
    try
      if Client.Heartbeat(Job.ID) then
        raise EAbort.Create('Job was cancelled before execution');
      ComputerName := GetEnvironmentVariable('COMPUTERNAME');
      Heartbeat := THeartbeatThread.Create(FConfig.ServerURL, FCredential, Job.ID);
      try
        Heartbeat.Start;
        try
          ReportJSON := Registry.Execute(Job, FAgentID, ComputerName,
            FConfig.AgentVersion, Heartbeat.CancelRequested);
        finally
          Heartbeat.Stop;
        end;
      finally
        Heartbeat.Free;
      end;
      Client.Complete(Job.ID, ReportJSON);
    except
      on E: Exception do
      begin
        try
          Client.Fail(Job.ID, E.ClassName, E.Message);
        except
          { Preserve the original command failure. }
        end;
      end;
    end;
    Job.Params.Free;
  finally
    Registry.Free;
    Client.Free;
  end;
end;

procedure TAgentWorker.RunLoop(StopEvent: THandle);
var
  WaitMilliseconds: Cardinal;
begin
  WaitMilliseconds := FConfig.PollSeconds * 1000;
  while WaitForSingleObject(StopEvent, 0) <> WAIT_OBJECT_0 do
  begin
    try
      EnsureStartupReport;
      ProcessOne;
      WaitMilliseconds := FConfig.PollSeconds * 1000;
    except
      WaitMilliseconds := 60000;
    end;
    if WaitForSingleObject(StopEvent, WaitMilliseconds) = WAIT_OBJECT_0 then
      Break;
  end;
end;

procedure TAgentWorker.RunOnce;
begin
  EnsureStartupReport;
  ProcessOne;
end;

end.
