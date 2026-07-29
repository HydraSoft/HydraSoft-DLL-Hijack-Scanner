program HydraAgent;

{$APPTYPE CONSOLE}

uses
  Winapi.Windows,
  Winapi.WinSvc,
  System.SysUtils,
  AgentService in 'AgentService.pas',
  AgentWorker in 'AgentWorker.pas',
  AgentConfig in 'AgentConfig.pas',
  PanelClient in 'PanelClient.pas',
  CredentialStore in 'CredentialStore.pas',
  CommandRegistry in 'CommandRegistry.pas',
  ScanEngine in '..\Robber\ScanEngine.pas',
  ScanExport in '..\Robber\ScanExport.pas';

const
  ERROR_FAILED_SERVICE_CONTROLLER_CONNECT_CODE = 1063;

procedure RunOnce;
var
  Config: TAgentConfig;
  Worker: TAgentWorker;
begin
  Config := TAgentConfig.Load;
  Worker := TAgentWorker.Create(Config);
  try
    Worker.RunOnce;
  finally
    Worker.Free;
  end;
end;

procedure RunConsole;
var
  Config: TAgentConfig;
  Worker: TAgentWorker;
  StopEvent: THandle;
begin
  Config := TAgentConfig.Load;
  StopEvent := CreateEvent(nil, True, False, nil);
  if StopEvent = 0 then
    RaiseLastOSError;
  Worker := TAgentWorker.Create(Config);
  try
    Writeln('HydraAgent console mode started. Press Ctrl+C to stop.');
    Writeln('Configuration: ', Config.ConfigFile);
    Worker.RunLoop(StopEvent);
  finally
    Worker.Free;
    CloseHandle(StopEvent);
  end;
end;

procedure RunDefault;
begin
  try
    RunAsService;
  except
    on E: EOSError do
      if E.ErrorCode = ERROR_FAILED_SERVICE_CONTROLLER_CONNECT_CODE then
        RunConsole
      else
        raise;
  end;
end;

begin
  try
    if FindCmdLineSwitch('console', ['-', '/'], True)
      or ((ParamCount > 0) and SameText(ParamStr(1), '--console')) then
      RunConsole
    else if FindCmdLineSwitch('run-once', ['-', '/'], True)
      or ((ParamCount > 0) and SameText(ParamStr(1), '--run-once')) then
      RunOnce
    else
      RunDefault;
  except
    on E: Exception do
    begin
      Writeln(E.ClassName, ': ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
