program RobberAgent;

{$APPTYPE CONSOLE}

uses
  Winapi.Windows,
  System.SysUtils,
  AgentService in 'AgentService.pas',
  AgentWorker in 'AgentWorker.pas',
  AgentConfig in 'AgentConfig.pas',
  PanelClient in 'PanelClient.pas',
  CredentialStore in 'CredentialStore.pas',
  CommandRegistry in 'CommandRegistry.pas',
  ScanEngine in '..\Robber\ScanEngine.pas',
  ScanExport in '..\Robber\ScanExport.pas';

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
    Writeln('RobberAgent console mode started. Press Ctrl+C to stop.');
    Worker.RunLoop(StopEvent);
  finally
    Worker.Free;
    CloseHandle(StopEvent);
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
      RunAsService;
  except
    on E: Exception do
    begin
      Writeln(E.ClassName, ': ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
