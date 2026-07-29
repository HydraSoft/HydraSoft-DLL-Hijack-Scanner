unit AgentService;

interface

procedure RunAsService;

implementation

uses
  Winapi.Windows, Winapi.WinSvc, System.SysUtils, AgentConfig, AgentWorker;

const
  ServiceName = 'HydraAgent';

var
  ServiceStatusHandle: SERVICE_STATUS_HANDLE;
  ServiceStatus: SERVICE_STATUS;
  StopEvent: THandle;

procedure SetState(State: DWORD; Win32ExitCode: DWORD = NO_ERROR);
begin
  ZeroMemory(@ServiceStatus, SizeOf(ServiceStatus));
  ServiceStatus.dwServiceType := SERVICE_WIN32_OWN_PROCESS;
  ServiceStatus.dwCurrentState := State;
  ServiceStatus.dwWin32ExitCode := Win32ExitCode;
  if State = SERVICE_START_PENDING then
    ServiceStatus.dwControlsAccepted := 0
  else
    ServiceStatus.dwControlsAccepted := SERVICE_ACCEPT_STOP or SERVICE_ACCEPT_SHUTDOWN;
  SetServiceStatus(ServiceStatusHandle, ServiceStatus);
end;

function ControlHandler(Control, EventType: DWORD;
  EventData, Context: Pointer): DWORD; stdcall;
begin
  Result := NO_ERROR;
  case Control of
    SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN:
      begin
        SetState(SERVICE_STOP_PENDING);
        SetEvent(StopEvent);
      end;
  end;
end;

procedure ServiceMain(ArgCount: DWORD; ArgVectors: PPChar); stdcall;
var
  Config: TAgentConfig;
  Worker: TAgentWorker;
begin
  ServiceStatusHandle := RegisterServiceCtrlHandlerEx(ServiceName, @ControlHandler, nil);
  if ServiceStatusHandle = 0 then
    Exit;
  StopEvent := CreateEvent(nil, True, False, nil);
  if StopEvent = 0 then
  begin
    SetState(SERVICE_STOPPED, GetLastError);
    Exit;
  end;
  try
    SetState(SERVICE_START_PENDING);
    try
      Config := TAgentConfig.Load;
      Worker := TAgentWorker.Create(Config);
      try
        SetState(SERVICE_RUNNING);
        Worker.RunLoop(StopEvent);
      finally
        Worker.Free;
      end;
      SetState(SERVICE_STOPPED);
    except
      SetState(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
    end;
  finally
    CloseHandle(StopEvent);
  end;
end;

procedure RunAsService;
var
  DispatchTable: array[0..1] of SERVICE_TABLE_ENTRY;
begin
  ZeroMemory(@DispatchTable, SizeOf(DispatchTable));
  DispatchTable[0].lpServiceName := PChar(ServiceName);
  DispatchTable[0].lpServiceProc := @ServiceMain;
  if not StartServiceCtrlDispatcher(DispatchTable[0]) then
    RaiseLastOSError;
end;

end.
