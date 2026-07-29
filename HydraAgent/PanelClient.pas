unit PanelClient;

interface

uses
  System.JSON, System.Net.HttpClient, CommandRegistry;

type
  TEnrollment = record
    AgentID: Int64;
    Credential: string;
  end;

  TPanelClient = class
  private
    FBaseURL: string;
    FCredential: string;
    FHTTP: THTTPClient;
    function Request(const Method, Path, Body: string; Auth: Boolean): TJSONObject;
  public
    constructor Create(const BaseURL: string);
    destructor Destroy; override;
    procedure SetCredential(const Credential: string);
    function Enroll(const BootstrapToken, ComputerName, AgentVersion: string): TEnrollment;
    function Claim(out Job: TAgentJob): Boolean;
    function Heartbeat(JobID: Int64): Boolean;
    procedure Complete(JobID: Int64; const ReportJSON: string);
    procedure UploadStartupReport(const ReportJSON: string);
    procedure Fail(JobID: Int64; const ErrorCode, ErrorMessage: string);
  end;

implementation

uses
  System.SysUtils, System.Classes, System.Net.URLClient;

constructor TPanelClient.Create(const BaseURL: string);
begin
  inherited Create;
  FBaseURL := BaseURL.TrimRight(['/']);
  FHTTP := THTTPClient.Create;
  FHTTP.ConnectionTimeout := 15000;
  FHTTP.ResponseTimeout := 60000;
  FHTTP.UserAgent := 'HydraAgent/2.0';
end;

destructor TPanelClient.Destroy;
begin
  FHTTP.Free;
  inherited;
end;

procedure TPanelClient.SetCredential(const Credential: string);
begin
  FCredential := Credential;
end;

function TPanelClient.Request(const Method, Path, Body: string; Auth: Boolean): TJSONObject;
var
  Headers: TNetHeaders;
  Stream: TStringStream;
  Response: IHTTPResponse;
  Value: TJSONValue;
begin
  SetLength(Headers, 1 + Ord(Auth));
  Headers[0].Name := 'Content-Type';
  Headers[0].Value := 'application/json';
  if Auth then
  begin
    Headers[1].Name := 'Authorization';
    Headers[1].Value := 'Bearer ' + FCredential;
  end;
  Stream := TStringStream.Create(Body, TEncoding.UTF8);
  try
    if SameText(Method, 'POST') then
      Response := FHTTP.Post(FBaseURL + Path, Stream, nil, Headers)
    else
      raise ENotSupportedException.Create('Unsupported HTTP method');
  finally
    Stream.Free;
  end;
  Value := TJSONObject.ParseJSONValue(Response.ContentAsString(TEncoding.UTF8));
  if not (Value is TJSONObject) then
  begin
    Value.Free;
    raise Exception.CreateFmt('HTTP %d: invalid API response', [Response.StatusCode]);
  end;
  Result := TJSONObject(Value);
  if (Response.StatusCode < 200) or (Response.StatusCode >= 300) then
  begin
    try
      raise Exception.CreateFmt('HTTP %d: %s', [Response.StatusCode,
        Result.GetValue<string>('error', 'API request failed')]);
    finally
      Result.Free;
    end;
  end;
end;

function TPanelClient.Enroll(const BootstrapToken, ComputerName,
  AgentVersion: string): TEnrollment;
var
  Body, Response: TJSONObject;
begin
  Body := TJSONObject.Create;
  try
    Body.AddPair('bootstrap_token', BootstrapToken);
    Body.AddPair('computer_name', ComputerName);
    Body.AddPair('agent_version', AgentVersion);
    Response := Request('POST', '/api/v1/agent/enroll', Body.ToJSON, False);
  finally
    Body.Free;
  end;
  try
    Result.AgentID := Response.GetValue<Int64>('agent_id');
    Result.Credential := Response.GetValue<string>('credential');
  finally
    Response.Free;
  end;
end;

function TPanelClient.Claim(out Job: TAgentJob): Boolean;
var
  Response, JobObject: TJSONObject;
  JobValue: TJSONValue;
begin
  Job := Default(TAgentJob);
  Response := Request('POST', '/api/v1/agent/jobs/claim', '{}', True);
  try
    JobValue := Response.GetValue('job');
    Result := (JobValue <> nil) and not (JobValue is TJSONNull);
    if not Result then
      Exit;
    JobObject := JobValue as TJSONObject;
    Job.ID := JobObject.GetValue<Int64>('id');
    Job.Operation := JobObject.GetValue<string>('operation');
    Job.Params := JobObject.GetValue<TJSONObject>('params').Clone as TJSONObject;
  finally
    Response.Free;
  end;
end;

function TPanelClient.Heartbeat(JobID: Int64): Boolean;
var
  Response: TJSONObject;
begin
  Response := Request('POST', Format('/api/v1/agent/jobs/%d/heartbeat', [JobID]), '{}', True);
  try
    Result := Response.GetValue<Boolean>('cancelled', False);
  finally
    Response.Free;
  end;
end;

procedure TPanelClient.Complete(JobID: Int64; const ReportJSON: string);
var
  Body, Report, Response: TJSONObject;
  Summary: TJSONValue;
begin
  Report := TJSONObject.ParseJSONValue(ReportJSON) as TJSONObject;
  if Report = nil then
    raise EConvertError.Create('Scan report is not a JSON object');
  Body := TJSONObject.Create;
  try
    Body.AddPair('report', Report);
    Summary := Report.GetValue('summary');
    if Summary <> nil then
      Body.AddPair('summary', Summary.Clone as TJSONValue);
    Response := Request('POST', Format('/api/v1/agent/jobs/%d/complete', [JobID]),
      Body.ToJSON, True);
    Response.Free;
  finally
    Body.Free;
  end;
end;

procedure TPanelClient.UploadStartupReport(const ReportJSON: string);
var
  Body, Report, Response: TJSONObject;
  Summary: TJSONValue;
begin
  Report := TJSONObject.ParseJSONValue(ReportJSON) as TJSONObject;
  if Report = nil then
    raise EConvertError.Create('Startup scan report is not a JSON object');
  Body := TJSONObject.Create;
  try
    Body.AddPair('report', Report);
    Summary := Report.GetValue('summary');
    if Summary <> nil then
      Body.AddPair('summary', Summary.Clone as TJSONValue);
    Response := Request('POST', '/api/v1/agent/reports/startup',
      Body.ToJSON, True);
    Response.Free;
  finally
    Body.Free;
  end;
end;

procedure TPanelClient.Fail(JobID: Int64; const ErrorCode, ErrorMessage: string);
var
  Body, Response: TJSONObject;
begin
  Body := TJSONObject.Create;
  try
    Body.AddPair('error_code', ErrorCode);
    Body.AddPair('error_message', ErrorMessage);
    Response := Request('POST', Format('/api/v1/agent/jobs/%d/fail', [JobID]),
      Body.ToJSON, True);
    Response.Free;
  finally
    Body.Free;
  end;
end;

end.
