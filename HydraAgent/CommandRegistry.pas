unit CommandRegistry;

interface

uses
  System.JSON, ScanEngine, AgentConfig;

type
  TAgentJob = record
    ID: Int64;
    Operation: string;
    Params: TJSONObject;
  end;

  TCommandRegistry = class
  private
    FConfig: TAgentConfig;
    class function FilterValue(const Value, AnyValue, FirstValue, SecondValue: string): Integer; static;
  public
    constructor Create(const Config: TAgentConfig);
    function BuildScanOptions(const Params: TJSONObject): TScanOptions;
    function Execute(const Job: TAgentJob; AgentID: Int64;
      const ComputerName, AgentVersion: string;
      IsCancelled: TEngineCancelCheck = nil): string;
    class function IsAllowed(const Operation: string): Boolean; static;
  end;

implementation

uses
  System.SysUtils, System.StrUtils, System.DateUtils, ScanExport;

constructor TCommandRegistry.Create(const Config: TAgentConfig);
begin
  inherited Create;
  FConfig := Config;
end;

class function TCommandRegistry.IsAllowed(const Operation: string): Boolean;
begin
  Result := SameText(Operation, 'robber.scan');
end;

class function TCommandRegistry.FilterValue(const Value, AnyValue,
  FirstValue, SecondValue: string): Integer;
begin
  if SameText(Value, AnyValue) then Result := 0
  else if SameText(Value, FirstValue) then Result := 1
  else if SameText(Value, SecondValue) then Result := 2
  else raise EArgumentException.CreateFmt('Invalid filter value: %s', [Value]);
end;

function TCommandRegistry.BuildScanOptions(const Params: TJSONObject): TScanOptions;
var
  Path, Rate: string;
  Pair: TJSONPair;
begin
  if Params = nil then
    raise EArgumentNilException.Create('params');
  for Pair in Params do
    if not MatchText(Pair.JsonString.Value, [
      'path', 'image_type', 'sign', 'rate', 'write_perm',
      'best_dll_count', 'best_exe_size', 'good_dll_count', 'good_exe_size']) then
      raise EArgumentException.CreateFmt('Unknown robber.scan parameter: %s',
        [Pair.JsonString.Value]);

  Result := Default(TScanOptions);
  Path := Params.GetValue<string>('path', '');
  if (Path = '') or not FConfig.IsPathAllowed(Path) or not DirectoryExists(Path) then
    raise EArgumentException.Create('Scan path is absent or outside allowed_roots');
  Result.SearchPath := Path;
  Result.ImageTypeFilter := FilterValue(
    Params.GetValue<string>('image_type', 'any'), 'any', 'x86', 'x64');
  if SameText(Params.GetValue<string>('sign', 'any'), 'any') then
    Result.SignFilter := 0
  else if SameText(Params.GetValue<string>('sign', 'any'), 'signed') then
    Result.SignFilter := 1
  else
    raise EArgumentException.Create('Invalid sign filter');
  Rate := Params.GetValue<string>('rate', 'any');
  Result.AbuseCandidateFilter := FilterValue(Rate, 'any', 'best', 'good');
  if SameText(Rate, 'bad') then
    Result.AbuseCandidateFilter := 3;
  Result.WritePermFilter := Ord(Params.GetValue<Boolean>('write_perm', False));
  Result.BestChoiceDLLCount := Params.GetValue<Integer>('best_dll_count', 2);
  Result.BestChoiceExeSize := Params.GetValue<Integer>('best_exe_size', 10240);
  Result.GoodChoiceDLLCount := Params.GetValue<Integer>('good_dll_count', 5);
  Result.GoodChoiceExeSize := Params.GetValue<Integer>('good_exe_size', 51200);
  if (Result.BestChoiceDLLCount < 0) or (Result.BestChoiceExeSize < 0)
    or (Result.GoodChoiceDLLCount < 0) or (Result.GoodChoiceExeSize < 0) then
    raise EArgumentException.Create('Scan thresholds must be non-negative');
end;

function TCommandRegistry.Execute(const Job: TAgentJob; AgentID: Int64;
  const ComputerName, AgentVersion: string;
  IsCancelled: TEngineCancelCheck): string;
var
  Options: TScanOptions;
  Results: TArray<TScanResult>;
  Metadata: TReportMetadata;
begin
  if not IsAllowed(Job.Operation) then
    raise EArgumentException.Create('Operation is not allow-listed');
  if not SameText(Job.Operation, 'robber.scan') then
    raise EArgumentException.Create('No handler for operation');

  Options := BuildScanOptions(Job.Params);
  Metadata := Default(TReportMetadata);
  Metadata.JobID := Job.ID;
  Metadata.AgentID := AgentID;
  Metadata.AgentVersion := AgentVersion;
  Metadata.ComputerName := ComputerName;
  Metadata.ScanPath := Options.SearchPath;
  Metadata.StartedAtUTC := DateToISO8601(TTimeZone.Local.ToUniversalTime(Now), True);
  Results := TScanEngine.Run(Options, nil, nil, IsCancelled);
  if Assigned(IsCancelled) and IsCancelled() then
    raise EAbort.Create('Job was cancelled by the server');
  Metadata.FinishedAtUTC := DateToISO8601(TTimeZone.Local.ToUniversalTime(Now), True);
  Result := BuildReportEnvelope(Metadata, Results);
end;

end.
