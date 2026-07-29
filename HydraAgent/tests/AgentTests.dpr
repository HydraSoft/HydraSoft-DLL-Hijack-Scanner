program AgentTests;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.IOUtils,
  System.JSON,
  AgentConfig in '..\AgentConfig.pas',
  CommandRegistry in '..\CommandRegistry.pas',
  CredentialStore in '..\CredentialStore.pas',
  ScanEngine in '..\..\Robber\ScanEngine.pas',
  ScanExport in '..\..\Robber\ScanExport.pas';

procedure Check(Condition: Boolean; const MessageText: string);
begin
  if not Condition then
    raise Exception.Create(MessageText);
end;

procedure Run;
var
  Config: TAgentConfig;
  Registry: TCommandRegistry;
  Params: TJSONObject;
  Options: TScanOptions;
  CredentialFile, Secret: string;
  EmptyResults: TArray<TScanResult>;
begin
  Check(TCommandRegistry.IsAllowed('robber.scan'), 'robber.scan must be allowed');
  Check(not TCommandRegistry.IsAllowed('shell.exec'), 'shell.exec must be rejected');

  Config := Default(TAgentConfig);
  Config.AllowedRoots := TArray<string>.Create(TPath.GetTempPath);
  Registry := TCommandRegistry.Create(Config);
  try
    Params := TJSONObject.Create;
    try
      Params.AddPair('path', TPath.GetTempPath);
      Params.AddPair('image_type', 'x64');
      Params.AddPair('sign', 'signed');
      Params.AddPair('rate', 'bad');
      Params.AddPair('write_perm', TJSONBool.Create(True));
      Options := Registry.BuildScanOptions(Params);
      Check(Options.ImageTypeFilter = 2, 'image_type mapping failed');
      Check(Options.SignFilter = 1, 'sign mapping failed');
      Check(Options.AbuseCandidateFilter = 3, 'rate mapping failed');
      Check(Options.WritePermFilter = 1, 'write_perm mapping failed');
    finally
      Params.Free;
    end;
  finally
    Registry.Free;
  end;

  CredentialFile := TPath.Combine(TPath.GetTempPath, 'robber-agent-dpapi-test.bin');
  Secret := 'agent-test-secret';
  try
    TCredentialStore.Save(CredentialFile, Secret);
    Check(TCredentialStore.Load(CredentialFile) = Secret, 'DPAPI round trip failed');
  finally
    if TFile.Exists(CredentialFile) then
      TFile.Delete(CredentialFile);
  end;

  SetLength(EmptyResults, 0);
  Check(BuildJSON(EmptyResults).Contains('['), 'legacy JSON export changed unexpectedly');
end;

begin
  try
    Run;
    Writeln('Agent tests passed');
  except
    on E: Exception do
    begin
      Writeln(E.ClassName, ': ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
