unit InternetUtils;

{$R-,T-,X+,H+,B-,O+,Q-}

interface

uses
  madExcept, Winapi.Windows,
  System.SysUtils,
  System.Classes,
  StrUtils,
  ShellApi,
  System.IOUtils,
  //FastStringUtils,
  Forms,
  //SystemInfoUtils,
  HTTPApp, IdHTTP,
  IdSSLOpenSSL,
  Winapi.WinInet,
  Winapi.UrlMon;


{$DEFINE Use_Debug_Log}

function DownloadURL_BLOCKING(const aUrl: string; var s: String; const Agent : String): Boolean;

function DownloadURL_BLOCKING_method1(const aUrl: string; var s: String; const Agent : String): Boolean;
function DownloadURL_BLOCKING_method2(const aUrl: string; var s: String; const Agent : String; AccessType : Integer): Boolean;

function DownloadFILE_BLOCKING(const aUrl: string; const OutputFilename : String; const Agent : String) : Boolean;


function DownloadFILE_BLOCKING_method1(const aURL: string; const DestinationFileName: string; const UserAgent: string) : Boolean;
function DownloadFILE_BLOCKING_method2(const aUrl: string; const OutputFilename : String; const Agent : String; AccessType : Integer): Integer;
function DownloadFILE_BLOCKING_method3(const aUrl: string; const OutputFilename : String): Boolean;
function DownloadFILE_BLOCKING_method4(const aUrl: string; const OutputFilename : String): Boolean;
function DownloadFILE_BLOCKING_method5(const aUrl: string; const OutputFilename : String): Boolean;

function ArrayToString(const a: array of Char): string;

function GetWinInetError(ErrorCode:Cardinal): string;
Function RunAsAdminAndWait(Filename, Parameters : String; ShowMode : Integer = SW_SHOW; MaxWaitTimeMSEC : Integer = 5000) : Integer;



Var
 GLOB_Internet_DebugLog : TStringList;
 GLOB_Has_Internet      : Integer; // // 1: yes, 0: no, -1: unknown


implementation


function GetWinInetError(ErrorCode:Cardinal): string;
const
   winetdll = 'wininet.dll';
var
  Len: Integer;
  Buffer: PChar;
begin
  Len := FormatMessage(
  FORMAT_MESSAGE_FROM_HMODULE or FORMAT_MESSAGE_FROM_SYSTEM or
  FORMAT_MESSAGE_ALLOCATE_BUFFER or FORMAT_MESSAGE_IGNORE_INSERTS or  FORMAT_MESSAGE_ARGUMENT_ARRAY,
  Pointer(GetModuleHandle(winetdll)), ErrorCode, 0, @Buffer, SizeOf(Buffer), nil);
  try
    while (Len > 0) and {$IFDEF UNICODE}(CharInSet(Buffer[Len - 1], [#0..#32, '.'])) {$ELSE}(Buffer[Len - 1] in [#0..#32, '.']) {$ENDIF} do Dec(Len);
    SetString(Result, Buffer, Len);
  finally
    LocalFree(HLOCAL(Buffer));
  end;
end;

function ArrayToString(const a: array of Char): string;
Var
 i : Integer;
begin
  Result := '';

  if Length(a) > 0 then
  begin
    if a[Low(a)] = #0 then Exit; // null string

    for i := Low(a) to High(a) do
    begin
     if a[i] = #0 then Break;
     Result := Result + String(a[i]);
    end;

   // SetString(Result, PChar(@a[0]), Length(a));

  end;

end;



function DownloadFILE_BLOCKING(const aUrl: string; const OutputFilename : String; const Agent : String): Boolean;


  Function DoGetFileSize(const Filename : String) : Int64;
  var
   Sr : TSearchRec;
  begin

   Result := -1;
   If (Length(Filename) < 5) or (FileExists(Filename) = False) then Exit;

   Try
     Try
      FindFirst(Filename, faAnyFile, Sr);
      Result := Int64(Sr.FindData.nFileSizeHigh) shl Int64(32) +
                Int64(Sr.FindData.nFileSizeLow);
     Finally
      FindClose(sr);
     End;
   Except
     Result := -1;
   End;
  end;


Begin


 if (OutputFilename = '') or (Length(OutputFilename) < 5) or (OutputFilename[2] <> ':') or (OutputFilename[3] <> '\') then EXIT(FALSE);

 Try
 {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add(#13#10 + 'DownloadFILE_BLOCKING Start: ' + aUrl + ', To: ' + OutputFilename); {$ENDIF}
  DownloadFILE_BLOCKING_method1(aUrl, OutputFilename, Agent);
 Except
  Sleep(500);
 End;


 // Fallback:
 if (DoGetFileSize(OutputFilename) < 5) then
 begin
   Try
    {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add('DownloadFILE_BLOCKING FailSafe-m2 Start'); {$ENDIF}
    DownloadFILE_BLOCKING_method2(aUrl, OutputFilename, Agent, INTERNET_OPEN_TYPE_DIRECT);
   Except
    Sleep(500);
   End;
 end;


 // Fallback:
 if (DoGetFileSize(OutputFilename) < 5) then
 begin
  Try
   {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add('DownloadFILE_BLOCKING FailSafe-m3 Start'); {$ENDIF}
   DownloadFILE_BLOCKING_method3(aUrl, OutputFilename);
  Except
   Sleep(500);
  End;
 end;

 // Fallback:
 if (DoGetFileSize(OutputFilename) < 5) then
 begin
  Try
   {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add('DownloadFILE_BLOCKING FailSafe-m4 Start'); {$ENDIF}
   DownloadFILE_BLOCKING_method4(aUrl, OutputFilename);
  Except
   Sleep(500);
  End;
 end;

 // Fallback:
 if (DoGetFileSize(OutputFilename) < 5) then
 begin
  Try
   {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add('DownloadFILE_BLOCKING FailSafe-m5 Start'); {$ENDIF}
   DownloadFILE_BLOCKING_method5(aUrl, OutputFilename);
  Except
   Sleep(500);
  End;
 end;

 Result := (DoGetFileSize(OutputFilename) >= 5);

 If Result then
 begin
  GLOB_Has_Internet := 1;
  {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add('DownloadFILE_BLOCKING OK: ' + aUrl); {$ENDIF}
 End else
 begin
  if GLOB_Has_Internet = -1 then GLOB_Has_Internet := 0;
  {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add('DownloadFILE_BLOCKING Fail: ' + aUrl); {$ENDIF}
 End;

End;


Function TrimEx_Simple(const Str : String; const RemoveStr : String) : String;
Begin

 Result := Str;

 While (Result <> '') and (Pos(Result[1], RemoveStr) > 0) do Delete(Result, 1, 1);
 While (Result <> '') and (Pos(Result[Length(Result)], RemoveStr) > 0) do Result := Copy(Result, 1, Length(Result)-1);

End;

function DownloadFILE_BLOCKING_method1(const aURL: string; const DestinationFileName: string; const UserAgent: string) : Boolean;
var
  i        : Integer;
  hInet    : HINTERNET;
  hConnect : HINTERNET;
  hRequest : HINTERNET;
  HttpStatus: Integer;
  lpvBuffer : PAnsiChar;
  lpdwBufferLength: DWORD;
  lpdwReserved : DWORD;
  dwBytesRead : DWORD;
  lpdwNumberOfBytesAvailable: DWORD;
  dwBytesWritten: DWORD;
  FileHandle: THandle;
  ServerName : String;
  Resource   : String;
begin

  Result := False;
  hInet := InternetOpen(PChar(UserAgent), INTERNET_OPEN_TYPE_PRECONFIG, nil, nil, 0);

  if hInet = nil then
  begin
    //ErrorCode := GetLastError;
    //raise Exception.Create(Format('InternetOpen Error %d Description %s',[ErrorCode,GetWinInetError(ErrorCode)]));
    EXIT;
  end;

  i := Pos('.', aURL);
  if i < 2 then EXIT;

  i := PosEx('/', aURL, i);
  if i < 2 then EXIT;

  ServerName := Trim(Copy(aURL, 1, i-1));
  Resource   := Trim(Copy(aURL, i, Length(aURL)));
  ServerName := TrimEx_Simple(ServerName, ' :\/');

  i := Pos(':', ServerName);
  if i > 0 then ServerName := Trim(Copy(ServerName, i+1, Length(ServerName)));
  ServerName := TrimEx_Simple(ServerName, ' :\/');


  try
    hConnect := InternetConnect(hInet, PChar(ServerName), INTERNET_DEFAULT_HTTPS_PORT, nil, nil, INTERNET_SERVICE_HTTP, INTERNET_FLAG_SECURE, 1);
    if hConnect=nil then
    begin
    //  ErrorCode:=GetLastError;
    //  raise Exception.Create(Format('InternetConnect Error %d Description %s',[ErrorCode,GetWinInetError(ErrorCode)]));
     EXIT;
    end;

    try
      //make the request
      hRequest := HttpOpenRequest(hConnect, 'GET', PChar(Resource), HTTP_VERSION, '', nil, INTERNET_FLAG_SECURE, 0);
      if hRequest=nil then
      begin
        //ErrorCode:=GetLastError;
        //raise Exception.Create(Format('HttpOpenRequest Error %d Description %s',[ErrorCode,GetWinInetError(ErrorCode)]));
        EXIT;
      end;

      try
        //send the GET request
        if not HttpSendRequest(hRequest, nil, 0, nil, 0) then
        begin
          //ErrorCode:=GetLastError;
          //raise Exception.Create(Format('HttpSendRequest Error %d Description %s',[ErrorCode,GetWinInetError(ErrorCode)]));
          EXIT;
        end;

        lpdwBufferLength := SizeOf(HttpStatus);
        lpdwReserved :=0;
        //get the status code
        if not HttpQueryInfo(hRequest, HTTP_QUERY_STATUS_CODE or HTTP_QUERY_FLAG_NUMBER, @HttpStatus, lpdwBufferLength, lpdwReserved) then
        begin
          //ErrorCode := GetLastError;
          //raise Exception.Create(Format('HttpQueryInfo Error %d Description %s',[ErrorCode,GetWinInetError(ErrorCode)]));
          EXIT;
        end;

        FileHandle := CreateFile(PWideChar(DestinationFileName),GENERIC_WRITE,FILE_SHARE_WRITE,nil,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
        if FileHandle <> INVALID_HANDLE_VALUE then
        begin
         //if HttpStatus=200 then //read the body response in case which the status code is 200
          repeat
            lpdwNumberOfBytesAvailable := 0;
            if InternetQueryDataAvailable(hRequest, lpdwNumberOfBytesAvailable, 0, 0) then
            begin
              GetMem(lpvBuffer,lpdwNumberOfBytesAvailable);
              try
                InternetReadFile(hRequest, lpvBuffer, lpdwNumberOfBytesAvailable, dwBytesRead);
                WriteFile(FileHandle, lpvBuffer^, dwBytesRead, dwBytesWritten, nil);
                Result := True;
              finally
                FreeMem(lpvBuffer);
              end;
            end
          until lpdwNumberOfBytesAvailable <= 0;
          CloseHandle(FileHandle);
        end
        else
        begin
          //ErrorCode := GetLastError();
         // Log('Cannot create ' +DestinationFileName + ' file. Error Code = ' + IntToStr(ErrorCode) + '. File Attributes: ' + IntToHex(GetFileAttributes(PWideChar(DestinationFileName)), 8));
        end;
        //else
        //begin
        //  ErrorCode := GetLastError;
        //  raise Exception.Create(Format('InternetQueryDataAvailable Error %d Description %s',[ErrorCode,GetWinInetError(ErrorCode)]));
        //end;
      finally
        InternetCloseHandle(hRequest);
      end;
    finally
      InternetCloseHandle(hConnect);
    end;
  finally
    InternetCloseHandle(hInet);
  end;
end;

function DownloadFILE_BLOCKING_method3(const aUrl: string; const OutputFilename : String): Boolean;
Begin

 URLDownloadToFile(nil,
                  PChar(aUrl),
                  PChar(OutputFilename),
                  0,
                  nil);

 Result := FileExists(OutputFilename);

End;


function DownloadFILE_BLOCKING_method4(const aUrl: string; const OutputFilename : String): Boolean;
var
  IdHTTP: TIdHTTP;
  Stream: TMemoryStream;
begin

  Result := False;

  Stream := TMemoryStream.Create;
  IdHTTP := TIdHTTP.Create(nil);
  IdHTTP.IOHandler := TIdSSLIOHandlerSocketOpenSSL.Create(IdHTTP);
  IdHTTP.HandleRedirects := True;

  try
    Try
     IdHTTP.Get(aUrl, Stream);
     Stream.SaveToFile(OutputFilename);
    Except
     Exit;
    End;
  finally
    Stream.Free;
    IdHTTP.Free;
  end;

  Result := FileExists(OutputFilename);

End;



function DownloadFILE_BLOCKING_method5(const aUrl: string; const OutputFilename : String): Boolean;
Var
 cUrlPath : String;
 TmpPath  : String;
begin

 Result := False;

 cUrlPath := ExtractFilePath(Application.Exename) + 'cURL\curl.exe';
 if FileExists(cUrlPath) = False then cUrlPath := ExtractFilePath(Application.Exename) + 'cUrl\curl.exe';
 if FileExists(cUrlPath) = False then cUrlPath := ExtractFilePath(Application.Exename) + 'curl\curl.exe';

 if FileExists(cUrlPath) = False then
 begin
  {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add('DownloadFILE_BLOCKING_method5 FAIL-1: ' + cUrlPath); {$ENDIF}
  EXIT;
 End;




 TmpPath := ExtractFilePath(OutputFilename);
 if DirectoryExists(TmpPath) = False then
 begin
  {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add('DownloadFILE_BLOCKING_method5 FAIL-2: ' + TmpPath); {$ENDIF}
  EXIT;
 End;

 {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add('DownloadFILE_BLOCKING_method5 Start: ' + cUrlPath); {$ENDIF}

 RunAsAdminAndWait(cUrlPath, ' -o "' + OutputFilename +'" '+ aUrl, SW_HIDE, 30000);

 Result := FileExists(OutputFilename);

End;


Function RunAsAdminAndWait(Filename, Parameters : String; ShowMode : Integer = SW_SHOW; MaxWaitTimeMSEC : Integer = 5000) : Integer;
var
  Info     : TShellExecuteInfo;
  ExitCode : DWORD;
  Start    : UInt64;
begin
  Result := -1;

  FillChar(Info, SizeOf(Info), 0);
  Info.cbSize := SizeOf(TShellExecuteInfo);
  Info.fMask  := SEE_MASK_NOCLOSEPROCESS;
  Info.Wnd    := Application.Handle;
  Info.lpVerb := 'RunAs';
  Info.lpFile := PWideChar(Filename);
  Info.lpParameters := PWideChar(Parameters);
  Info.nShow := ShowMode;
  Start := GetTickCount64();

  if ShellExecuteEx(@Info) and (MaxWaitTimeMSEC > 1) then
  begin
    ExitCode := 0;

    while True do
    begin
      Sleep(100); Application.ProcessMessages;
      GetExitCodeProcess(Info.hProcess, ExitCode);

      If (ExitCode <> STILL_ACTIVE) or (Application = nil) or (Application.Terminated) then Break;
      if GetTickCount64() - Start > MaxWaitTimeMSEC then Break;
    End;

    Result := ExitCode;
  end;

end;

function DownloadFILE_BLOCKING_method2(const aUrl: string; const OutputFilename : String; const Agent : String; AccessType : Integer): Integer;
var
  hSession    : HINTERNET;
  hService    : HINTERNET;
  lpBuffer    : array[0..1024 + 1] of Char;
  dwBytesRead : DWORD;
  Start       : UInt64;
  FileOut     : TFileStream;
begin
  Result  := 0;
  Start   := GetTickCount64();

  Try
    if FileExists(OutputFilename) then DeleteFile(PWideChar(OutputFilename));
  Except
    Exit;
  End;

  FileOut := TFileStream.Create(OutputFilename, fmCreate);
  hSession := InternetOpen(PWideChar(Agent), AccessType, nil, nil, 0);

  try
    if Assigned(hSession) then
    begin
      //hService := InternetOpenUrl(hSession, PWideChar(aUrl), nil, 0, INTERNET_FLAG_IGNORE_CERT_CN_INVALID or INTERNET_FLAG_IGNORE_CERT_DATE_INVALID or INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP or INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS or INTERNET_FLAG_NO_UI, 0);

      hService := InternetOpenUrl(hSession, PWideChar(aUrl), nil, 0, INTERNET_FLAG_RELOAD or INTERNET_FLAG_PRAGMA_NOCACHE or INTERNET_FLAG_IGNORE_CERT_CN_INVALID or INTERNET_FLAG_IGNORE_CERT_DATE_INVALID or INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP or INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS or INTERNET_FLAG_NO_UI, 0);
      if not Assigned(hService) then hService := InternetOpenUrl(hSession, PWideChar(aUrl), nil, 0, INTERNET_FLAG_RELOAD or INTERNET_FLAG_PRAGMA_NOCACHE or INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS or INTERNET_FLAG_NO_UI, 0);
      if not Assigned(hService) then hService := InternetOpenUrl(hSession, PWideChar(aUrl), nil, 0, INTERNET_FLAG_RELOAD or INTERNET_FLAG_PRAGMA_NOCACHE or INTERNET_FLAG_NO_UI, 0);
      if not Assigned(hService) then hService := InternetOpenUrl(hSession, PWideChar(aUrl), nil, 0, INTERNET_FLAG_NO_UI, 0);

      if not Assigned(hService) then hService := InternetOpenUrl(hSession, PWideChar(aUrl), nil, 0, INTERNET_FLAG_RELOAD or INTERNET_FLAG_IGNORE_CERT_CN_INVALID or INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
      if not Assigned(hService) then hService := InternetOpenUrl(hSession, PWideChar(aUrl), nil, 0, INTERNET_FLAG_RELOAD or INTERNET_FLAG_IGNORE_CERT_CN_INVALID, 0);
      if not Assigned(hService) then hService := InternetOpenUrl(hSession, PWideChar(aUrl), nil, 0, INTERNET_FLAG_RELOAD, 0);
      if not Assigned(hService) then hService := InternetOpenUrl(hSession, PWideChar(aUrl), nil, 0, 0, 0);


      if Assigned(hService) then
        try

          while True do
          begin
            dwBytesRead := 1024;
            InternetReadFile(hService, @lpBuffer, 1024, dwBytesRead);
            if dwBytesRead = 0 then break;

            lpBuffer[dwBytesRead] := #0;
            FileOut.Write(lpBuffer, dwBytesRead);

            // Timeout
            if (GetTickCount64() - Start) > 30000 then
            begin
             Result := -1;
             Break;
            end;

            Result := 1;
          end;
        finally
          InternetCloseHandle(hService);
        end;
    end;
  finally
    InternetCloseHandle(hSession);
    FileOut.Free
  end;
end;



function DownloadURL_BLOCKING_Method1(const aUrl: string; var s: String; const Agent : String): Boolean;
var
  i        : Integer;
  hInet    : HINTERNET;
  hConnect : HINTERNET;
  hRequest : HINTERNET;
  HttpStatus: Integer;
  ErrorCode : Integer;
  lpvBuffer : PAnsiChar;
  lpdwBufferLength: DWORD;
  lpdwReserved : DWORD;
  dwBytesRead : DWORD;
  lpdwNumberOfBytesAvailable: DWORD;
  ServerName : String;
  Resource   : String;
begin

  Result := False;
  s := '';

  hInet := InternetOpen(PChar(Agent), INTERNET_OPEN_TYPE_PRECONFIG, nil, nil, 0);

  {$IFDEF Use_Debug_Log}
  if Assigned(hInet) then GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING_Method1 hInet: OK')
  else begin ErrorCode := GetLastError(); GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING_Method1 hInet: FAIL - Error Code: ' + IntToStr(ErrorCode) + ', Error Desc: ' +GetWinInetError(ErrorCode)); End;
  {$ENDIF}

  if hInet = nil then EXIT;



  i := Pos('.', aURL);
  if i < 2 then EXIT;

  i := PosEx('/', aURL, i);
  if i < 2 then EXIT;

  ServerName := Trim(Copy(aURL, 1, i-1));
  Resource := Trim(Copy(aURL, i, Length(aURL)));
  ServerName := TrimEx_Simple(ServerName, ' :\/');

  i := Pos(':', ServerName);
  if i > 0 then ServerName := Trim(Copy(ServerName, i+1, Length(ServerName)));
  ServerName := TrimEx_Simple(ServerName, ' :\/');


  try
    hConnect := InternetConnect(hInet, PChar(ServerName), INTERNET_DEFAULT_HTTPS_PORT, nil, nil, INTERNET_SERVICE_HTTP, INTERNET_FLAG_SECURE, 1);


    {$IFDEF Use_Debug_Log}
    if Assigned(hConnect) then GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING_Method1 hConnect: OK')
    else begin ErrorCode := GetLastError(); GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING_Method1 hConnect: FAIL - Error Code: ' + IntToStr(ErrorCode) + ', Error Desc: ' +GetWinInetError(ErrorCode)); End;
    {$ENDIF}

    if hConnect=nil then EXIT;

    try
      //make the request
      hRequest := HttpOpenRequest(hConnect, 'GET', PChar(Resource), HTTP_VERSION, '', nil, INTERNET_FLAG_SECURE, 0);

      {$IFDEF Use_Debug_Log}
      if Assigned(hRequest) then GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING_Method1 hRequest: OK')
      else begin ErrorCode := GetLastError(); GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING_Method1 hRequest: FAIL - Error Code: ' + IntToStr(ErrorCode) + ', Error Desc: ' +GetWinInetError(ErrorCode)); End;
      {$ENDIF}

      if hRequest=nil then EXIT;

      try
        //send the GET request
        if not HttpSendRequest(hRequest, nil, 0, nil, 0) then
        begin


        {$IFDEF Use_Debug_Log}
        ErrorCode := GetLastError();
        GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING_Method1 HttpSendRequest: FAIL - Error Code: ' + IntToStr(ErrorCode) + ', Error Desc: ' +GetWinInetError(ErrorCode));
        {$ENDIF}

         EXIT;
        end;

        lpdwBufferLength := SizeOf(HttpStatus);
        lpdwReserved :=0;

        //get the status code
        if not HttpQueryInfo(hRequest, HTTP_QUERY_STATUS_CODE or HTTP_QUERY_FLAG_NUMBER, @HttpStatus, lpdwBufferLength, lpdwReserved) then
        begin

         {$IFDEF Use_Debug_Log}
         ErrorCode := GetLastError();
         GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING_Method1 HttpQueryInfo: FAIL - Error Code: ' + IntToStr(ErrorCode) + ', Error Desc: ' +GetWinInetError(ErrorCode));
         {$ENDIF}

          EXIT;
        end;

         //if HttpStatus=200 then //read the body response in case which the status code is 200
          repeat
            lpdwNumberOfBytesAvailable := 0;

            if InternetQueryDataAvailable(hRequest, lpdwNumberOfBytesAvailable, 0, 0) and (lpdwNumberOfBytesAvailable > 0) then
            begin
              GetMem(lpvBuffer,lpdwNumberOfBytesAvailable+1);
              try
                dwBytesRead := 0;
                InternetReadFile(hRequest, lpvBuffer, lpdwNumberOfBytesAvailable, dwBytesRead);
                //WriteFile(FileHandle, lpvBuffer^, dwBytesRead, dwBytesWritten, nil);

                If dwBytesRead < 1 then Break;
                lpvBuffer[dwBytesRead] := #0;
                s := s + String(lpvBuffer);

                Result := True;
              finally
                FreeMem(lpvBuffer);
              end;
            end else Break;

          until lpdwNumberOfBytesAvailable <= 0;

      finally
        InternetCloseHandle(hRequest);
      end;
    finally
      InternetCloseHandle(hConnect);
    end;
  finally
    InternetCloseHandle(hInet);
  end;

end;



function DownloadURL_BLOCKING(const aUrl: string; var s: String; const Agent : String): Boolean;
Var
 ResStr      : String;
 TmpDir      : String;
 TmpFilename : String;
 TmpList     : TStringList;
 ReadFail    : Boolean;
begin

 s        := '';
 ResStr   := '';
 ReadFail := False;
 Result   := False;

 Try
  {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add(#13#10 + 'DownloadURL_BLOCKING Start: ' + aUrl + ', As: ' + Agent); {$ENDIF}
  Result := DownloadURL_BLOCKING_Method1(aUrl, ResStr, Agent);
  s := ResStr;
 Except
  ReadFail := True;
 End;


 // Failsafe:
 if (ReadFail) or (Result = False) or (Trim(ResStr) = '') then
 begin
   Try
    {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING Failsafe-m2-a Start'); {$ENDIF}
    Result := DownloadURL_BLOCKING_Method2(aUrl, ResStr, Agent, INTERNET_OPEN_TYPE_PRECONFIG);
   Except
    ReadFail := True;
   End;

   s := ResStr;
 End;


 // Failsafe:
 if (ReadFail) or (Result = False) or (Trim(ResStr) = '') then
 begin
  {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING Failsafe-m2-b Start'); {$ENDIF}

   Try
    ResStr := '';
    Result := DownloadURL_BLOCKING_Method2(aUrl, ResStr, Agent, INTERNET_OPEN_TYPE_DIRECT);
    ReadFail := False;
   Except
    ReadFail := True;
   End;

   s := ResStr;
 end;



 // Failsafe via DownloadFILE_BLOCKING:
 if (ReadFail) or (Result = False) or (Trim(ResStr) = '') then
 begin
  TmpDir := System.IOUtils.TPath.GetTempPath();
  {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING Failsafe-by-File Start: ' + TmpDir); {$ENDIF}

  if (Copy(TmpDir, 2, 2) = ':\') and
     (DirectoryExists(TmpDir)) then
  begin
   TmpFilename := TmpDir + 'DownloadUrl_Failsafe_' + IntToStr(GetTickCount64()) + '.tmp';
   {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING Failsafe-by-File File: ' + TmpFilename); {$ENDIF}


   if FileExists(TmpFilename) = False then
   begin
    DownloadFILE_BLOCKING(aUrl, TmpFilename, Agent);

    if FileExists(TmpFilename) then
    begin
     TmpList := TStringList.Create;
     ReadFail := False;
    {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING Failsafe-by-File File Exists!'); {$ENDIF}

     Try
      TmpList.LoadFromFile(TmpFilename, TEncoding.UTF8);
     Except
      ReadFail := True;
     End;

     if ReadFail then
     begin
      ReadFail := False;

      Try
       TmpList.LoadFromFile(TmpFilename);
      Except
       ReadFail := True;
      End;
     end;

    {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING Failsafe-by-File File Size: ' + IntToStr(TmpList.Count)); {$ENDIF}

     If ReadFail = False then
     begin
      s := TmpList.Text;
      Result := s <> '';
     End;

     TmpList.Free;

     Try
      DeleteFile(TmpFilename);
     Except
       ;
     End;
    end else
    begin

     {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING Failsafe-by-File Download Failed'); {$ENDIF}

    End;
   end;
  end;
 end;



 If Result then
 begin
  GLOB_Has_Internet := 1;
  {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING OK: ' + aUrl + ', Res: ' + s); {$ENDIF}
 End else
 begin
  if GLOB_Has_Internet = -1 then GLOB_Has_Internet := 0;
  {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING Fail: ' + aUrl); {$ENDIF}
 End;


end;


function DownloadURL_BLOCKING_Method2(const aUrl: string; var s: String; const Agent : String; AccessType : Integer): Boolean;
var
  hSession    : HINTERNET;
  hService    : HINTERNET;
  lpBuffer    : array[0..1024 + 1] of AnsiChar;
  dwBytesRead : DWORD;
  Start       : UInt64;
  FinalURL    : String;
begin
  Result := False;
  s := '';
  Start := GetTickCount64();
  FinalURL := Trim(aUrl);

  hSession := InternetOpen(PWideChar(Agent), AccessType, nil, nil, 0);

  {$IFDEF Use_Debug_Log} if Assigned(hSession) then GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING_Do hSession: OK') else GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING_Do hSession: Fail'); {$ENDIF}


  try
    if Assigned(hSession) then
    begin
      hService := InternetOpenUrl(hSession, PWideChar(FinalURL), nil, 0, INTERNET_FLAG_DONT_CACHE or INTERNET_FLAG_PRAGMA_NOCACHE or INTERNET_FLAG_RELOAD, 0);
      {$IFDEF Use_Debug_Log} If not Assigned(hService) then GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING_Do GetLastError: ' + IntToStr(GetLastError)); {$ENDIF}

      if not Assigned(hService) then hService := InternetOpenUrl(hSession, PWideChar(FinalURL), nil, 0, INTERNET_FLAG_DONT_CACHE or INTERNET_FLAG_PRAGMA_NOCACHE or INTERNET_FLAG_RELOAD, 0);
      {$IFDEF Use_Debug_Log} If not Assigned(hService) then GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING_Do GetLastError: ' + IntToStr(GetLastError)); {$ENDIF}
      if not Assigned(hService) then hService := InternetOpenUrl(hSession, PWideChar(FinalURL), nil, 0, INTERNET_FLAG_RELOAD or INTERNET_FLAG_PRAGMA_NOCACHE or INTERNET_FLAG_IGNORE_CERT_CN_INVALID or INTERNET_FLAG_IGNORE_CERT_DATE_INVALID or INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP or INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS or INTERNET_FLAG_NO_UI, 0);

      if not Assigned(hService) then hService := InternetOpenUrl(hSession, PWideChar(FinalURL), nil, 0, INTERNET_FLAG_RELOAD or INTERNET_FLAG_PRAGMA_NOCACHE or INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS or INTERNET_FLAG_NO_UI, 0);
      if not Assigned(hService) then hService := InternetOpenUrl(hSession, PWideChar(FinalURL), nil, 0, INTERNET_FLAG_RELOAD or INTERNET_FLAG_PRAGMA_NOCACHE or INTERNET_FLAG_NO_UI, 0);
      if not Assigned(hService) then hService := InternetOpenUrl(hSession, PWideChar(FinalURL), nil, 0, INTERNET_FLAG_NO_UI, 0);

      if not Assigned(hService) then hService := InternetOpenUrl(hSession, PWideChar(FinalURL), nil, 0, INTERNET_FLAG_RELOAD or INTERNET_FLAG_IGNORE_CERT_CN_INVALID or INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
      if not Assigned(hService) then hService := InternetOpenUrl(hSession, PWideChar(FinalURL), nil, 0, INTERNET_FLAG_RELOAD or INTERNET_FLAG_IGNORE_CERT_CN_INVALID, 0);
      if not Assigned(hService) then hService := InternetOpenUrl(hSession, PWideChar(FinalURL), nil, 0, INTERNET_FLAG_RELOAD, 0);
      if not Assigned(hService) then hService := InternetOpenUrl(hSession, PWideChar(FinalURL), nil, 0, 0, 0);




      {$IFDEF Use_Debug_Log} If not Assigned(hService) then GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING_Do GetLastError: ' + IntToStr(GetLastError)); {$ENDIF}
      {$IFDEF Use_Debug_Log} if Assigned(hService) then GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING_Do hService: OK') else GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING_Do hService: Fail'); {$ENDIF}

      if Assigned(hService) then
        try

          while True do
          begin

            dwBytesRead := 1024;
            InternetReadFile(hService, @lpBuffer, 1024, dwBytesRead);

            {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING_Do dwBytesRead: ' + IntToStr(dwBytesRead));  {$ENDIF}
            if dwBytesRead = 0 then break;

            lpBuffer[dwBytesRead] := #0;
            s := s + String(lpBuffer);
            {$IFDEF Use_Debug_Log} GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING_Do s: ' + s);  {$ENDIF}

            if (GetTickCount64() - Start) > 10000 then
            begin
             s := '';
             Break;
            end;

          end;

          Result := s <> '';
        finally
          InternetCloseHandle(hService);
        end;
    end;
  finally
    InternetCloseHandle(hSession);
  end;


  {$IFDEF Use_Debug_Log} If Result then GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING_Do Result: OK') else GLOB_Internet_DebugLog.Add('DownloadURL_BLOCKING_Do Result: Fail'); {$ENDIF}
end;



initialization

 GLOB_Internet_DebugLog := TStringList.Create;
 GLOB_Has_Internet := -1;



end.
