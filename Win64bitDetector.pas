unit Win64bitDetector;

{$R-,T-,X+,H+,B-,O+,Q-}

interface

Uses
  madExcept, Windows, Messages;


type
 TWow64DisableWow64FsRedirection = function ( var Wow64FsEnableRedirection: LongBool): LongBool; StdCall;
 TWow64RevertWow64FsRedirection  = function ( var Wow64FsEnableRedirection: LongBool): LongBool; StdCall;


Procedure Detect64bitWindows();
function Is64bitWindows() : Boolean;

Procedure Wow64_DisableRedirection();
Procedure Wow64_RestoreRedirection();

Var
 GLOBAL_Wow64FsEnableRedirection       : LongBool;
 GLOBAL_Wow64RedirectionDisabled       : Boolean = False;
 GLOBAL_Wow64RevertWow64FsRedirection  : TWow64RevertWow64FsRedirection = nil;
 GLOBAL_Wow64DisableWow64FsRedirection : TWow64DisableWow64FsRedirection = nil;
 GLOBAL_is64bitWindows                 : Integer = -1; //0 = No, 1 = Yes, -1 = Not checked yet

implementation


Procedure Detect64bitWindows();
var
 hHandle : THandle;
Begin

 Try
   GLOBAL_is64bitWindows                 := -1;
   GLOBAL_Wow64DisableWow64FsRedirection := nil;
   GLOBAL_Wow64RevertWow64FsRedirection  := nil;

   If Is64bitWindows() then
   begin
     hHandle := GetModuleHandle('kernel32.dll');
     @GLOBAL_Wow64RevertWow64FsRedirection  := GetProcAddress(hHandle, PAnsiChar(AnsiString('Wow64RevertWow64FsRedirection')));
     @GLOBAL_Wow64DisableWow64FsRedirection := GetProcAddress(hHandle, PAnsiChar(AnsiString('Wow64DisableWow64FsRedirection')));
   End;
 Except
  Exit;
 End;


End;

Procedure Wow64_DisableRedirection();
Begin

 Try
   If Is64bitWindows() and
      Assigned(GLOBAL_Wow64RevertWow64FsRedirection) and
      Assigned(GLOBAL_Wow64DisableWow64FsRedirection) then
   begin
    GLOBAL_Wow64DisableWow64FsRedirection(GLOBAL_Wow64FsEnableRedirection);
    GLOBAL_Wow64RedirectionDisabled := True;
   End;
 Except
  Exit;
 End;

End;

Procedure Wow64_RestoreRedirection();
Begin

 if GLOBAL_Wow64RedirectionDisabled = False then Exit;

 Try
   If Is64bitWindows() and
      Assigned(GLOBAL_Wow64RevertWow64FsRedirection) and
      Assigned(GLOBAL_Wow64DisableWow64FsRedirection) then
   begin
    GLOBAL_Wow64RevertWow64FsRedirection(GLOBAL_Wow64FsEnableRedirection);
    GLOBAL_Wow64RedirectionDisabled := False;
   End;
 Except
  Exit;
 End;

End;

function Is64bitWindows() : Boolean;
type
  TIsWow64Process = function( // Type of IsWow64Process API fn
    Handle: THandle;
    var Res: BOOL
  ): BOOL; stdcall;
var
  IsWow64Result: BOOL;              // result from IsWow64Process
  IsWow64Process: TIsWow64Process;  // IsWow64Process fn reference
begin


 if GLOBAL_is64bitWindows = 1 then
 begin
  Result := True;
  Exit;
 end Else
 Begin
  if GLOBAL_is64bitWindows = 0 then
  begin
   Result := False;
   Exit;
  end;
 End;

 Try
  // Try to load required function from kernel32
  IsWow64Process := GetProcAddress(GetModuleHandle('kernel32'), PAnsiChar(AnsiString('IsWow64Process')) );

  if Assigned(IsWow64Process) then
  begin
    // Function is implemented: call it
    if not IsWow64Process(GetCurrentProcess, IsWow64Result) then
    begin
     Result := False; //internal error
     Exit;
    End;

    // Return result of function
    Result := IsWow64Result;
  end
  else
    // Function not implemented: can't be running on Wow64
    Result := False;
 Except
  Result := False;
 End;

 if Result then GLOBAL_is64bitWindows := 1
 else           GLOBAL_is64bitWindows := 0;

end;

initialization

 GLOBAL_is64bitWindows := -1;


end.
