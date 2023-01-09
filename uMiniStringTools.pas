unit uMiniStringTools;


interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils,
  System.Variants, System.Classes, Vcl.Graphics,
  FastStringCaseUtils,
  Generics.Collections,
  System.Character,
  System.StrUtils,
  System.NetEncoding,
  ShellAPI;


  Function UrlSafeEncode(const AStr : String) : String;
  Function BoolToIntStr(const b : Boolean) : String;
  Function MakeDelphiString(const Str : String) : String;

  function Murmur2Hash(const AString: String): LongWord;

  function GetSystemDecimalSeparator() : Char;

  Function StringCompare(Const Str1 : String; Const Str2 : String) : Boolean;          Overload;
  function StringCompare(Const Str1 : String; Const Str2 : Array of String) : Boolean; Overload;

  Function StringCompareBegin(const SubStr : String; const Str : String) : Boolean;          Overload;
  Function StringCompareBegin(const SubStr : Array of String; const Str : String) : Boolean; Overload;

  Function StringCompareEnd(const SubStr : String; const Str : String) : Boolean;

  Function FastPosExArr(Const SubStrs : Array of String; Const Str : String) : Boolean;
  Function FastPosExB(const Substr : String; const Str : String; i : Integer = 1; CaseSensitive : Boolean = False): Boolean;
  Function FastPosEx(const Substr : String; const Str : String; i : Integer = 1; CaseSensitive : Boolean = False; SkipHits : Integer = 0): Integer;

  Function CopyFrom(Const Source: String; Const SubStr : String; CopyEndOffset : Integer = 0; SkipHits : Integer = 0) : String;

  Function RemoveTrailingWords(Const Str : String; Const SubStrs : Array of String) : String; overload;
  Function RemoveTrailingWords(Const Str : String; Const SubStr : String) : String; overload;

  Function RawReadFile_UTF8(const Filename : String; MaxLen : Integer = -1) : String;

  Function Explode(const Sep : Char; Const Str : String) : TStringList;
  Function ExplodeEx(const Sep : Char; Const Str : String; const ReturnItemIdx : Integer) : String;
  Function ExplodeFrom(Const Separator : String; Const Str : String; ReturnItemsUpFromIndex : Integer) : String;

  Procedure AddToStringList(const Dest : TStringList; const Source : TStringList);

  Function Implode(const Sep : String; Const List : TStringList) : String;
  Function FastCharCount(const Sep : Char; Const Str : String) : Integer;
  Function Capitalize(Const Str : String) : String;

  Function LookLikeEmailAddress(const Str : String) : Boolean;

  Function EnsureTrail(const Str : String) : String;
  Function RemoveTrail(const Str : String) : String;
  Function ExtractFilePathOrRegKey(Const InputStr : String) : String;
  Function ExtractTopDir(Dir : String) : String;
  Function UpOneDir(Dir : String) : String;

  function ArrayToString(const a: array of Char): string;
  Function PathCase(const Str : String) : String;

  Function ReadVarValueFromList(const List : TStringList; const VarName : String) : String;

  Function LooksLikePath(const Str : String) : Boolean;

  Function trim_non_numeric(const str : String; const EndOnly : Boolean = False) : String;
  Function trim_non_alpha(const str : String; const EndOnly : Boolean = False) : String;
  Function trim_non_alphanum(const str : String; const EndOnly : Boolean = False) : String;

  Function make_safe_str(const str : String) : String;

  Function strip_non_alphanum(const Str : String) : String;
  Function strip_non_alpha(const Str : String) : String;
  Function strip_non_alpha_ws(const Str : String) : String;

  Function IsNumericHex(const Data : String; AllowSpaces : Boolean = False) : Boolean;
  Function IsPseudoGUID(const Data : String) : Boolean;
  Function TrimEx(const InputStr : String; const CharsToRemove : String; EndOnly : Boolean = False; StartOnly : Boolean = False) : String;

  Function StringReplaceEx(const Str : String; const Search : String; const Replace : String) : String;          Overload;
  Function StringReplaceEx(const Str : String; const Search : Array of String; const Replace : String) : String; Overload;

  Function StringReplaceEx_AllNonNumeric(const Str : String; const ReplaceWith : Char) : String;

  Function StringReplaceEx_SpecialCase2(const Str : String) : String;
  Function StringReplaceEx_SpecialCase1(const Str : String; const SearchArr : Array of Char; const ReplaceChr : Char) : String;

  Function ExtractExeNameOrPath(const Str : String) : String;

  Function html_link(const Text : String; const URL : String; const OpenInNewWindow : Boolean = False) : String;



implementation



Function html_link(const Text : String; const URL : String; const OpenInNewWindow : Boolean = False) : String;
Var
 Addon : String;
Begin

 if OpenInNewWindow then Addon := ' target="_blank" ' else Addon := '';


 if Text <> '' then
      Result := '<a href="' + FastLowerCase_Trim(URL) + '"'+Addon+'>' + Trim(Text) + '</a>'
 else Result := '<a href="' + FastLowerCase_Trim(URL) + '"'+Addon+'>' + URL + '</a>';

End;


// Case: 'c75145410ad03cd9dcb1a13827f0d0497bd1306b'
Function IsPseudoGUID(const Data : String) : Boolean;
Var
 i   : Integer;
 Len : Integer;
 c   : Char;
Begin

 Len := Length(Data);
 if (Len < 16) or (Len > 45) then EXIT(FALSE);

 Result := True;
 for i := 1 to Len do
 begin
  if Data[i].IsWhiteSpace or Data[i].IsControl then EXIT(FALSE);
  if Data[i].IsLetter then
  begin
   c := Data[i].ToLower;
   if (c <> 'a') and (c <> 'b') and (c <> 'c') and (c <> 'd') and (c <> 'e') and (c <> 'f') then EXIT(FALSE);
  end;
 end;

End;

// Note: We allow starting 'x', even though normally 'x' is not a part of hex (A to F):
// e.g. 'x01f10f731acb26a8163760165354860485a1f29b50c305445d4031e33f261a' is allowed!
Function IsNumericHex(const Data : String; AllowSpaces : Boolean = False) : Boolean;
Const
 Alpha = 'abcdef';
 Num   = '1234567890';
Var
 i   : Integer;
 Len : Integer;
 c   : Char;
begin

 Len := Length(Data);
 if Len = 0 then EXIT(False);

 Result := True;

 For i := 1 to Len do
 begin
  c := Data[i];
  if (i = 1) and ((c = 'x') or (c = 'X')) then Continue;
  If (AllowSpaces and (c = ' ')) then Continue;

  if ((c = '0') or (c = '1') or (c = '2') or (c = '3') or (c = '4') or (c = '5') or
      (c = '6') or (c = '7') or (c = '8') or (c = '9') or
      (c = 'A') or (c = 'B') or (c = 'C') or (c = 'D') or (c = 'E') or (c = 'F') or
      (c = 'a') or (c = 'b') or (c = 'c') or (c = 'd') or (c = 'e') or (c = 'f')) = False then
  begin
   Result := False;
   Break;
  end;
 End;


End;



function GetSystemDecimalSeparator() : Char;
Var
 TmpStr : String;
begin

 Result := '.';
 TmpStr := FloatToStr(1/2);
 If Length(TmpStr) > 2 then Result := TmpStr[2];

End;


Function StringCompareEnd(const SubStr : String; const Str : String) : Boolean;
Begin
 Result := Str.EndsWith(SubStr, True);
End;

Function StringCompareBegin(const SubStr : String; const Str : String) : Boolean;
Begin
 Result := Str.StartsWith(SubStr, True);
End;

Function StringCompareBegin(const SubStr : Array of String; const Str : String) : Boolean;
var
 SubStrTmp : String;
begin
  Result := false;

  for SubStrTmp in SubStr do
  begin
    if (SubStrTmp <> '') and (Str.StartsWith(SubStrTmp, True)) then Exit(True);
  end;
End;

function StringCompare(Const Str1 : String; Const Str2 : Array of String) : Boolean;
var
 SubStr : String;
begin
  Result := false;

  for SubStr in Str2 do
  begin
    if (SubStr <> '') and (StringCompare(Str1, SubStr)) then Exit(true);
  end;

end;

Function StringCompare(Const Str1 : String; Const Str2 : String) : Boolean;
Var
 i    : Integer;
 len1 : Integer;
 len2 : Integer;
Begin
 {$IFDEF EnablePerformanceLog} try PerfLog_SectionBegin('FastStringUtils.StringCompare6', nil, TRUE); {$ENDIF}

 len1 := Length(Str1);
 len2 := Length(Str2);

 if len1 <> len2 then EXIT(FALSE);
 if len1 = 0 then EXIT(TRUE); // Special Case: StringCompare('', '') = True

 for i := 1 to len1 do
  if GLOB_CharLowCaseTable[Str1[i]] <> GLOB_CharLowCaseTable[Str2[i]] then EXIT(FALSE);


 EXIT(TRUE);


 {$IFDEF EnablePerformanceLog} finally PerfLog_SectionEnd('FastStringUtils.StringCompare6'); end; {$ENDIF}
End;


Function make_safe_str(const str : String) : String;
Var
 i : Integer;
Begin

 for i := 1 to Length(Str) do
 begin
  if (Str[i].IsLetter) or
     (Str[i].IsNumber) or
     (Str[i] = '!') or
     (Str[i] = '?') or
     (Str[i] = ' ') or
     (Str[i] = ':') or
     (Str[i] = ',') or
     (Str[i] = '.') or
     (Str[i] = '-') or
     (Str[i] = '&') then Result := Result + Str[i];
 end;

 Result := StringReplaceEx(Result, '  ', ' ');
 Result := Trim(Result);

End;

Function strip_non_alphanum(const Str : String) : String;
Var
 i : Integer;
Begin

 Result := '';

 for i := 1 to Length(Str) do
 begin
  if Str[i].IsLetter or Str[i].IsNumber then Result := Result + Str[i];
 end;

End;

Function strip_non_alpha(const Str : String) : String;
Var
 i : Integer;
Begin

 Result := '';

 for i := 1 to Length(Str) do
 begin
  if Str[i].IsLetter then Result := Result + Str[i];
 end;

End;

Function strip_non_alpha_ws(const Str : String) : String;
Var
 i : Integer;
Begin

 Result := '';

 for i := 1 to Length(Str) do
 begin
  if Str[i].IsLetter or Str[i].IsWhiteSpace then Result := Result + Str[i];
 end;

End;


Function trim_non_alpha(const str : String; const EndOnly : Boolean = False) : String;
Var
 i : Integer;
Begin
 {$IFDEF EnablePerformanceLog} try PerfLog_SectionBegin('FastStringUtils.trim_non_alpha', nil, TRUE); {$ENDIF}

 Result := Str;

 If EndOnly = False then
 begin
   while (Result <> '') do
   begin
    if Result[1].IsLetter then Break;
    Delete(Result, 1, 1);
   end;
 End;

 while (Result <> '') do
 begin
  i := Length(Result);
  if i <= 0 then Break;
  if Result[i].IsLetter then Break;

  Delete(Result, i, 1);
 end;

 {$IFDEF EnablePerformanceLog} finally PerfLog_SectionEnd('FastStringUtils.trim_non_alpha'); end; {$ENDIF}
End;

Function trim_non_alphanum(const str : String; const EndOnly : Boolean = False) : String;
Var
 i : Integer;
Begin
 {$IFDEF EnablePerformanceLog} try PerfLog_SectionBegin('FastStringUtils.trim_non_alphanum', nil, TRUE); {$ENDIF}

 Result := Str;

 If EndOnly = False then
 begin
   while (Result <> '') do
   begin
    if Result[1].IsLetterOrDigit then Break;
    Delete(Result, 1, 1);
   end;
 End;

 while (Result <> '') do
 begin
  i := Length(Result);
  if i <= 0 then Break;
  if Result[i].IsLetterOrDigit then Break;

  Delete(Result, i, 1);
 end;

 {$IFDEF EnablePerformanceLog} finally PerfLog_SectionEnd('FastStringUtils.trim_non_alphanum'); end; {$ENDIF}
End;

// Does the input look like a file or registry path
Function LooksLikePath(const Str : String) : Boolean;
Var
 i      : Integer;
 Len    : Integer;
 TmpStr : String;
begin

 Result := False;
 Len := Length(Str);
 if Len < 3 then EXIT;

 // file path:
 if (Str[2] = ':') and (Str[3] = '\') then
 begin
  if (Len > 3) and
     ((Str[4] = '\') or
      (Str[4] = ':')) then EXIT;

  if Str[1].IsLetter = False then EXIT;

  // Final checks:
  if Pos('\\', Str) > 0 then EXIT;
  if Pos('"', Str) > 0 then EXIT;

  Result := True;
 end else

 // Registry data:
 if (Len > 8) and (Str.StartsWith('hkey_', True)) then
 begin
  // Case: 'hkey_local_machine\hkey_local_machine\foo'
  TmpStr := ExplodeEx('\', TmpStr, 1);
  if TmpStr.StartsWith('hkey_', True) then EXIT;

  i := Pos('\ :', Str);
  if i > 0 then TmpStr := Copy(Str, 1, i-1) else TmpStr := Str;

  // Final checks:
  if Pos('\\', TmpStr) > 0 then EXIT;
  if Pos('"', TmpStr) > 0 then EXIT;

  Result := True;
 end;

end;

Function trim_non_numeric(const str : String; const EndOnly : Boolean = False) : String;
Var
 i : Integer;
 x : Integer;
Begin

 Result := Str;

 If EndOnly = False then
 begin
   while (Result <> '') do
   begin
    // x := FastLowerCaseCharOrd(Result[1]);
    if (Result[1] >= Low(GLOB_LowCaseOrdTable)) and
       (Result[1] <= High(GLOB_LowCaseOrdTable)) then x := GLOB_LowCaseOrdTable[Result[1]] else x := 1;

    if (x >= 48) and (x <= 57) then Break;
    Delete(Result, 1, 1);
   end;
 End;

 while (Result <> '') do
 begin
  i := Length(Result);
  if i <= 0 then Break;

  if (Result[i] >= Low(GLOB_LowCaseOrdTable)) and
     (Result[i] <= High(GLOB_LowCaseOrdTable)) then x := GLOB_LowCaseOrdTable[Result[i]] else x := 1;

  // x := FastLowerCaseCharOrd(Result[i]);
  if (x >= 48) and (x <= 57) then Break;
  Delete(Result, i, 1);
 end;

End;


Function Capitalize(Const Str : String) : String;
Begin

 Result := Str;
 if Result = '' then Exit;
 Result[1] := Result[1].ToUpper;

End;

Function LookLikeEmailAddress(const Str : String) : Boolean;
Var
 i : Integer;
begin

 Result :=

		   (Length(Str) > 4) and
		   (Length(Str) < 200) and
       (TrimEx(Str, '",._-@!?# ') = Str) and
       (FastPosExB('.', Str)) and
       (FastPosExB('..', Str) = False) and
       (FastCharCount('@', Str) = 1);

 if Result = False then EXIT;

 For i := 1 to Length(Str) do
 begin
  If (Str[i].IsLetter = False) and
     (Str[i].IsNumber = False) and
     (Str[i] <> '.') and
     (Str[i] <> '_') and
     (Str[i] <> '-') and
     (Str[i] <> '@') then
  begin
   Result := False;
   Exit;
  End;
 End;

End;


Function FastCharCount(const Sep : Char; Const Str : String) : Integer;
Var
 i   : Integer;
 Len : Integer;
 x   : Char;
Begin

 Result := 0;
 Len := Length(Str);
 if Len < 1 then Exit;
 x := GLOB_CharLowCaseTable[Sep];

 for i := 1 to Len do
 begin
  if GLOB_CharLowCaseTable[Str[i]] = x then Inc(Result);
 end;

End;

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

  end;

end;



Function Implode(const Sep : String; Const List : TStringList) : String;
Var
 i : Integer;
begin

 Result := '';
 if List.Count = 1 then
 begin
  Result := List[0];
  Exit;
 end;

 for i := 0 to List.Count-1 do
 begin
  if i < List.Count-1 then Result := Result + List[i] + Sep
  else Result := Result + List[i];
 end;

end;


Procedure AddToStringList(const Dest : TStringList; const Source : TStringList);
Var
 i : Integer;
begin

 for i := 0 to Source.Count-1 do
 begin
  Dest.Add(Source[i]);
 end;

end;

Function ExplodeFrom(Const Separator : String; Const Str : String; ReturnItemsUpFromIndex : Integer) : String;
Var
 i   : Integer;
Begin
 {$IFDEF EnablePerformanceLog} try PerfLog_SectionBegin('FastStringUtils.ExplodeFrom', nil, TRUE); {$ENDIF}


 Result := '';

 if ReturnItemsUpFromIndex = 0 then
 begin
  Result := Str;
  EXIT;
 end;

 i := FastPosEx(Separator, Str, 1, False, ReturnItemsUpFromIndex-1);
 if i > 0 then
 begin
  Result := Copy(Str, i+Length(Separator), Length(Str));
 end;

 {
 // WARNING: the following implementation will lead to data corruption in cases of e.g.
 // ExplodeFrom('\', 'hkey_users\foobar\foo\ : data', 1) => 'foobar\foo\: data' !!
 Tmp := Explode(Separator, Str);

 if (ReturnItemsUpFromIndex > -1) and (ReturnItemsUpFromIndex <= Tmp.Count-1) then
 begin
   for i := ReturnItemsUpFromIndex to Tmp.Count-1 do
   begin
    if (i mod 100) = 0 then SmartUpdate('FastStringUtils:5259');
    Result := Result + Tmp[i];
    if i < Tmp.Count-1 then Result := Result + Separator;
   end;
 end;

 Tmp.Free; }


 {$IFDEF EnablePerformanceLog} finally PerfLog_SectionEnd('FastStringUtils.ExplodeFrom'); end; {$ENDIF}
End;

Function ExplodeEx(const Sep : Char; Const Str : String; const ReturnItemIdx : Integer) : String;
Var
 TmpList : TStringList;
begin

 TmpList := Explode(Sep, Str);

 if (ReturnItemIdx > -1) and
    (ReturnItemIdx <= TmpList.Count-1) then Result := TmpList[ReturnItemIdx]
 else Result := '';

 TmpList.Free;

end;

Function Explode(const Sep : Char; Const Str : String) : TStringList;
Var
 i        : Integer;
 last_idx : Integer;
 Len      : Integer;
 x        : Char;
Begin

 Result := TStringList.Create;
 Len := Length(Str);
 if Len < 1 then Exit;

 x := GLOB_CharLowCaseTable[Sep];
 last_idx := -1;

 for i := 1 to Len do
 begin

  if GLOB_CharLowCaseTable[Str[i]] = x then
  begin

   if Result.Count = 0 then
   begin
    If i > 1 then Result.Add( Copy(Str, 1, i-1) );
   end else if (last_idx > -1) and (i-last_idx-1 > 0) then Result.Add( Copy(Str, last_idx+1, i-last_idx-1) );

   last_idx := i;

  end else if i = Len then
  begin
   If (last_idx > -1) and (last_idx+1 < Len) then Result.Add( Copy(Str, last_idx+1, Len) )
  end;

 end;

End;

Function CopyFrom(Const Source: String; Const SubStr : String; CopyEndOffset : Integer = 0; SkipHits : Integer = 0) : String;
Var
 i : Integer;
Begin

 i := FastPosEx(SubStr, Source, 0, False, SkipHits);
 if i > 0 then Result := Copy(Source, i+CopyEndOffset, Length(Source))
 else Result := '';

End;

Function FastPosEx(const Substr : String; const Str : String; i : Integer = 1; CaseSensitive : Boolean = False; SkipHits : Integer = 0): Integer;
Var
 n         : Integer;
 x         : Integer;
 x_max     : Integer;
 z         : Integer;
 LenSub    : Integer;
 LenStr    : Integer;
 SubChr    : Char;
 SubStrArr : Array[0..255] of Boolean;
 bCanJump  : Boolean;
 SubStrLC  : String;
Begin
 {$IFDEF EnablePerformanceLog} try PerfLog_SectionBegin('FastStringUtils.FastPosEx', nil, TRUE); {$ENDIF}

 Result := 0;
 LenSub := Length(SubStr);
 if LenSub < 1 then Exit;

 LenStr := Length(Str);
 if LenStr < 1 then Exit;

 If i < 1 then i := 1;

 // Case: FastPosEx('foo', 'foo')
 if (i = 1) and (LenSub = LenStr) then
 begin
  if SkipHits > 0 then EXIT;
  if CaseSensitive then
  begin
   If SubStr = Str then Result := 1;
  End Else
  begin
   If StringCompare(SubStr, Str) then Result := 1;
  end;

  EXIT;
 end;

 if (LenSub+i-1) > LenStr then Exit;

 If SkipHits > 0 then
 begin
  if (LenSub+i-1) + (SkipHits*LenSub) > LenStr then Exit;
 End;



 // Special case: the search word is one character long
 If LenSub = 1 then
 begin

  If CaseSensitive or (GLOB_CharLowCaseTable[SubStr[1]] = SubStr[1].ToUpper) then
  begin
    SubChr := SubStr[1];

    For x := i to LenStr do
    begin
     if Str[x] = SubChr then
     begin
      if SkipHits <= 0 then EXIT(x) else Dec(SkipHits);
     End;
    End;
  End Else
  begin
    SubChr := GLOB_CharLowCaseTable[SubStr[1]];

    For x := i to LenStr do
    begin
     if GLOB_CharLowCaseTable[Str[x]] = SubChr then
     begin
      if SkipHits <= 0 then EXIT(x) else Dec(SkipHits);
     End;
    End;
  End;

  EXIT;
 End;

 SubStrLC := FastLowerCase(SubStr);

 // Consider:
 // Str = 'foo lol abc foobar'
 // Sub = 'foobar'
 // When we are at first ' ' after 'foo', we can continue search from 'l' of 'lol'
 // as we know ' ' is not part of the substr

 If LenSub > 5 then
 begin
   FillChar(SubStrArr, High(SubStrArr)-1, False);
   bCanJump := True;
   For x := 1 to LenSub do
   begin
    if not CaseSensitive then
    begin
     //z := FastLowerCaseCharOrd(SubStr[x])

     if (SubStr[x] >= Low(GLOB_LowCaseOrdTable)) and
        (SubStr[x] <= High(GLOB_LowCaseOrdTable)) then z := GLOB_LowCaseOrdTable[SubStr[x]] else z := 1;

    end else z := Ord(SubStr[x]);


    if (z < Low(SubStrArr)) or (z > High(SubStrArr)) then
    begin
     bCanJump := False;
     Break;
    End;

    SubStrArr[z] := True;
   End;
 End else bCanJump := False;



 // FastLowerCaseChar(SubStr[n]] is very fast,
 // faster than creating a custom array SubStrArr
 x := i-1;
 x_max := (LenStr-LenSub+1);

 If (SkipHits > 0) and (LenSub > 1) then
 begin
  x_max := x_max - (SkipHits*(LenSub-1));
 End;

 While (x+1) <= x_max do
 begin
  Inc(x);

  if not CaseSensitive then
  begin
   for n := 1 to LenSub do
    if SubStrLC[n] <> GLOB_CharLowCaseTable[Str[x+n-1]] then
    begin
     If (bCanJump) and (n > 1) then
     begin
      // z := FastLowerCaseCharOrd(Str[x+n-1]);

      if (Str[x+n-1] >= Low(GLOB_LowCaseOrdTable)) and
         (Str[x+n-1] <= High(GLOB_LowCaseOrdTable)) then z := GLOB_LowCaseOrdTable[Str[x+n-1]] else z := 1;

      if (z >= Low(SubStrArr)) and (z <= High(SubStrArr)) and (SubStrArr[z] = False) then x := x + n-1;
     End;

     Break;
    End
    else if n = LenSub then
    begin
     if SkipHits <= 0 then EXIT(x) else Dec(SkipHits);
    end;
  end else
  begin
   for n := 1 to LenSub do
    if SubStrLC[n] <> Str[x+n-1] then
    begin
     If (bCanJump) and (n > 1) then
     begin
      z := Ord(Str[x+n-1]);
      if (z >= Low(SubStrArr)) and (z <= High(SubStrArr)) and (SubStrArr[z] = False) then x := x + n-1;
     End;

     Break;
    End
    else if n = LenSub then
    begin
     if SkipHits <= 0 then EXIT(x) else Dec(SkipHits);
    end;
  end;
 end;

End;

Function ExtractExeNameOrPath(const Str : String) : String;
Var
 i : Integer;
Begin

 Result := Str;

 i := Pos(':\', Result);
 if i < 1 then EXIT('');
 if (i <> 1) then Result := Copy(Result, i-1, Length(Result));

 // Find the end of the path:
 i := Pos('|', Result);
 if i > 0 then Result := Copy(Result, 1, i-1);

 i := Pos('"', Result);
 if i > 0 then Result := Copy(Result, 1, i-1);

 i := Pos('!', Result);
 if i > 0 then Result := Copy(Result, 1, i-1);

 i := Pos('.exe', Result.ToLower);
 if i > 0 then Result := Copy(Result, 1, i+4);

 Result := TrimEx(Result, '" ,.');

End;


// Varname: value
Function ReadVarValueFromList(const List : TStringList; const VarName : String) : String;
Var
 i : Integer;
 Row : String;
begin

 Result := '';

 for i := 0 to List.Count-1 do
 begin
  Row := FastLowerCase_Trim(List[i]);

  if Row.StartsWith(VarName + ':', True) then
  begin
   Result := Trim(Copy(List[i], Length(VarName)+2, Length(Row)));
   Result := TrimEx(Result, ' :"');
   Break;
  end;
 end;

end;

Function PathCase(const Str : String) : String;
Var
 i : Integer;
 bReg : Boolean;
Begin

 Result := FastLowerCase_Trim(Str);
 if Length(Result) < 3 then EXIT;
 bReg := False;

 // Case: file path
 if Result[2] = ':' then
 begin
  Result[1] := Result[1].ToUpper;
 end else if Result.StartsWith('hkey_') then
 begin
  // Registry key or entry
  bReg := True;
  i := Pos('\', Result);
  if i > 0 then
  begin
   Result := FastUpperCase( Copy(Result, 1, i) ) + Copy(Result, i+1, Length(Result));
  end;
 end;


 for i := 3 to Length(Result)-1 do
 begin

  // In case of registry entry, we are done when the entry part starts:
  if (bReg) and
     (i+2 < Length(Result)) and
     (Result[i] = '\') and
     (Result[i+1] = ' ') and
     (Result[i+2] = ' ') then Break;

  if (Result[i] = '\') or (Result[i] = ' ') then
  begin
   Result[i+1] := Result[i+1].ToUpper;
  end;

 end;


End;

Function RemoveTrail(const Str : String) : String;
Begin

 Result := Trim(Str);
 While (Result <> '') and
       (Result[Length(Result)] = '\') do Delete(Result, Length(Result), 1);

End;



// UpOneDir('c:\foobar\foo\') = > 'c:\foobar\'
// UpOneDir('c:\foobar\foo\\') = > 'c:\foobar\'
// UpOneDir('c:\foobar\foo\foo.exe') => 'c:\foobar\'
// UpOneDir('foobar') => ''
// UpOneDir('\\share\foo\fii\') = > '\\share\foobar\'

Function UpOneDir(Dir : String) : String;
Var
 idx  : Integer;
 bool : Boolean;
begin

 Result := '';
 idx := Length(Dir) - 1;
 bool := False;

 while idx > 1 do
 begin

  if Dir[idx] = '\' then
  begin
   if Bool then
   begin
    Result := Trim(Copy(Dir, 1, idx));
    Exit;
   end;
  end else if Dir[idx].IsWhiteSpace = False then bool := True;

  Dec(idx);
 end;


End;

// ExtractTopDir('c:\foobar\foo\') = > 'foo'
// ExtractTopDir('c:\foobar\foo\\') = > 'foo'
// ExtractTopDir('c:\foobar\foo\foo.exe') => 'foo.exe'
// ExtractTopDir('foobar') => 'foobar'

Function ExtractTopDir(Dir : String) : String;
Var
 x   : Integer;
 idx : Integer;
 len : Integer;
begin
 Result := '';

 // Remove trailing whitespace and slash(es):
 while True do
 begin
  len := Length(Dir);
  if len < 1 then Exit;

  // detect trailing whitespace and slash (92):
  x := ord(Dir[len]);
  if (x <= 32) or (x = 92) then
  begin
   if len < 2 then Exit;
   Dir := Copy(Dir, 1, len-1);
  End else break;
 end;


 idx := LastDelimiter('\', Dir);
 if idx > 0 then Result := Copy(Dir, idx+1, len) else Result := Dir;

 // Remove possibly prefixing whitespace and slash (92):
 while True do
 begin
  if Result = '' then Break;
  x := ord(Result[1]);

  if (x <= 32) or (x = 92) then
  begin
   Result := Copy(Result, 2, len);
  End else break;
 end;

End;

Function ExtractFilePathOrRegKey(Const InputStr : String) : String;
Var
 i : Integer;
 TmpStr : String;
Begin
 Result := '';

 // Case: 'start "" "c:\foobar.exe"
 TmpStr := StringReplaceEx(InputStr, '""', ' ');
 TmpStr := StringReplaceEx(TmpStr, '\\', '\');

 i := FastPosEx(':\', TmpStr);
 if i > 0 then
 begin
  Result := Trim(Copy(TmpStr, i-1, Length(TmpStr)));
 end else
 begin
  i := FastPosEx('hkey_', TmpStr);

  if i > 0 then
  begin
   Result := Trim(Copy(TmpStr, i, Length(TmpStr)));
  End else
  begin
   i := FastPosEx('hk', TmpStr);
   if (i > 0) and (Copy(TmpStr, i+4, 1) = '\') then
     Result := Trim(Copy(TmpStr, i, Length(TmpStr)));
  end;
 end;

 i := FastPosEx('"', Result);
 if i > 0 then Result := Trim(Copy(Result, 1, i-1));


 // Remove registry entry:
 if Result.StartsWith('hk', True) then
 begin
  i := FastPosEx('\ :', Result);
  if i > 0 then Result := Trim(Copy(Result, 1, i-1));

  if Result.EndsWith('\\') then Result := Copy(Result, 1, Length(Result)-1);

 end else
 if Copy(Result, 2, 2) = ':\' then
 begin

  Result := ExtractFilePath(Result);

 end;


End;

Function EnsureTrail(const Str : String) : String;
Begin

 Result := Trim(Str);
 if (Result <> '') and
    (Result[Length(Result)] <> '\') then Result := Result + '\';

End;

Function TrimEx(const InputStr : String; const CharsToRemove : String; EndOnly : Boolean = False; StartOnly : Boolean = False) : String;
Var
 i       : integer;
 LastRes : String;
Begin
 Result := InputStr;

 // We need to loop to ensure we catch 'em all
 while True do
 begin
   LastRes := Result;

   if EndOnly = False then
      while (Result <> '') and (FastPosEx(Result[1], CharsToRemove) > 0) do Delete(Result, 1, 1);

   if StartOnly = False then
   begin
    while True do
    begin
     i := Length(Result);
     if (i > 0) and (FastPosEx(Result[i], CharsToRemove) > 0) then Delete(Result, i, 1) else Break;
    end;
   end;

   if (Result = '') or (Result = LastRes) then Break;

 end;

End;

Function RemoveTrailingWords(Const Str : String; Const SubStr : String) : String;
begin
 Result := RemoveTrailingWords(Str, [SubStr]);
end;

Function RemoveTrailingWords(Const Str : String; Const SubStrs : Array of String) : String;
Var
 i : Integer;
 j : Integer;
 len0 : Integer;
 len1 : Integer;
begin

 Result := Str;

 for j := 1 to 16 do
 begin
   len0 := Length(Result);

   for i := Low(SubStrs) to High(SubStrs) do
   begin
    if Result.EndsWith(SubStrs[i], True) then
    begin
     Result := Trim(Copy(Result, 1, Length(Result)-Length(SubStrs[i])));
    end;
   end;

   len1 := Length(Result);
   if (len1 < 1) or (len1 = len0) then Break;
 end;

end;

Function FastPosExArr(Const SubStrs : Array of String; Const Str : String) : Boolean;
Var
 i : Integer;
begin

 Result := False;

 for i := Low(SubStrs) to High(SubStrs) do
  if FastPosExB(SubStrs[i], Str) then EXIT(TRUE);

end;

Function StringReplaceEx_AllNonNumeric(const Str : String; const ReplaceWith : Char) : String;
Var
 i : Integer;
Begin

 Result := '';

 for i := 1 to Length(Str) do
 begin
  if Str[i].IsNumber then Result := Result + Str[i] else Result := Result + ReplaceWith;
 end;

End;

Function StringReplaceEx(const Str : String; const Search : Array of String; const Replace : String) : String;
Var
 i : Integer;
begin

 Result := Str;

 for i := Low(Search) to High(Search) do
   Result := StringReplaceEx(Result, Search[i], Replace);

end;

Function StringReplaceEx(const Str : String; const Search : String; const Replace : String) : String;
Var
 i : Integer;
begin

 // Loop to ensure all occurances are replaced
 for i := 1 to 2 do
 begin
  Result := StringReplace(Str, Search, Replace, [rfReplaceAll, rfIgnoreCase]);
 end;

end;


// StringReplaceEx_SpecialCase1: All Search elements are one character long, and they are being replaced
Function StringReplaceEx_SpecialCase1(const Str : String; const SearchArr : Array of Char; const ReplaceChr : Char) : String;
Var
 i    : Integer;
 x    : Integer;
 Len  : Integer;
 Chr  : Char;
 bHit : Boolean;
begin
 {$IFDEF EnablePerformanceLog} try PerfLog_SectionBegin('FastStringUtils.StringReplaceEx_SpecialCase1', nil, TRUE); {$ENDIF}

 Result := Str;

 Len := Length(Result);
 for i := 1 to Len do
 begin
  bHit := False;

  // Always ignore case:
  Chr := GLOB_CharLowCaseTable[Result[i]];

  For x := Low(SearchArr) to High(SearchArr) do
    If GLOB_CharLowCaseTable[SearchArr[x]] = Chr then
    begin
     bHit := True;
     Break;
    End;

  if bHit then
  begin
   Result[i] := ReplaceChr;
  End;
 End;

 {$IFDEF EnablePerformanceLog} finally PerfLog_SectionEnd('FastStringUtils.StringReplaceEx_SpecialCase1'); end; {$ENDIF}
end;


// Performs: Result := Trim(StringReplace(Str, '  ', ' ', [rfReplaceAll]));
Function StringReplaceEx_SpecialCase2(const Str : String) : String;
begin
 {$IFDEF EnablePerformanceLog} try PerfLog_SectionBegin('FastStringUtils.StringReplaceEx_SpecialCase2', nil, TRUE); {$ENDIF}


 Result := Trim(StringReplace(Str, '  ', ' ', [rfReplaceAll]));

 {$IFDEF EnablePerformanceLog} finally PerfLog_SectionEnd('FastStringUtils.StringReplaceEx_SpecialCase2'); end; {$ENDIF}
end;


Function UrlSafeEncode(const AStr : String) : String;
var
 Base64: TBase64Encoding;
Begin

 Try
  Base64 := TBase64Encoding.Create();
  Result := Base64.Encode(AStr);
 Except
  Result := '';
 End;

 Result := StringReplace(Result, '+', '-', [rfReplaceAll]);
 Result := StringReplace(Result, '/', '.', [rfReplaceAll]);
 Result := StringReplace(Result, '=', '_', [rfReplaceAll]);

 // just in case:
 Result := StringReplace(Result, #9, '', [rfReplaceAll]);
 Result := StringReplace(Result, #10, '', [rfReplaceAll]);
 Result := StringReplace(Result, #13, '', [rfReplaceAll]);

 Result := Trim(Result);
End;

Function MakeDelphiString(const Str : String) : String;
Var
 i : Integer;
begin

 i := 200;
 Result := '''' + StringReplace(Str, #13, '''' + #13, [rfReplaceAll]) + ''';';

 while i < Length(Result) do
 begin
  Insert('''+'+#13#10+#9+'''', Result, i);
  Inc(i, 200);
 end;


end;

Function BoolToIntStr(const b : Boolean) : String;
Begin
 if b then Result := '1' else Result := '0';
End;

Function RawReadFile_UTF8(const Filename : String; MaxLen : Integer = -1) : String;
Var
 TmpList : TStringList;
 Fail    : Boolean;
begin

 TmpList := TStringList.Create;
 Fail := False;

 Try
  TmpList.LoadFromFile(Filename, TEncoding.UTF8);
 Except
  Fail := True;
 End;


 if Fail then
 begin
   Try
    TmpList.LoadFromFile(Filename);
    Fail := False;
   Except
    Fail := True;
   End;
 end;

 if Fail then Result := '' else Result := TmpList.Text;
 TmpList.Free;

 if MaxLen > 0 then Result := Copy(Result, 1, MaxLen);
end;


Function FastPosExB(const Substr : String; const Str : String; i : Integer = 1; CaseSensitive : Boolean = False): Boolean;
Var
 LenSub   : Integer;
 LenStr   : Integer;
 SubChr   : Char;
 x        : Integer;
 n        : Integer;
 idx_end  : Integer;
Begin
 {$IFDEF EnablePerformanceLog} try PerfLog_SectionBegin('FastStringUtils.FastPosExB', nil, TRUE); {$ENDIF}

 Result := False;
 LenSub := Length(SubStr);
 if LenSub < 1 then Exit;

 LenStr := Length(Str);
 if LenStr < 1 then Exit;
 if LenSub > LenStr then Exit;

 If i < 1 then i := 1;


 // Case: FastPosExB('foo', 'foo')
 if (LenSub = LenStr) then
 begin
  if i > 1 then EXIT(FALSE);
  if CaseSensitive then Result := SubStr = Str else Result := StringCompare(SubStr, Str);
  EXIT;
 end;

 if (i > 1) and ((LenSub+i-1) > LenStr) then Exit;



 {$IFDEF Debug_FastPosExB_SpeedHack_DoubleCheck}  {$ENDIF}



 // Check for the case of FastPosExB_Special_OneCharNonCase()
 If LenSub = 1 then
 begin
  SubChr := SubStr[1];

  If (CaseSensitive) or (GLOB_CharLowCaseTable[SubChr] = GLOB_CharUpCaseTable[SubChr]) then
  begin
   if (i < LenStr) and (Str[LenStr] = SubChr) then EXIT(TRUE); // Fast case: FastPosExB('\', 'c:\foobar\')

   // Result := FastPosExB_Special_OneCharCaseSensitive(SubChr, Str, LenStr, i); Exit;

   for x := i to LenStr-1 do
    if Str[x] = SubChr then EXIT(TRUE);

   EXIT(FALSE);
  End else
  begin
   SubChr := GLOB_CharLowCaseTable[SubStr[1]];
   if (i < LenStr) and (GLOB_CharLowCaseTable[Str[LenStr]] = SubChr) then EXIT(TRUE); // Fast case: FastPosExB('\', 'c:\foobar\')

   // Result := FastPosExB_Special_OneCharCaseInSensitive(SubChr, Str, LenStr, i); Exit;

   for x := i to LenStr-1 do
    if GLOB_CharLowCaseTable[Str[x]] = SubChr then EXIT(TRUE);

   EXIT(FALSE);
  End;
 End;


 idx_end := LenStr-LenSub+1;


 if not CaseSensitive then
 begin

   //for x := i to idx_end do
   x := i;
   while x <= idx_end do
   begin
     for n := 1 to LenSub do
     begin
      if GLOB_CharLowCaseTable[SubStr[n]] <> GLOB_CharLowCaseTable[Str[x+n-1]] then
      begin
       if (n > 1) and (GLOB_CharLowCaseTable[Str[x+n-1]] <> GLOB_CharLowCaseTable[SubStr[1]]) then x := x + n -1;
       Break;
      End else if n = LenSub then EXIT(TRUE);
     end;

     Inc(x);
   end;

 end else
 begin

   //for x := i to idx_end do
   x := i;
   while x <= idx_end do
   begin
     for n := 1 to LenSub do
     begin
      if SubStr[n] <> Str[x+n] then
      begin
       if (n > 1) and (Str[x+n] <> SubStr[1]) then x := x + n -1;
       Break;
      end else if n = LenSub then EXIT(TRUE);
     end;

     Inc(x);
   end;

 end;


 {$IFDEF EnablePerformanceLog} finally PerfLog_SectionEnd('FastStringUtils.FastPosExB'); end; {$ENDIF}
End;


{$OVERFLOWCHECKS OFF}
{$RangeChecks OFF}

// Warning: Case sensitive!
function Murmur2Hash(const AString: String): LongWord;
const
  SEED = $9747b28c;
  M    = $5bd1e995;
  R    = 24;
var
  i    : Integer;
  hash : LongWord;
  len  : LongWord;
  k    : LongWord;
  s    : AnsiString;
begin

  s    := AnsiString(AString);
  len  := Length(s);
  hash := SEED xor len;

  for i := 1 to Len do
  begin
   k := ord(s[i]);
   k := k * M;
   k := k xor (k shr R);
   k := k * M;
   hash := hash * M;
   hash := hash xor k;
  end;

  if len  = 3 then hash := hash xor (Ord(s[2]) shl 16);
  if len >= 2 then hash := hash xor (Ord(s[1]) shl 8);
  if len >= 1 then
  begin
    hash := hash xor (Ord(s[Len]));
    hash := hash * m;
  end;

  hash := hash xor (hash shr 13);
  hash := hash * m;
  hash := hash xor (hash shr 15);

  result := hash;

end;

end.
