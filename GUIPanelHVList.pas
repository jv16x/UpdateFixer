unit GUIPanelHVList;

{$R-,T-,X+,H+,B-,O+,Q-}

// If the list contains automatically positioned elements, throw Assert in case they were resized or re-positioned elsewhere
{.$DEFINE Debug_Assert_IfPosChanged}
{.$DEFINE EnablePerformanceLog}

interface


{.$DEFINE Debug_ExplicitMadExceptUse}

uses
  {$IFDEF Debug_ExplicitMadExceptUse} madExcept, {$ENDIF}
  Windows, Messages, SysUtils, Classes, Graphics, Controls,
  {$IFDEF EnablePerformanceLog} PerformanceLog, {$ENDIF}

  {$IFDEF Debug_Assert_IfPosChanged}
  AssertUnit,
  System.Generics.Collections, {$ENDIF}

  Forms, StdCtrls, ExtCtrls, Contnrs, GUIPanel, System.Types;



type
  TCustomGUIPanelList = class(TGUIPanel)
  private
    FResizeControls: Boolean;
    FIgnoreInvisible: Boolean;
    FSortByTags: Boolean;
    FReverseFill: Boolean;
    procedure SetResizeControls(Value: Boolean);
  protected
    FMarginTop: Integer;
    FMarginLeft: Integer;
    FMarginSeparator: Integer;
    procedure Set_AutoSizeW(Value: Boolean); override;
    procedure Set_AutoSizeH(Value: Boolean); override;
    procedure SetMarginTop(Value: Integer);
    procedure SetMarginLeft(Value: Integer);
    procedure SetMarginSeparator(Value: Integer);
    procedure SetIgnoreInvisibleControls(Value: Boolean);
    procedure SetSortByTags(Value: Boolean);
    procedure SetReverseFill(Value: Boolean);
  public
    constructor Create(AOwner: TComponent); override;
    Function GetAverageControlWidth : Single;
    Function GetBottomControlTop(PlusItsHeight : Boolean) : Integer;
    Function GetVisibleControlCount() : Integer;
  published
    property AutoSizeW: Boolean read FAutoSizeW write Set_AutoSizeW;
    property AutoSizeH: Boolean read FAutoSizeH write Set_AutoSizeH;
    property MarginTop: Integer read FMarginTop write SetMarginTop;
    property MarginLeft: Integer read FMarginLeft write SetMarginLeft;
    property MarginSeparator: Integer read FMarginSeparator write SetMarginSeparator;
    property ResizeControls : Boolean read FResizeControls write SetResizeControls;
    property SortByTags: Boolean read FSortByTags write SetSortByTags;
    property ReverseFill: Boolean read FReverseFill write SetReverseFill;
    property IgnoreInvisibleControls: Boolean read FIgnoreInvisible write SetIgnoreInvisibleControls;
  end;

  TGUIPanelHList = class(TCustomGUIPanelList)
  private
    FMarginHorizontal: Integer;
    FLastAdjustState : String;
    {$IFDEF Debug_Assert_IfPosChanged} FLastControlStates : TDictionary<String, String>; {$ENDIF}

    procedure SetMarginHorizontal(Value: Integer);
    function GetAdjustState() : String;
  public
    constructor Create(AOwner: TComponent); override;
    procedure AdjustControls(const ForceUpdate : Boolean = False); override;
  published
    property MarginHorizontal: Integer read FMarginHorizontal write SetMarginHorizontal;
  end;

  TGUIPanelVList = class(TCustomGUIPanelList)
  private
    FMarginVertical: Integer;
    FExtraLabelMargin: Integer;
    FExtraLabelSeparation : Integer;
    FExtraMemoMargin: Integer;
    FLastAdjustState : String;
    {$IFDEF Debug_Assert_IfPosChanged} FLastControlStates : TDictionary<String, String>; {$ENDIF}

    procedure SetMarginVertical(Value: Integer);
    procedure SetExtraLabelMargin(Value: Integer);
    procedure SetExtraLabelSeparation(Value: Integer);
    procedure SetExtraMemoMargin(Value: Integer);
    function GetAdjustState() : String;
  public
    constructor Create(AOwner: TComponent); override;
    procedure AdjustControls(const ForceUpdate : Boolean = False); override;
  published
    property MarginVertical: Integer read FMarginVertical write SetMarginVertical;
    property ExtraLabelMargin: Integer read FExtraLabelMargin write SetExtraLabelMargin; // Horizontal margin!
    property ExtraLabelSeparation: Integer read FExtraLabelSeparation write SetExtraLabelSeparation; // Vertical margin!
    property ExtraMemoMargin: Integer read FExtraMemoMargin write SetExtraMemoMargin;


  end;

procedure Register;

implementation

procedure Register;
begin
  RegisterComponents('Macecraft GUIPanels', [TGUIPanelHList]);
  RegisterComponents('Macecraft GUIPanels', [TGUIPanelVList]);
end;

constructor TCustomGUIPanelList.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  Self.DoubleBuffered := True;
  Self.ParentBackground := False;

  FAutoSizeW := False;
  FAutoSizeH := False;
  FMarginTop := 5;
  FMarginLeft := 5;
  FMarginSeparator := 0;
  FResizeControls := False;
  FIgnoreInvisible := True;
  FSortByTags := False;
  FReverseFill := False;

  AdjustControls;
end;

constructor TGUIPanelHList.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  {$IFDEF Debug_Assert_IfPosChanged} FLastControlStates := TDictionary<String, String>.Create; {$ENDIF}
  Self.DoubleBuffered := True;
  Self.ParentBackground := False;

  FMarginHorizontal := 5;
end;

constructor TGUIPanelVList.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  {$IFDEF Debug_Assert_IfPosChanged} FLastControlStates := TDictionary<String, String>.Create; {$ENDIF}
  Self.DoubleBuffered := True;
  Self.ParentBackground := False;

  FMarginVertical := 5;
  FExtraLabelSeparation := 0;
  FExtraLabelMargin := 0;
  FExtraMemoMargin := 0;
end;

procedure TCustomGUIPanelList.Set_AutoSizeW(Value: Boolean);
begin

  if Self.Align = alClient then Value := False;
  if Self.Align = alTop then Value := False;
  if Self.Align = alBottom then Value := False;

  if FAutoSizeW <> Value then
  begin
    FAutoSizeW := Value;
    if Value = True then
      ResizeControls := False;

    Invalidate;
    AdjustControls;
  end;
end;

procedure TCustomGUIPanelList.Set_AutoSizeH(Value: Boolean);
begin

  if Self.Align = alClient then
    Value := False;
  if Self.Align = alLeft then
    Value := False;
  if Self.Align = alRight then
    Value := False;


  if FAutoSizeH <> Value then
  begin
    FAutoSizeH := Value;
    Invalidate;
    AdjustControls;
  end;
end;

procedure TGUIPanelHList.SetMarginHorizontal(Value: Integer);
begin
  FMarginHorizontal := Value;
  Invalidate;
  AdjustControls;
end;


procedure TGUIPanelVList.SetExtraMemoMargin(Value: Integer);
begin
  FExtraMemoMargin := Value;
  Invalidate;
  AdjustControls;
end;

procedure TGUIPanelVList.SetExtraLabelMargin(Value: Integer);
begin
  FExtraLabelMargin := Value;
  Invalidate;
  AdjustControls;
end;

procedure TGUIPanelVList.SetExtraLabelSeparation(Value: Integer);
begin
  FExtraLabelSeparation := Value;
  Invalidate;
  AdjustControls;
end;



procedure TGUIPanelVList.SetMarginVertical(Value: Integer);
begin
  FMarginVertical := Value;
  Invalidate;
  AdjustControls;
end;

procedure TCustomGUIPanelList.SetMarginTop(Value: Integer);
begin
  FMarginTop := Value;
  Invalidate;
  AdjustControls;
end;

procedure TCustomGUIPanelList.SetMarginLeft(Value: Integer);
begin
  FMarginLeft := Value;
  Invalidate;
  AdjustControls;
end;

procedure TCustomGUIPanelList.SetMarginSeparator(Value: Integer);
begin
  FMarginSeparator := Value;
  Invalidate;
  AdjustControls;
end;

Function TCustomGUIPanelList.GetAverageControlWidth : Single;
Var
 i     : Integer;
 c     : TControl;
 Sum   : Integer;
 Count : Integer;
begin
 {$IFDEF EnablePerformanceLog} try PerfLog_SectionBegin('TCustomGUIPanelList.GetAverageControlWidth', Self); {$ENDIF} // SmartUpdate('GUIPanelHVList:255');

 Sum := 0;
 Count := 0;

 for i := 0 to FControlList.Count-1 do
 begin
  c := TControl(FControlList[i]);
  if c = nil then Continue;

  Inc(Count);
  Sum := Sum + c.Width;
 end;

 if Count > 0 then Result := Sum / Count else Result := 0;

 {$IFDEF EnablePerformanceLog} finally PerfLog_SectionEnd('TCustomGUIPanelList.GetAverageControlWidth'); end; {$ENDIF}
end;

Function TCustomGUIPanelList.GetBottomControlTop(PlusItsHeight : Boolean) : Integer;
Var
 i     : Integer;
 c     : TControl;
 x_val : Integer;
 x_idx : Integer;
begin
 {$IFDEF EnablePerformanceLog} try PerfLog_SectionBegin('TCustomGUIPanelList.GetBottomControlTop', Self); {$ENDIF} // SmartUpdate('GUIPanelHVList:281');

 Result := 0;
 If FControlList.Count < 1 then EXIT;

 x_val := 0;
 x_idx := -1;

 for i := 0 to FControlList.Count-1 do
 begin
  c := TControl(FControlList[i]);
  if (c = nil) or (c.Visible = False) then Continue;

  if (x_idx < 0) or (c.Top > x_val) then
  begin
   x_idx := i;
   x_val := c.Top;
  End;
 end;

 If (x_idx > -1) then
 begin
  c := TControl(FControlList[x_idx]);

  if (c <> nil) and (c.Visible) then
  begin
   if PlusItsHeight then Result := c.Top + c.Height else Result := c.Top;
  End;
 End;

 {$IFDEF EnablePerformanceLog} finally PerfLog_SectionEnd('TCustomGUIPanelList.GetBottomControlTop'); end; {$ENDIF}
end;

Function TCustomGUIPanelList.GetVisibleControlCount() : Integer;
Var
 i : Integer;
 c : TControl;
begin
 {$IFDEF EnablePerformanceLog} try PerfLog_SectionBegin('TCustomGUIPanelList.GetVisibleControlCount', Self); {$ENDIF} // SmartUpdate('GUIPanelHVList:319');

 Result := 0;

 for i := 0 to FControlList.Count-1 do
 begin
  c := TControl(FControlList[i]);
  if (c = nil) or (c.Visible = False) then Continue;
  Inc(Result);
 End;

 {$IFDEF EnablePerformanceLog} finally PerfLog_SectionEnd('TCustomGUIPanelList.GetVisibleControlCount'); end; {$ENDIF}
end;

procedure TCustomGUIPanelList.SetResizeControls(Value: Boolean);
begin

 Try
  FResizeControls := Value;

  if Value = True then
  begin
   if Self is TGUIPanelVList then FAutoSizeW := False;
   if Self is TGUIPanelHList then FAutoSizeH := False;
  end;

  Invalidate;
  AdjustControls;
 Except
    //HandleException();
 End;

end;

procedure TCustomGUIPanelList.SetIgnoreInvisibleControls(Value: Boolean);
begin

 Try
  FIgnoreInvisible := Value;
  Invalidate;
  AdjustControls;
 Except
  //HandleException();
 End;


end;

procedure TCustomGUIPanelList.SetSortByTags(Value: Boolean);
begin
  FSortByTags := Value;
  Invalidate;
  AdjustControls;
end;

procedure TCustomGUIPanelList.SetReverseFill(Value: Boolean);
begin
  FReverseFill := Value;
  Invalidate;
  AdjustControls;
end;

// sort controls according to their horizontal position
function ControlSorter_H(p1, p2: Pointer): Integer;
var
  y1, y2: Integer;
begin
  y1 := TControl(p1).Left;
  y2 := TControl(p2).Left;
  if y1 > y2 then
    Result := 1
  else if y1 < y2 then
    Result := -1
  else
    Result := 0;
end;

// sort controls according to their vertical position
function ControlSorter_V(p1, p2: Pointer): Integer;
var
  y1, y2: Integer;
begin
  y1 := TControl(p1).Top;
  y2 := TControl(p2).Top;
  if y1 > y2 then
    Result := 1
  else if y1 < y2 then
    Result := -1
  else
    Result := 0;
end;

// sort controls according to their Tag value
function ControlSorter_Tag(p1, p2: Pointer): Integer;
var
  y1, y2: Integer;
begin
  y1 := TControl(p1).Tag;
  y2 := TControl(p2).Tag;
  if y1 > y2 then
    Result := 1
  else if y1 < y2 then
    Result := -1
  else
    Result := 0;
end;

// sort controls according to their horizontal position
function ControlSorter_H_Reverse(p1, p2: Pointer): Integer;
var
  y1, y2: Integer;
begin
  y1 := TControl(p1).Left;
  y2 := TControl(p2).Left;
  if y1 > y2 then
    Result := -1
  else if y1 < y2 then
    Result := 1
  else
    Result := 0;
end;

// sort controls according to their vertical position
function ControlSorter_V_Reverse(p1, p2: Pointer): Integer;
var
  y1, y2: Integer;
begin
  y1 := TControl(p1).Top;
  y2 := TControl(p2).Top;
  if y1 > y2 then
    Result := -1
  else if y1 < y2 then
    Result := 1
  else
    Result := 0;
end;


function TGUIPanelHList.GetAdjustState() : String;
Var
 i : Integer;
begin
 {$IFDEF EnablePerformanceLog} try PerfLog_SectionBegin('TGUIPanelHList.GetAdjustState', Self); {$ENDIF} // SmartUpdate('GUIPanelHVList:461');

 Result := IntToStr(Self.Width) +'x'+ IntToStr(Self.Height) +':' +
    IntToStr(Self.ControlCount) +':'+
    IntToStr(Self.ComponentCount) +':'+
    IntToStr(Self.MarginHorizontal) +':'+
    IntToStr(Self.MarginTop) +':'+
    IntToStr(Self.MarginLeft) +':'+
    IntToStr(Self.MarginSeparator) +':';

 if Self.ResizeControls then Result := Result + 'x' else Result := Result + 'z';
 if Self.SortByTags     then Result := Result + 'x' else Result := Result + 'z';
 if Self.ReverseFill    then Result := Result + 'x' else Result := Result + 'z';
 if Self.AutoSizeW      then Result := Result + 'x' else Result := Result + 'z';
 if Self.AutoSizeH      then Result := Result + 'x' else Result := Result + 'z';

 if Self.Parent <> nil then
 begin
  Result := Result + IntToStr(Self.Parent.Width) +'x'+ IntToStr(Self.Parent.Height) +':';
 end;

 for i := 0 to Self.ControlCount-1 do
 begin
  // SmartUpdate('GUIPanelHVList:485');
  Result := Result +
    IntToStr(Self.Controls[i].Width) + 'x' +
    IntToStr(Self.Controls[i].Height) +':'+
    IntToStr(Self.Controls[i].Left) +':'+
    IntToStr(Self.Controls[i].Top) +':'+

    IntToStr(Self.Controls[i].Margins.Left) +':'+
    IntToStr(Self.Controls[i].Margins.Top) +':'+
    IntToStr(Self.Controls[i].Margins.Right) +':'+
    IntToStr(Self.Controls[i].Margins.Bottom) +':'+

    IntToStr(Self.Controls[i].Tag) +':';
  if Self.Controls[i].Visible then Result := Result + 'vis';
 end;

 {$IFDEF EnablePerformanceLog} finally PerfLog_SectionEnd('TGUIPanelHList.GetAdjustState'); end; {$ENDIF}
end;

// Lines up controls horizontally
procedure TGUIPanelHList.AdjustControls(const ForceUpdate : Boolean = False);
var
  i, X, Y, H  : Integer;
  prevName    : String;
  CurState    : String;
  NewSize     : TPoint;
  MaxPos      : TPoint;
  Control     : TControl;
  ControlList : TObjectList;
  {$IFDEF Debug_Assert_IfPosChanged} CurState : String; OldState : String; {$ENDIF}
begin
 {$IFDEF EnablePerformanceLog} try PerfLog_SectionBegin('TGUIPanelHList.AdjustControls', Self); {$ENDIF} // SmartUpdate('GUIPanelHVList:506');

  if Self = nil then EXIT;
  if csReading in ComponentState then EXIT;
  if Self.ControlCount < 1 then EXIT;

  if ForceUpdate = False then
  begin
   CurState := GetAdjustState();
   if FLastAdjustState = CurState then EXIT;
  End;

  // Call the AdjustControls() of any child controls:
  for i := 0 to Self.ControlCount - 1 do
  begin
    // SmartUpdate('GUIPanelHVList:531');
    Control := Self.Controls[i];
    if (Control <> nil) and (Control <> self) then
    begin
     If (Control is TGUIPanelVList) then TGUIPanelVList(Control).AdjustControls();
     If (Control is TGUIPanelHList) then TGUIPanelHList(Control).AdjustControls();

     //if (Control is TPTZCheckBox) then TPTZCheckBox(Control).AdjustAutoSize();
     //if (Control is TPTZRadioButton) then TPTZRadioButton(Control).AdjustAutoSize();

     // Fix case of autosize labels:
     if (Self.ResizeControls) and (Control is TLabel) and (TLabel(Control).AutoSize) then TLabel(Control).AutoSize := False;
    End;
  end;
  for i := 0 to Self.ControlCount - 1 do
  begin
   Control := Self.Controls[i];
   if (Control <> nil) and (Control <> self) and (Control.Align <> alNone) and (Control is TWinControl) then TWinControl(Control).Realign;
  End;
  // **



  Try
    NewSize := Point(0, 0);

    ControlList := TObjectList.Create(False);
    for i := 0 to Self.ControlCount - 1 do
    begin
      // SmartUpdate('GUIPanelHVList:557');
      Control := Self.Controls[i];
      if (Control = nil) or (Control = self) then Continue; // just in case
      if (FIgnoreInvisible) and (Control.Visible = False) then Continue;
      ControlList.Add(Control);
    end;

    if ReverseFill then
    begin
      X := Self.Width - FMarginLeft - 1;
      if FSortByTags then
        ControlList.Sort(@ControlSorter_Tag)
      else
        ControlList.Sort(@ControlSorter_H_Reverse);
    end
    else
    begin
      X := FMarginLeft;
      if FSortByTags then
        ControlList.Sort(@ControlSorter_Tag)
      else
        ControlList.Sort(@ControlSorter_H);
    end;



    {$IFDEF Debug_Assert_IfPosChanged}
    If (not (csReading in ComponentState)) and (FLastControlStates <> nil) and (FLastControlStates.Count > 0) then
    begin
      for i := 0 to ControlList.Count - 1 do
      begin
       Control := TControl(ControlList[i]);
       CurState := IntToStr(Control.Left) +':'+ IntToStr(Control.Top);
       If FLastControlStates.TryGetValue(Control.Name, OldState) then
        AssertEx(OldState = CurState, 'Control state changed: ' + Control.Name + ', Self: ' + Self.Name + ', Current state: ' + CurState + ', Old state: ' + OldState);
      End;
    End;
   {$ENDIF}

    H := 0;

    // find tallest control
    if not FAutoSizeH then
    begin

      for i := 0 to ControlList.Count - 1 do
      begin
        Control := TControl(ControlList[i]);
        if Control.Height > H then
          H := Control.Height;
      end;
      H := H div 2;
    end;

    // iterate controls; collect width and height
    for i := 0 to ControlList.Count - 1 do
    begin
      // SmartUpdate('GUIPanelHVList:614');
      Control := TControl(ControlList[i]);

      if FResizeControls then
      begin
        Control.Top := FMarginTop;
        Control.Height := Height - (FMarginTop * 2);
      end
      else
        Control.Top := FMarginTop + (H - (Control.Height div 2));

      if ReverseFill then
      begin
        Dec(X, Control.Width);
        if i > 0 then
        begin
          if Control.ClassName <> prevName then
            Dec(X, FMarginSeparator);
          Dec(X, FMarginHorizontal);

          if Control.AlignWithMargins then
            Dec(X, Control.Margins.Left);
        end;
        Control.Left := X;
      end
      else
      begin
        if i > 0 then
        begin
          if Control.ClassName <> prevName then
            Inc(X, FMarginSeparator);
          Inc(X, FMarginHorizontal);

          if Control.AlignWithMargins then
            Inc(X, Control.Margins.Left);
        end;
        Control.Left := X;
        Inc(X, Control.Width);
      end;

      prevName := Control.ClassName;
    end;

    if ReverseFill then
      Dec(X, FMarginHorizontal)
    else
      Inc(X, FMarginHorizontal);

    // resize height if needed
    if FAutoSizeH then
    begin
      for i := 0 to Self.ControlCount - 1 do
      begin
        Y := Controls[i].Height;
        if (Y > MaxPos.Y) or (i = 0) then
          MaxPos.Y := Y;
      end;
      Y := MaxPos.Y + (FMarginTop * 2);
      if Y <> Height then
        Height := Y;
    end;

    // resize width if needed
    if FAutoSizeW then
    begin
      Dec(X, FMarginHorizontal);
      Inc(X, FMarginLeft);

      if X <> Width then
        Width := X;
    end;


    {$IFDEF Debug_Assert_IfPosChanged}
    If not (csReading in ComponentState) then
    begin
      for i := 0 to ControlList.Count - 1 do
      begin
       Control := TControl(ControlList[i]);
       CurState := IntToStr(Control.Left) +':'+ IntToStr(Control.Top);
       FLastControlStates.AddOrSetValue(Control.Name, CurState);
      End;
    End;
   {$ENDIF}


    FLastAdjustState := GetAdjustState();
    ControlList.Free;

  Except
     //HandleException();
  End;

 {$IFDEF EnablePerformanceLog} finally PerfLog_SectionEnd('TGUIPanelHList.AdjustControls'); end; {$ENDIF}
end;


function TGUIPanelVList.GetAdjustState() : String;
Var
 i : Integer;
begin
 {$IFDEF EnablePerformanceLog} try PerfLog_SectionBegin('TGUIPanelVList.GetAdjustState', Self); {$ENDIF} // SmartUpdate('GUIPanelHVList:692');

 Result := IntToStr(Self.Width) +'x'+ IntToStr(Self.Height) +':' +
    IntToStr(Self.ControlCount) +':'+
    IntToStr(Self.ComponentCount) +':'+
    IntToStr(Self.MarginVertical) +':'+
    IntToStr(Self.MarginTop) +':'+
    IntToStr(Self.MarginLeft) +':'+
    IntToStr(Self.MarginSeparator) +':';

 if Self.ResizeControls then Result := Result + 'x' else Result := Result + 'z';
 if Self.SortByTags     then Result := Result + 'x' else Result := Result + 'z';
 if Self.ReverseFill    then Result := Result + 'x' else Result := Result + 'z';
 if Self.AutoSizeW      then Result := Result + 'x' else Result := Result + 'z';
 if Self.AutoSizeH      then Result := Result + 'x' else Result := Result + 'z';

 if Self.Parent <> nil then
 begin
  Result := Result + IntToStr(Self.Parent.Width) +'x'+ IntToStr(Self.Parent.Height) +':';
 end;

 for i := 0 to Self.ControlCount-1 do
 begin
  // SmartUpdate('GUIPanelHVList:738');
  Result := Result +
    IntToStr(Self.Controls[i].Width) + 'x' +
    IntToStr(Self.Controls[i].Height) +':'+
    IntToStr(Self.Controls[i].Left) +':'+
    IntToStr(Self.Controls[i].Top) +':'+

    IntToStr(Self.Controls[i].Margins.Left) +':'+
    IntToStr(Self.Controls[i].Margins.Top) +':'+
    IntToStr(Self.Controls[i].Margins.Right) +':'+
    IntToStr(Self.Controls[i].Margins.Bottom) +':'+

    IntToStr(Self.Controls[i].Tag) +':';
  if Self.Controls[i].Visible then Result := Result + 'vis';
 end;

 {$IFDEF EnablePerformanceLog} finally PerfLog_SectionEnd('TGUIPanelVList.GetAdjustState'); end; {$ENDIF}
end;

// Lines up controls vertically
procedure TGUIPanelVList.AdjustControls(const ForceUpdate : Boolean = False);
var
  i, X, Y     : Integer;
  iVal        : Integer;
  prevName    : String;
  CurState    : String;
  NewSize     : TPoint;
  MaxPos      : TPoint;
  Control     : TControl;
  ControlList : TObjectList;
  {$IFDEF Debug_Assert_IfPosChanged} CurState : String; OldState : String; {$ENDIF}
begin
 {$IFDEF EnablePerformanceLog} try PerfLog_SectionBegin('TGUIPanelVList.AdjustControls', Self); {$ENDIF} // SmartUpdate('GUIPanelHVList:738');

  if Self = nil then EXIT;
  if csReading in ComponentState then EXIT;
  If Self.ControlCount < 1 then EXIT;

  if ForceUpdate = False then
  begin
   CurState := GetAdjustState();
   if FLastAdjustState = CurState then EXIT;
  End;


  // Call the AdjustControls() of any child controls:
  for i := 0 to Self.ControlCount - 1 do
  begin
    // SmartUpdate('GUIPanelHVList:786');
    Control := Self.Controls[i];
    if (Control <> nil) and (Control <> self) then
    begin
     If (Control is TGUIPanelVList) then TGUIPanelVList(Control).AdjustControls();
     If (Control is TGUIPanelHList) then TGUIPanelHList(Control).AdjustControls();

     //if (Control is TPTZCheckBox) then TPTZCheckBox(Control).AdjustAutoSize();
     //if (Control is TPTZRadioButton) then TPTZRadioButton(Control).AdjustAutoSize();

     // Fix case of autosize labels:
     if (Self.ResizeControls) and (Control is TLabel) and (TLabel(Control).AutoSize) then TLabel(Control).AutoSize := False;
    End;
  end;

  for i := 0 to Self.ControlCount - 1 do
  begin
   // SmartUpdate('GUIPanelHVList:800');
   Control := Self.Controls[i];
   if (Control <> nil) and (Control <> self) and (Control.Align <> alNone) and (Control is TWinControl) then TWinControl(Control).Realign;
  End;
  // **


  NewSize := Point(0, 0);
  ControlList := TObjectList.Create(False);

  for i := 0 to Self.ControlCount - 1 do
  begin
    // SmartUpdate('GUIPanelHVList:812');
    Control := Self.Controls[i];
    if (Control = nil) or (Control = self) then Continue; // just in case
    If (FIgnoreInvisible) and (Control.Visible = False) then Continue;
    ControlList.Add(Control);
  end;

  if ReverseFill then
  begin
    Y := Height - FMarginTop - 1;
    if FSortByTags then
      ControlList.Sort(@ControlSorter_Tag)
    else
      ControlList.Sort(@ControlSorter_V_Reverse);
  end
  else
  begin
    Y := FMarginTop;
    if FSortByTags then
      ControlList.Sort(@ControlSorter_Tag)
    else
      ControlList.Sort(@ControlSorter_V);
  end;


  {$IFDEF Debug_Assert_IfPosChanged}
    If (not (csReading in ComponentState)) and (FLastControlStates <> nil) and (FLastControlStates.Count > 0) then
    begin
      for i := 0 to ControlList.Count - 1 do
      begin
       Control := TControl(ControlList[i]);
       CurState := IntToStr(Control.Left) +':'+ IntToStr(Control.Top);
       If FLastControlStates.TryGetValue(Control.Name, OldState) then
        AssertEx(OldState = CurState, 'Control state changed: ' + Control.Name + ', Self: ' + Self.Name + ', Current state: ' + CurState + ', Old state: ' + OldState);
      End;
    End;
  {$ENDIF}

  // iterate controls; collect width and height
  for i := 0 to ControlList.Count - 1 do
  begin
    // SmartUpdate('GUIPanelHVList:853');
    Control := TControl(ControlList[i]);
    Control.Align := alNone;

    iVal := FMarginLeft;
    If (FExtraLabelMargin <> 0) and (Control is TLabel) then Inc(iVal, FExtraLabelMargin);
    If (FExtraMemoMargin <> 0) and (Control is TMemo) then Inc(iVal, FExtraMemoMargin);
    Control.Left := iVal;


    if FResizeControls then
      Control.Width := Self.Width - (Control.Left * 2);



    if ReverseFill then
    begin
      Dec(Y, Control.Height);
      if i > 0 then
      begin
        if Control.ClassName <> prevName then
          Dec(Y, FMarginSeparator);

        Dec(Y, FMarginVertical);
        if Control is TLabel then Dec(Y, FExtraLabelSeparation);

        if Control.AlignWithMargins then
            Dec(Y, Control.Margins.Top);
      end;
      Control.Top := Y;
      prevName := Control.ClassName;
    end
    else
    begin
      if i > 0 then
      begin
        if Control.ClassName <> prevName then
          Inc(Y, FMarginSeparator);

        Inc(Y, FMarginVertical);
        if Control is TLabel then Inc(Y, FExtraLabelSeparation);

        if Control.AlignWithMargins then
            Inc(Y, Control.Margins.Top);
      end;
      Control.Top := Y;
      Inc(Y, Control.Height);
      prevName := Control.ClassName;
    end;
  end;



  if ReverseFill then
    Dec(Y, FMarginVertical)
  else
    Inc(Y, FMarginVertical);


  // resize width if needed
  if FAutoSizeW then
  begin
    for i := 0 to Self.ControlCount - 1 do
    begin
      X := Controls[i].Width;
      if (X > MaxPos.X) or (i = 0) then MaxPos.X := X;
    end;

    X := MaxPos.X;

    if X <> Width then Width := X;
  end;

  // resize height if needed
  if FAutoSizeH then
  begin
    Y := Y + Self.Margins.Top;
    Y := Y + Self.Margins.Bottom;
    if Y <> Height then Height := Y;
  end;


  {$IFDEF Debug_Assert_IfPosChanged}
  If not (csReading in ComponentState) then
  begin
    for i := 0 to ControlList.Count - 1 do
    begin
      Control := TControl(ControlList[i]);
      CurState := IntToStr(Control.Left) +':'+ IntToStr(Control.Top);
      FLastControlStates.AddOrSetValue(Control.Name, CurState);
    End;
  End;
  {$ENDIF}

  FLastAdjustState := GetAdjustState();
  ControlList.Free;

 {$IFDEF EnablePerformanceLog} finally PerfLog_SectionEnd('TGUIPanelVList.AdjustControls'); end; {$ENDIF}
end;

end.
