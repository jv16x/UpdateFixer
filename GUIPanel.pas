unit GUIPanel;


{$R-,T-,X+,H+,B-,O+,Q-}

interface

{.$DEFINE EnablePerformanceLog}
{.$DEFINE Debug_ExplicitMadExceptUse}

uses
  {$IFDEF Debug_ExplicitMadExceptUse} madExcept, {$ENDIF}
  Windows, Messages, SysUtils, Classes,
  Graphics, Controls, Forms, System.Types,
  {$IFDEF EnablePerformanceLog} PerformanceLog, {$ENDIF}
  ExtCtrls, Contnrs, Vcl.Themes;

type
  TCustomGUIPanel = class(TCustomPanel)
  private
    FAlignControlsCalls: Integer;
    procedure WMEraseBkgnd(var Message: TWmEraseBkgnd); message WM_ERASEBKGND;
  protected
    FAutoSizeW: Boolean;
    FAutoSizeH: Boolean;
    FControlList: TObjectList;
    procedure Paint; override;
    procedure AdjustControls(const ForceUpdate : Boolean = False); virtual;
    procedure Set_AutoSizeW(Value: Boolean); virtual;
    procedure Set_AutoSizeH(Value: Boolean); virtual;
    procedure CMEnabledChanged(var Message: TMessage); message CM_ENABLEDCHANGED;
    procedure CMControlListChanging(var Message: TCMControlListChanging); message CM_CONTROLLISTCHANGING;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure AlignControls(AControl: TControl; var Rect: TRect); override;
    procedure GetChildren(Proc: TGetChildProc; Root: TComponent); override;
    function GetControlIndex(AControl: TControl): Integer;
    procedure SetControlIndex(AControl: TControl; Index: Integer);
  published
  end;

  TGUIPanel = class(TCustomGUIPanel)
  public
    procedure AdjustControls(const ForceUpdate : Boolean = False); override;
  published
    property AutoSizeW: Boolean read FAutoSizeW write Set_AutoSizeW;
    property AutoSizeH: Boolean read FAutoSizeH write Set_AutoSizeH;
    property BevelEdges;
    property BevelInner;
    property BevelKind;
    property BevelOuter;
    property BevelWidth;
    property BorderWidth;
    property BorderStyle;
    property Font;
    property Color;
    property ParentColor;
    property Enabled;
    property Visible;
    property Align;
    property Alignment;
    property Cursor;
    property Hint;
    property ParentShowHint;
    property ShowHint;
    property PopupMenu;
    property TabOrder;
    property TabStop;
    property UseDockManager;
    property Anchors;
    property BiDiMode;
    property Constraints;
    property DragKind;
    property DragMode;
    property DragCursor;
    property ParentBiDiMode;
    property DockSite;
    property OnEndDock;
    property OnStartDock;
    property OnCanResize;
    property OnConstrainedResize;
    property OnDockDrop;
    property OnDockOver;
    property OnGetSiteInfo;
    property OnUnDock;
    property OnContextPopup;
    property OnClick;
    property OnDblClick;
    property OnDragDrop;
    property OnDragOver;
    property OnEndDrag;
    property OnEnter;
    property OnExit;
    property OnMouseDown;
    property OnMouseMove;
    property OnMouseUp;
    property OnResize;
    property OnStartDrag;
  end;

procedure Register;

implementation

procedure Register;
begin
  RegisterComponents('Macecraft GUIPanels', [TGUIPanel]);
end;

constructor TCustomGUIPanel.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  FAlignControlsCalls := 0;

  FControlList := TObjectList.Create(False);

  ControlStyle := ControlStyle - [csSetCaption];
  ControlStyle := ControlStyle + [csAcceptsControls, csOpaque];
  DoubleBuffered := True;

  FAutoSizeW := False;
  FAutoSizeH := False;

  ParentFont := True;
  ParentColor := True;

  SetBounds(0, 0, 185, 41);
  AdjustControls;
end;

destructor TCustomGUIPanel.Destroy;
begin
  FControlList.Free;
  inherited;
end;

procedure TCustomGUIPanel.WMEraseBkgnd(var Message: TWmEraseBkgnd);
begin
{ Only erase background if we're not doublebuffering or painting to memory. }
  if not FDoubleBuffered or
{$IF DEFINED(CLR)}
    (Message.OriginalMessage.WParam = Message.OriginalMessage.LParam) then
{$ELSE}
    (TMessage(Message).WParam = WParam(TMessage(Message).LParam)) then
{$ENDIF}
    begin
      if StyleServices.Enabled and Assigned(Parent) and (csParentBackground in ControlStyle) then
        begin
          if Parent.DoubleBuffered then
            PerformEraseBackground(Self, Message.DC)
          else
            StyleServices.DrawParentBackground(Handle, Message.DC, nil, False);
        end
      else
        FillRect(Message.DC, ClientRect, Brush.Handle);
    end;
  Message.Result := 1;
end;

procedure TCustomGUIPanel.CMControlListChanging
  (var Message: TCMControlListChanging);
begin

  Try
    inherited;
    if Message.Inserting and (Message.ControlListItem.Parent = Self) then
    begin
      if FControlList.IndexOf(Message.ControlListItem.Control) < 0 then
        FControlList.Add(Message.ControlListItem.Control);
    end
    else
      FControlList.Remove(Message.ControlListItem.Control);
 Except
  //HandleException();
 End;


end;

procedure TCustomGUIPanel.GetChildren(Proc: TGetChildProc; Root: TComponent);
var
  i       : Integer;
  Control : TControl;
begin

  for i := 0 to FControlList.Count - 1 do
  begin

    if (assigned(FControlList[i]) and (FControlList[i] is TControl)) then
    begin
     Control := TControl(FControlList[i]);
     if Control.Owner = Root then Proc(Control);
    end;
  end;

end;

function TCustomGUIPanel.GetControlIndex(AControl: TControl): Integer;
begin
  Result := FControlList.IndexOf(AControl);
end;

procedure TCustomGUIPanel.SetControlIndex(AControl: TControl; Index: Integer);
var
  CurIndex: Integer;
begin

  CurIndex := GetControlIndex(AControl);
  if (CurIndex > -1) and (CurIndex <> Index) and (Index < FControlList.Count)
    then
  begin
    FControlList.Move(CurIndex, Index);
    Realign;
  end;
end;

procedure TCustomGUIPanel.Set_AutoSizeW(Value: Boolean);
begin

  FAutoSizeW := Value;
  Invalidate;
  AdjustControls;
end;

procedure TCustomGUIPanel.Set_AutoSizeH(Value: Boolean);
begin

  FAutoSizeH := Value;
  Invalidate;
  AdjustControls;
end;

procedure TCustomGUIPanel.CMEnabledChanged(var Message: TMessage);
begin
  inherited;
  Invalidate;
end;

procedure TCustomGUIPanel.AlignControls(AControl: TControl; var Rect: TRect);
begin
 {$IFDEF EnablePerformanceLog} try PerfLog_SectionBegin('TCustomGUIPanel.AlignControls', Self); {$ENDIF}
  Try

    Inc(FAlignControlsCalls);
    if ControlCount < 1 then
    begin
      if Showing then
        AdjustSize;
      Exit;
    end;
    AdjustClientRect(Rect);
    AdjustControls;
 Except
  //HandleException();
 End;

 {$IFDEF EnablePerformanceLog} finally PerfLog_SectionEnd('TCustomGUIPanel.AlignControls'); end; {$ENDIF}
end;

procedure TCustomGUIPanel.AdjustControls;
begin
  // do nothing, descendants should override this
end;

procedure TGUIPanel.AdjustControls(const ForceUpdate : Boolean = False);
var
  Control: TControl;
  I, X, Y: Integer;
  MinPos, MaxPos: TPoint;
begin
 {$IFDEF EnablePerformanceLog} try PerfLog_SectionBegin('TGUIPanel.AdjustControls', Self); {$ENDIF}
  if csReading in ComponentState then Exit;

  Try

    if ControlCount < 1 then
    begin
      if Showing then
        AdjustSize;
      Exit;
    end;

    // iterate components; collect width and height
    for I := 0 to FControlList.Count - 1 do
    begin
      Control := TControl(FControlList[I]);

      X := Control.Left;
      Y := Control.Top;
      if (X < MinPos.X) or (I = 0) then
        MinPos.X := X;
      if (Y < MinPos.Y) or (I = 0) then
        MinPos.Y := Y;

      X := X + Control.Width;
      Y := Y + Control.Height;
      if (X > MaxPos.X) or (I = 0) then
        MaxPos.X := X;
      if (Y > MaxPos.Y) or (I = 0) then
        MaxPos.Y := Y;
    end;

    if Self.Align = alClient then
    begin
      FAutoSizeW := False;
      FAutoSizeH := False;
    end;

    if Self.Align = alClient then
    begin
      FAutoSizeW := False;
      FAutoSizeH := False;
    end;

    if Self.Align = alTop then
      FAutoSizeW := False;
    if Self.Align = alBottom then
      FAutoSizeW := False;
    if Self.Align = alLeft then
      FAutoSizeH := False;
    if Self.Align = alRight then
      FAutoSizeH := False;

    // resize width if needed
    if FAutoSizeW then
    begin
      for I := 0 to FControlList.Count - 1 do
        with TControl(FControlList[I]) do
          Left := Left - MinPos.X;
      X := MaxPos.X - MinPos.X;
      if X <> Width then
        Width := X;
    end;

    // resize height if needed
    if FAutoSizeH then
    begin
      for I := 0 to FControlList.Count - 1 do
        with TControl(FControlList[I]) do
          Top := Top - MinPos.Y;
      Y := MaxPos.Y - MinPos.Y;
      if Y <> Height then
        Height := Y;
    end;

    ControlsAligned;
    if Showing then
      AdjustSize;

 Except
  //HandleException();
 End;

 {$IFDEF EnablePerformanceLog} finally PerfLog_SectionEnd('TGUIPanel.AdjustControls'); end; {$ENDIF}
end;

procedure TCustomGUIPanel.Paint;
var
  memoryBitmap: TBitmap;
  trt: TRect;
  S: String;
  X: Integer;
begin
 {$IFDEF EnablePerformanceLog} try PerfLog_SectionBegin('TCustomGUIPanel.Paint', Self); {$ENDIF}

  memoryBitmap := TBitmap.Create; // create memory bitmap to draw flicker-free
  try
    memoryBitmap.Height := ClientRect.Bottom;
    memoryBitmap.Width := ClientRect.Right;

    if csDesigning in ComponentState then
    begin
      trt := ClientRect;
      with memoryBitmap.Canvas do
      begin
        // Draw background
        Brush.Color := clWhite;
        FillRect(trt);

        // Draw border
        Brush.Color := clSilver;
        FrameRect(trt);
        InflateRect(trt, -1, -1);
        FrameRect(trt);

        // Display classname at designtime
        if (Height > 25) and (Width > 30) then
        begin
          S := Self.ClassName;
          Brush.Style := bsClear;
          Font.Name := 'Arial';
          Font.Style := [fsBold];
          Font.Size := 8;
          X := memoryBitmap.Canvas.TextWidth(S);
          Font.Color := clBlack;
          TextOut(ClientWidth - X - 3, 3, S);
          Font.Color := clWhite;
          TextOut(ClientWidth - X - 4, 2, S);
        end;
      end;
    end
    else
    begin
      // Draw background
      memoryBitmap.Canvas.Brush.Color := Self.Color;
      memoryBitmap.Canvas.FillRect(ClientRect);
    end;

    // Copy memoryBitmap to screen
    Canvas.CopyRect(ClientRect, memoryBitmap.Canvas, ClientRect);
  finally
    FreeAndNil(memoryBitmap); // delete the bitmap
  end;

 {$IFDEF EnablePerformanceLog} finally PerfLog_SectionEnd('TCustomGUIPanel.Paint'); end; {$ENDIF}
end;

end.
