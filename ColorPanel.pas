unit ColorPanel;

{$R-,T-,X+,H+,B-,O+,Q-}

interface

uses
  Windows, Messages, SysUtils, Classes,
  Graphics, Controls, Forms, Math,
  ExtCtrls, StdCtrls,
  Vcl.ImageCollection, vcl.Themes;

Type TDrawSymbol = (dsNone, dsClose, dsMinimize, dsMaximize, dsUnMaximize,
  dsArrowDown, dsArrowUp, dsTriangleDown, dsTriangleUp, dsMenuBoxLeft, dsMenuBoxRight);

type
  TColorPanel = class(TCustomPanel)
  private
    FImageCollection    : TImageCollection;
    FGlyphName          : string;
    FGlyphLeftMargin    : Integer;
    FGlyphTopPadding    : Integer;
    FGlyphResizing      : Boolean;
    FGlyphCentered      : Boolean;
    FGlyphSize          : Integer;
    FGlyphSizeMin       : Integer;
    FGlyphSizeMax       : Integer;
    FBorderTop          : Boolean;
    FBorderBottom       : Boolean;
    FBorderLeft         : Boolean;
    FBorderRight        : Boolean;
    FBorderColor        : TColor;
    FFocusBorderColor   : TColor;
    FFocusSymbolColor   : TColor;
    FFocusColor         : TColor;
    FClickColor         : TColor;
    FBorderWidth        : Integer;
    FBorderWithMargins  : Boolean;
    FPreChangeColor     : TColor;
    FOrigColor          : TColor;
    FFocusColorEnabled  : Boolean;
    FMouseInside        : Boolean;
    FClickColorEnabled  : Boolean;
    FDrawSymbol         : TDrawSymbol;
    FDrawSymbolColor    : TColor;
    FDrawSymbolSize     : Integer;
    FUpdateLock         : Integer;
    FTextAlignment      : TAlignment;

    FFadeEffectIdx      : Integer;
    FFadeOutEffectIdx   : Integer;
    FFadeColorEffect    : Boolean;
    FFadeColorSteps     : Integer;
    FFadeEnterStepDelay : Integer;
    FFadeClickStepDelay : Integer;
    FFadeStartColor     : TColor;
    FFadeEndColor       : TColor;
    FFadeInTimer        : TTimer;
    FFadeInOutTimer     : TTimer;
    FTextLeftPadding    : Integer;
    FTextTopPadding     : Integer;
    FTextDrawEnabled    : Boolean;
    FWordWrap           : Boolean;
    FTagStr             : String;

    FDebug_TextRect     : TRect;

    procedure Handle_WM_MouseEnter(var Msg: TMessage); message CM_MOUSEENTER;
    procedure Handle_WM_MouseLeave(var Msg: TMessage); message CM_MOUSELEAVE;
    procedure Handle_WM_MouseUp(var Msg: TMessage);    message WM_LBUTTONUP;
    procedure WMEraseBkgnd(var Message: TWmEraseBkgnd); message WM_ERASEBKGND;

    procedure SetDrawSymbolSize(Value : Integer);
    Procedure SetDrawSymbol(Value : TDrawSymbol);
    Procedure SetBorderWidth(Value : Integer);
    function DrawTextDo(Canvas: TCanvas; const ClientRect: TRect; S: String): Integer;

    procedure FadeColorTo(TargetColor : TColor);
    procedure FadeColorToAndBack(TargetColor : TColor);
    Function CalculateFadeinColor(StartColor, EndColor : TColor; CurrentStep, FinalStep : Integer) : TColor;
    procedure tmrFadeInTimerOnTimer(Sender : TObject);
    procedure tmrFadeInOutTimerOnTimer(Sender : TObject);

    procedure SetImageCollection(NewValue: TImageCollection);
    procedure SetGlyphName(NewValue: string);
    procedure SetGlyphLeftMargin(NewValue: Integer);
    procedure SetGlyphTopPadding(NewValue: Integer);
    procedure SetGlyphResizing(NewValue: Boolean);
    procedure SetGlyphSizeMin(NewValue: Integer);
    procedure SetGlyphSizeMax(NewValue: Integer);
  protected
    procedure Paint; override;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure CopySettingsFrom(Panel : TColorPanel);

    procedure BeginUpdate();
    procedure EndUpdate();
    procedure ResetColors();
    procedure AutoSizeByCaption();
    Function GetRecommendedWidth() : Integer;

    property UpdateLockCount  : Integer     read FUpdateLock;
  published
   property GlyphCollection: TImageCollection read FImageCollection write SetImageCollection;
    // Defines the name of the image inside TImageCollection that the control draws to its canvas.

   property GlyphName: string read FGlyphName write SetGlyphName;
    // Defines the distance between the left edge of the control and the PNG glyph drawn.
    // For example, if GlyphLeftMargin = 5, there will be empty space of 5 units between the left edge of the control and the left edge of the PNG glyph.

   property GlyphLeftMargin: Integer read FGlyphLeftMargin write SetGlyphLeftMargin;
    //  Defines a minimum space required to be empty between the top of the PNG Glyph and the edge of the control.

   property GlyphTopPadding: Integer read FGlyphTopPadding write SetGlyphTopPadding;
    // Defines whether the glyph can be resized.
    // Note: Even if set to true, the resizing shall not ever change the ratio of height and width of the glyph.
   property GlyphResizing  : Boolean read FGlyphResizing  write SetGlyphResizing;
   property GlyphSize      : Integer read FGlyphSize;
   property GlyphCentered  : Boolean read FGlyphCentered  write FGlyphCentered;
   property GlyphSizeMin   : Integer read FGlyphSizeMin   write SetGlyphSizeMin;
   property GlyphSizeMax   : Integer read FGlyphSizeMax   write SetGlyphSizeMax;


   property BorderTop         : Boolean     read FBorderTop         write FBorderTop;
   property BorderBottom      : Boolean     read FBorderBottom      write FBorderBottom;
   property BorderLeft        : Boolean     read FBorderLeft        write FBorderLeft;
   property BorderRight       : Boolean     read FBorderRight       write FBorderRight;
   property BorderWidth       : Integer     read FBorderWidth       write SetBorderWidth;
   property BorderWithMargins : Boolean     read FBorderWithMargins write FBorderWithMargins;
   property BorderColor       : TColor      read FBorderColor       write FBorderColor;
   property FocusColor        : TColor      read FFocusColor        write FFocusColor;
   property ClickColor        : TColor      read FClickColor        write FClickColor;
   property FocusColorEnabled : Boolean     read FFocusColorEnabled write FFocusColorEnabled;
   property ClickColorEnabled : Boolean     read FClickColorEnabled write FClickColorEnabled;
   property DrawSymbol        : TDrawSymbol read FDrawSymbol        write SetDrawSymbol;
   property DrawSymbolColor   : TColor      read FDrawSymbolColor   write FDrawSymbolColor;
   property DrawSymbolSize    : Integer     read FDrawSymbolSize    write SetDrawSymbolSize;
   property FocusBorderColor  : TColor      read FFocusBorderColor  write FFocusBorderColor;
   property FocusSymbolColor  : TColor      read FFocusSymbolColor  write FFocusSymbolColor;

   property TextLeftPadding   : Integer     read FTextLeftPadding   write FTextLeftPadding;
   property TextTopPadding    : Integer     read FTextTopPadding    write FTextTopPadding;
   property TextDrawEnabled   : Boolean     read FTextDrawEnabled   write FTextDrawEnabled;

   // If FadeColorEffect = True, the FocusColor and ClickColor changes are done via a fade-in effect (in steps)
   property FadeColorEffect    : Boolean     read FFadeColorEffect    write FFadeColorEffect;
   property FadeColorSteps     : Integer     read FFadeColorSteps     write FFadeColorSteps;
   property FadeEnterStepDelay : Integer     read FFadeEnterStepDelay write FFadeEnterStepDelay;
   property FadeClickStepDelay : Integer     read FFadeClickStepDelay write FFadeClickStepDelay;
   property Alignment          : TAlignment  read FTextAlignment      write FTextAlignment;
   property WordWrap           : Boolean     read FWordWrap           write FWordWrap;
   property TagStr             : String      read FTagStr             write FTagStr;
   Property Debug_TextRect     : TRect       read FDebug_TextRect;

   property Caption;
   property Font;
   property Align;
   property Visible;
   property Color;
   property OnClick;
   property OnDblClick;
   property OnMouseDown;
   property OnMouseMove;
   property OnMouseUp;
   property OnMouseEnter;
   property OnMouseLeave;
   property OnResize;

   property ParentColor;
   property ParentBackground;
   property PopupMenu;

  end;

procedure Register;

implementation


procedure Register;
begin
  RegisterComponents('Macecraft', [TColorPanel]);
end;

constructor TColorPanel.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);

  FUpdateLock           := 1;
  Self.BevelInner       := bvNone;
  Self.BevelOuter       := bvNone;
  Self.BevelKind        := bkNone;
  Self.BorderStyle      := bsNone;
  Self.DoubleBuffered   := True;
  Self.ParentBackground := False;
  FPreChangeColor       := Self.Color;
  FGlyphSize            := 0;
  FGlyphSizeMin         := -1;
  FGlyphSizeMax         := -1;
  FBorderTop            := True;
  FBorderBottom         := True;
  FBorderLeft           := True;
  FBorderRight          := True;
  FBorderWidth          := 1;
  FBorderWithMargins    := False;
  FBorderColor          := clBlack;
  FFocusColor           := clWhite;
  FClickColor           := clWhite;
  FFocusColorEnabled    := False;
  FClickColorEnabled    := False;
  FDrawSymbol           := dsNone;
  FDrawSymbolColor      := clWhite;
  FDrawSymbolSize       := 1;
  FFocusBorderColor     := clBlack;
  FFocusSymbolColor     := clWhite;
  FTextLeftPadding      := 1;
  FTextTopPadding       := 1;
  FTextDrawEnabled      := True;
  FFadeColorEffect      := False;
  FFadeColorSteps       := 5;
  FFadeEnterStepDelay   := 10;
  FFadeClickStepDelay   := 2;
  FTextAlignment        := taCenter;
  FWordWrap             := False;
  FTagStr               := '';
  
  FFadeInTimer := TTimer.Create(Self);
  FFadeInTimer.Interval := 1;
  FFadeInTimer.Enabled  := False;
  FFadeInTimer.OnTimer  := tmrFadeInTimerOnTimer;

  FFadeInOutTimer := TTimer.Create(Self);
  FFadeInOutTimer.Interval := 1;
  FFadeInOutTimer.Enabled  := False;
  FFadeInOutTimer.OnTimer  := tmrFadeInOutTimerOnTimer;

  FDebug_TextRect.Left   := 0;
  FDebug_TextRect.Top    := 0;
  FDebug_TextRect.Bottom := 0;
  FDebug_TextRect.Right  := 0;

  FMouseInside := False;
  FUpdateLock  := 0;
  FOrigColor   := Self.Color;
end;


destructor TColorPanel.Destroy;
begin

 FFadeInTimer.Enabled := False;
 FFadeInOutTimer.Enabled := False;

 FFadeInTimer.Free;
 FFadeInOutTimer.Free;

 inherited;
end;

procedure TColorPanel.SetImageCollection(NewValue: TImageCollection);
begin
  If FImageCollection <> NewValue then
  begin
   FImageCollection := NewValue;
   If FUpdateLock = 0 then Self.Invalidate();
  End;
end;

procedure TColorPanel.SetGlyphName(NewValue: string);
begin
  If FGlyphName <> NewValue then
  begin
   FGlyphName := NewValue;
   If FUpdateLock = 0 then Self.Invalidate();
  End;
end;

procedure TColorPanel.SetGlyphLeftMargin(NewValue: Integer);
begin
  If FGlyphLeftMargin <> NewValue then
  begin
   FGlyphLeftMargin := NewValue;
   If FUpdateLock = 0 then Self.Invalidate();
  End;
end;

procedure TColorPanel.SetGlyphTopPadding(NewValue: Integer);
begin
  If FGlyphTopPadding <> NewValue then
  begin
   FGlyphTopPadding := NewValue;
   If FUpdateLock = 0 then Self.Invalidate();
  End;
end;

procedure TColorPanel.SetGlyphSizeMin(NewValue: Integer);
begin
  If FGlyphSizeMin <> NewValue then
  begin
   FGlyphSizeMin := NewValue;
   If FUpdateLock = 0 then Self.Invalidate();
  End;
end;

procedure TColorPanel.SetGlyphSizeMax(NewValue: Integer);
begin
  If FGlyphSizeMax <> NewValue then
  begin
   FGlyphSizeMax := NewValue;
   If FUpdateLock = 0 then Self.Invalidate();
  End;
end;

procedure TColorPanel.SetGlyphResizing(NewValue: Boolean);
begin
  If FGlyphResizing <> NewValue then
  begin
   FGlyphResizing := NewValue;
   If FUpdateLock = 0 then Self.Invalidate();
  End;
end;

procedure TColorPanel.CopySettingsFrom(Panel : TColorPanel);
begin

 Self.BeginUpdate;

 Try
   Self.Font.Assign(Panel.Font);

   Self.BorderTop          := Panel.BorderTop;
   Self.BorderBottom       := Panel.BorderBottom;
   Self.BorderLeft         := Panel.BorderLeft;
   Self.BorderRight        := Panel.BorderRight;
   Self.BorderWidth        := Panel.BorderWidth;
   Self.BorderWithMargins  := Panel.BorderWithMargins;
   Self.BorderColor        := Panel.BorderColor;
   Self.BorderStyle        := Panel.BorderStyle;
   Self.Color              := Panel.Color;
   Self.FadeColorEffect    := Panel.FadeColorEffect;
   Self.FadeColorSteps     := Panel.FadeColorSteps;
   Self.FadeEnterStepDelay := Panel.FadeEnterStepDelay;
   Self.FadeClickStepDelay := Panel.FadeClickStepDelay;
   Self.FocusColor         := Panel.FocusColor;
   Self.FocusColorEnabled  := Panel.FocusColorEnabled;
   Self.FocusBorderColor   := Panel.FocusBorderColor;
   Self.ClickColor         := Panel.ClickColor;
   Self.ClickColorEnabled  := Panel.ClickColorEnabled;
   Self.DrawSymbol         := Panel.DrawSymbol;
   Self.DrawSymbolColor    := Panel.DrawSymbolColor;
   Self.DrawSymbolSize     := Panel.DrawSymbolSize;
   Self.GlyphCollection    := Panel.GlyphCollection;
   Self.GlyphName          := Panel.GlyphName;
   Self.GlyphLeftMargin    := Panel.GlyphLeftMargin;
   Self.GlyphTopPadding    := Panel.GlyphTopPadding;
   Self.GlyphResizing      := Panel.GlyphResizing;
   Self.TextLeftPadding    := Panel.TextLeftPadding;
   Self.TextTopPadding     := Panel.TextTopPadding;
   Self.TextDrawEnabled    := Panel.TextDrawEnabled;
   Self.WordWrap           := Panel.WordWrap;
   Self.Tag                := Panel.Tag;
   Self.TagStr             := Panel.TagStr;
 Finally
   Self.EndUpdate;
 End;

end;

procedure TColorPanel.BeginUpdate;
Begin
 Inc(FUpdateLock);
End;

procedure TColorPanel.EndUpdate;
Begin
 Dec(FUpdateLock);
 FOrigColor := Self.Color;

 if FUpdateLock <= 0 then
 begin
  FUpdateLock := 0;
  Self.Invalidate;
  Self.Refresh;
 end;
End;

Function TColorPanel.GetRecommendedWidth() : Integer;
Var
 TmpLbl : TLabel;
begin

 TmpLbl := TLabel.Create(Self);
 TmpLbl.Parent := Self;
 TmpLbl.Left := -2000;
 TmpLbl.Visible := False;
 TmpLbl.AutoSize := True;
 TmpLbl.WordWrap := False;
 TmpLbl.Font.Assign(Self.Font);

 TmpLbl.Caption := Self.Caption;

 Result := Round(TmpLbl.Width * 1.3 + Self.Padding.Left + Self.Padding.Right);

 TmpLbl.Free;

End;

procedure TColorPanel.AutoSizeByCaption;
Var
 TmpLbl : TLabel;
Begin

 if (Self.Align = alClient) then EXIT;

 TmpLbl := TLabel.Create(Self);
 TmpLbl.Parent := Self;
 TmpLbl.Left := -2000;
 TmpLbl.Visible := False;
 TmpLbl.AutoSize := True;
 TmpLbl.WordWrap := False;
 TmpLbl.Font.Assign(Self.Font);

 TmpLbl.Caption := Self.Caption;

 if (Self.Align = alNone) or
    (Self.Align = alLeft) or
    (Self.Align = alRight) then Self.Width := Round(TmpLbl.Width * 1.3 + Self.Padding.Left + Self.Padding.Right);

 if (Self.Align = alNone) or
    (Self.Align = alTop) or
    (Self.Align = alBottom) then Self.Height := Round(TmpLbl.Height * 1.3 + Self.Padding.Top + Self.Padding.Bottom);

 TmpLbl.Free;
End;

procedure TColorPanel.ResetColors;
begin
 FFadeInTimer.Enabled := False;
 FFadeInOutTimer.Enabled  := False;
 FUpdateLock := 0;
 FFadeEffectIdx := 0;
 Self.Color := FOrigColor;
 FMouseInside := False;

 If FUpdateLock = 0 then Self.Invalidate();
end;

procedure TColorPanel.tmrFadeInTimerOnTimer(Sender : TObject);
Var
 NewColor : TColor;
begin


 if (FFadeColorEffect = False) or
    (csDesigning in ComponentState) then
 begin
  FFadeInTimer.Enabled := False;
  Exit;
 End;

 NewColor := CalculateFadeinColor(FFadeStartColor, FFadeEndColor, FFadeEffectIdx, FFadeColorSteps);
 Self.Color := NewColor;
 Self.Invalidate;

 Inc(FFadeEffectIdx);
 if FFadeEffectIdx > FFadeColorSteps then
 begin
  FFadeInTimer.Enabled := False;
 end;

end;

procedure TColorPanel.tmrFadeInOutTimerOnTimer(Sender : TObject);
Var
 NewColor : TColor;
 tmpColor : TColor;
begin


 if (FFadeColorEffect = False) or
    (csDesigning in ComponentState) then
 begin
  FFadeInTimer.Enabled := False;
  Exit;
 End;

 NewColor := CalculateFadeinColor(FFadeStartColor, FFadeEndColor, FFadeEffectIdx, FFadeColorSteps);
 Self.Color := NewColor;
 Self.Invalidate;

 Inc(FFadeEffectIdx);
 if FFadeEffectIdx > FFadeColorSteps then
 begin
  if FFadeOutEffectIdx = 0 then
  begin // Reverse:
   tmpColor := FFadeStartColor;
   FFadeStartColor := FFadeEndColor;
   FFadeEndColor := tmpColor;
   FFadeOutEffectIdx := 1;
   FFadeEffectIdx    := 0;
  end else
  begin
   FFadeInOutTimer.Enabled := False;
  end;

 end;

end;



procedure TColorPanel.FadeColorTo(TargetColor : TColor);
begin

 FFadeOutEffectIdx := 0;
 FFadeEffectIdx    := 0;
 FFadeStartColor   := Self.Color;
 FFadeEndColor     := TargetColor;

 FFadeInTimer.Interval   := FFadeEnterStepDelay;
 FFadeInTimer.Enabled    := True;
 FFadeInOutTimer.Enabled := False;

end;

procedure TColorPanel.FadeColorToAndBack(TargetColor : TColor);
begin
 FFadeOutEffectIdx := 0;
 FFadeEffectIdx    := 0;
 FFadeStartColor   := Self.Color;
 FFadeEndColor     := TargetColor;

 FFadeInOutTimer.Interval := FFadeClickStepDelay;
 FFadeInOutTimer.Enabled  := True;
 FFadeInTimer.Enabled     := False;

end;


procedure TColorPanel.Handle_WM_MouseEnter(var Msg: TMessage);
begin

 If Self = nil then EXIT;

 Inherited;
 FMouseInside := True;

 If (not (csDesigning in ComponentState)) and
    (FFocusColorEnabled) and
    (Self.FFocusColor <> Self.Color) and
    (Self.Enabled) and
    (Self.Visible) and
    (FFadeInTimer.Enabled = False) and
    (FFadeInOutTimer.Enabled = False) then
 begin
  FPreChangeColor := Self.Color;

  if FFadeColorEffect then Self.FadeColorTo(FFocusColor)
  else
  begin
   Self.Color := FFocusColor;
   Self.Invalidate();
  end;
 end;


end;

procedure TColorPanel.Handle_WM_MouseLeave(var Msg: TMessage);
begin
 If Self = nil then EXIT;

 Inherited;
 FMouseInside := False;

 If (not (csDesigning in ComponentState)) and
    (FFocusColorEnabled) and
    (Self.Enabled) then
 begin
  if FFadeColorEffect then Self.FadeColorTo(FPreChangeColor)
  else
  begin
   Self.Color := FPreChangeColor;
   Self.Invalidate();
  end;
 end;

end;

procedure TColorPanel.WMEraseBkgnd(var Message: TWmEraseBkgnd);
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


procedure TColorPanel.Handle_WM_MouseUp(var Msg: TMessage);
Var
 PreChangeColor : TColor;
begin

 If Self = nil then EXIT;

 Inherited;

 If (not (csDesigning in ComponentState)) and
    (FClickColorEnabled) and
    (Self.Enabled) then
 begin
  PreChangeColor := Self.Color;

  if FFadeColorEffect then Self.FadeColorToAndBack(FClickColor)
  else
  begin
   Self.Color := FClickColor;
   Self.Invalidate();
  end;

  Sleep(10);

  if FFadeColorEffect = False then
  else
  begin
   Self.Color := PreChangeColor;
   Self.Invalidate();
  end;
 end;

end;

procedure TColorPanel.SetDrawSymbolSize(Value : Integer);
begin
 if FDrawSymbolSize <> Value then
 begin
  FDrawSymbolSize := Value;
  If FUpdateLock = 0 then Self.Invalidate;
 end;
end;

Procedure TColorPanel.SetBorderWidth(Value : Integer);
begin
 if FBorderWidth <> Value then
 begin
  FBorderWidth := Value;
  If FUpdateLock = 0 then Self.Invalidate;
 end;
end;

Procedure TColorPanel.SetDrawSymbol(Value : TDrawSymbol);
begin
 if FDrawSymbol <> Value then
 begin
  FDrawSymbol := Value;
  If FUpdateLock = 0 then Self.Invalidate;
 end;
end;

// Allows drawing of fading in colors, for example from white to grays to black
// Note: Indexing starts at zero!
Function TColorPanel.CalculateFadeinColor(StartColor, EndColor : TColor; CurrentStep, FinalStep : Integer) : TColor;
Var
 Steps   : Integer;
 Start_R : Byte;
 Start_G : Byte;
 Start_B : Byte;
 End_R   : Byte;
 End_G   : Byte;
 End_B   : Byte;
 Final_R : Byte;
 Final_G : Byte;
 Final_B : Byte;
Begin

 if CurrentStep <= 0 then EXIT(StartColor);
 if CurrentStep >= FinalStep then EXIT(EndColor);
 If StartColor = EndColor then EXIT(EndColor);

 Start_R := (StartColor and $000000ff);
 Start_G := (StartColor and $0000ff00) shr 8;
 Start_B := (StartColor and $00ff0000) shr 16;

 End_R := (EndColor and $000000ff);
 End_G := (EndColor and $0000ff00) shr 8;
 End_B := (EndColor and $00ff0000) shr 16;

 Final_R := Start_R;
 Final_G := Start_G;
 Final_B := Start_B;
 Steps   := FinalStep;

 if Start_R < End_R then Final_R := Final_R + Round(((End_R-Start_R) / Steps) * CurrentStep)
 else Final_R := Final_R - Round(((Start_R-End_R) / Steps) * CurrentStep);

 if Start_G < End_G then Final_G := Final_G + Round(((End_G-Start_G) / Steps)  * CurrentStep)
 else Final_G := Final_G - Round(((Start_G-End_G) / Steps) * CurrentStep);

 if Start_B < End_B then Final_B := Final_B + Round(((End_B-Start_B) / Steps) * CurrentStep)
 else Final_B := Final_B - Round(((Start_B-End_B) / Steps) * CurrentStep);

 Result := RGB(Final_R, Final_G, Final_B);
End;


function TColorPanel.DrawTextDo(Canvas: TCanvas; const ClientRect: TRect; S: String): Integer;
var
  DrawRect   : TRect;
  DrawFlags  : Cardinal;
  DrawParams : TDrawTextParams;
begin
  DrawRect  := ClientRect;
  DrawFlags := DT_END_ELLIPSIS or DT_NOPREFIX or DT_EDITCONTROL;
  if FWordWrap then DrawFlags := DrawFlags or DT_WORDBREAK;

  if Self.FTextAlignment = taCenter then DrawFlags := DrawFlags or DT_CENTER
  else if Self.FTextAlignment = taLeftJustify then DrawFlags := DrawFlags or DT_LEFT
  else if Self.FTextAlignment = taRightJustify then DrawFlags := DrawFlags or DT_RIGHT;

  // Just in case:
  if FTextLeftPadding < 0 then FTextLeftPadding := 0;
  if FTextTopPadding  < 0 then FTextTopPadding  := 0;  

  //OffsetRect(DrawRect, FTextLeftPadding, FTextTopPadding);
  DrawRect.Left   := DrawRect.Left   + Max( FTextLeftPadding, 2);
  DrawRect.Right  := DrawRect.Right  - Max( FTextLeftPadding, 2);
  DrawRect.Top    := DrawRect.Top    + Max( FTextTopPadding, 2);
  DrawRect.Bottom := DrawRect.Bottom - Max( FTextTopPadding, 2);

  if (FGlyphSize > 0) and (FGlyphName <> '') then
      DrawRect.Left := DrawRect.Left + FGlyphLeftMargin + FGlyphSize;

  DrawText(Canvas.Handle, PChar(S), -1, DrawRect, DrawFlags or DT_CALCRECT);
  DrawRect.Right := ClientRect.Right;

  if DrawRect.Bottom < ClientRect.Bottom then
    OffsetRect(DrawRect, 0, (ClientRect.Bottom - DrawRect.Bottom) div 2 -1)
  else
    DrawRect.Bottom := ClientRect.Bottom;

  FDebug_TextRect := DrawRect;

  ZeroMemory(@DrawParams, SizeOf(DrawParams));
  DrawParams.cbSize := SizeOf(DrawParams);
  DrawTextEx(Canvas.Handle, PChar(S), -1, DrawRect, DrawFlags, @DrawParams);
  Result := DrawParams.uiLengthDrawn;
end;


procedure TColorPanel.Paint;
CONST
 LEFT_ALIGN_MARGIN = 5;

var
  points        : array of TPoint;
  mem           : TBitmap;
  trt           : TRect;
  start_x       : Integer;
  start_y       : Integer;
  end_x         : Integer;
  end_y         : Integer;
  sfact         : Integer;
  iVal          : Integer;
  iCount        : integer;
  desiredHeight : Integer;
  y, k, Index   : Integer;
  BestDelta     : Integer;
  BestIndex     : Integer;
  CurDelta      : Integer;
  Rect          : TRect;
  tmp_x         : Integer;
  tmp_y         : Integer;
begin

  If Self = nil then EXIT;
  Inherited;
  If FUpdateLock > 0 then EXIT;

  mem := TBitmap.Create; // create memory bitmap to draw flicker-free
  try
    mem.Height := ClientRect.Bottom;
    mem.Width  := ClientRect.Right;

    trt := ClientRect;
    with mem.Canvas do
    begin
     // Draw background
     Brush.Color := Self.Color;
     FillRect(trt);
     iVal := 0;

     if (FImageCollection <> nil) and (FGlyphName <> '') then
     begin
      Index := FImageCollection.GetIndexByName(FGlyphName);
      if Index >= 0 then
      begin

        if FGlyphResizing then
        begin

          If FGlyphSizeMax > 0 then
          begin
           tmp_x := Trunc((mem.Width  - FGlyphSizeMax - FGlyphLeftMargin * 2) / 2);
           tmp_y := Trunc((mem.Height - FGlyphSizeMax - FGlyphTopPadding * 2) / 2);
          End else
          Begin
           tmp_x := 0;
           tmp_y := 0;
          End;

          Rect.Left   := FGlyphLeftMargin + tmp_x;
          Rect.Right  := mem.Width - tmp_x;
          Rect.Top    := FGlyphTopPadding + tmp_y;
          Rect.Bottom := mem.Height - FGlyphTopPadding - tmp_y;

          FImageCollection.Draw(mem.Canvas, Rect, FGlyphName, True);
          iVal := Rect.Bottom - Rect.Top;
        end
        else
        begin
          desiredHeight := mem.Height - FGlyphTopPadding * 2;
          BestDelta := 0;
          BestIndex := -1;

          For k := 0 to FImageCollection.Images[Index].SourceImages.Count-1 do
          begin
           if (FImageCollection.Images[Index].SourceImages.Items[k].Image.Width  > Self.Width - FGlyphLeftMargin) or
              (FImageCollection.Images[Index].SourceImages.Items[k].Image.Height > Self.Height - FGlyphTopPadding*2) then Continue;

           if (FGlyphSizeMin > 0) and
               ((FImageCollection.Images[Index].SourceImages.Items[k].Image.Width < FGlyphSizeMin) or
                (FImageCollection.Images[Index].SourceImages.Items[k].Image.Height < FGlyphSizeMin)) then Continue;

           if (FGlyphSizeMax > 0) and
               ((FImageCollection.Images[Index].SourceImages.Items[k].Image.Width > FGlyphSizeMax) or
                (FImageCollection.Images[Index].SourceImages.Items[k].Image.Height > FGlyphSizeMax)) then Continue;

           CurDelta := Abs(desiredHeight - FImageCollection.Images[Index].SourceImages.Items[k].Image.Height);

            if (CurDelta < BestDelta) or (BestIndex = -1) then
            begin
              BestDelta := CurDelta;
              BestIndex := k;
            end;
          end;

          if BestIndex > -1 then
          begin
            iVal := FImageCollection.Images[Index].SourceImages.Items[BestIndex].Image.Height;

            if FGlyphCentered and (FTextDrawEnabled = False) then
            begin
             tmp_x := mem.Width  div 2 - FGlyphSize div 2;
             tmp_y := mem.Height div 2 - FGlyphSize div 2;
            End Else
            begin
             tmp_x := FGlyphLeftMargin;

             If FGlyphTopPadding < -1 then tmp_y := Abs(FGlyphTopPadding)
             else tmp_y := mem.Height div 2 - FGlyphSize div 2;
            End;

            mem.Canvas.Draw(tmp_x, tmp_y, FImageCollection.Images[Index].SourceImages.Items[BestIndex].Image);
          end;
        end;
      end;

      FGlyphSize := iVal;
     end;




     if (Self.Caption <> '') and (FTextDrawEnabled) then
     begin
      mem.Canvas.Font.Assign(Self.Font);
      Self.DrawTextDo(mem.Canvas, trt, Self.Caption);
     End;


     if (FDrawSymbolSize > 0) and (FGlyphSize = 0) then
     begin



       sfact := Round(trt.Width - FDrawSymbolSize);
       if sfact < 1 then sfact := 1;
       if sfact > trt.Width*0.8 then sfact := Round(trt.Width*0.8);

      if (Self.FocusSymbolColor <> Self.DrawSymbolColor) and
         (FMouseInside) and
         (FocusColorEnabled) then Pen.Color := Self.FocusSymbolColor
       else Pen.Color := Self.DrawSymbolColor;

       Pen.Width := 1;

       // ** Draw symbol: x
       if Self.DrawSymbol = dsClose then
       begin
        sfact := Round(FDrawSymbolSize * 0.6);
        if sfact < 1 then sfact := 1;
        if sfact mod 2 <> 0 then sfact := sfact+1; // Ensures a perfectly balanced X

        start_x := trt.Left + trt.Width  div 2 - sfact div 2;
        start_y := trt.Top  + trt.Height div 2 - sfact div 2;
        end_x   := start_x + sfact;
        end_y   := start_y + sfact;

        MoveTo(start_x, start_y);
        LineTo(end_x+1, end_y+1);
        MoveTo(start_x, end_y);
        LineTo(end_x+1, start_y-1);
       end else

       // ** Draw symbol: _
       if Self.DrawSymbol = dsMinimize then
       begin
        sfact := Round(FDrawSymbolSize * 0.5);
        start_x := trt.Left + (trt.Width div 2) - (sfact div 2);
        start_y := trt.Top  + Round(trt.Height * 0.75) - 2;
        end_x   := trt.Left + (trt.Width div 2) + (sfact div 2);
        end_y   := start_y;
        MoveTo(start_x, start_y);
        LineTo(end_x, end_y);
       end else

       // ** Draw symbol: =
       if Self.DrawSymbol = dsMenuBoxLeft then
       begin
        sfact := Round(FDrawSymbolSize * 0.2);
        if sfact*2+16 > trt.Width then sfact := Round((trt.Width / 3) -16);
        if sfact < 4 then sfact := 4;

        start_x := trt.Left + sfact*2;
        start_y := trt.Top  + (trt.Height div 2) - ((sfact*2) div 2);
        end_x   := start_x + Round(sfact * 4.1) +3;

        MoveTo(start_x+3, start_y);
        LineTo(end_x-3, start_y);

        MoveTo(start_x+3, start_y+sfact);
        LineTo(end_x-3, start_y+sfact);

        MoveTo(start_x+3, start_y+sfact*2);
        LineTo(end_x-3, start_y+sfact*2);
       end else


       // ** Draw symbol: = (to the right)
       if Self.DrawSymbol = dsMenuBoxRight then
       begin
        start_x := trt.Left + trt.Width - 8 -12;
        start_y := trt.Top  + (trt.Height div 2) - (16 div 2);
        end_x   := start_x + FDrawSymbolSize;

        MoveTo(start_x+3, start_y+4);
        LineTo(end_x-3, start_y+4);

        MoveTo(start_x+3, start_y+8);
        LineTo(end_x-3, start_y+8);

        MoveTo(start_x+3, start_y+12);
        LineTo(end_x-3, start_y+12);
       end else

       // ** Draw symbol: []
       if Self.DrawSymbol = dsMaximize then
       begin
        start_x := trt.Left + sfact;
        start_y := trt.Top  + sfact;
        end_x   := trt.Left + trt.Width - sfact;
        end_y   := start_y;

        MoveTo(start_x, start_y);
        LineTo(end_x, end_y);
        LineTo(end_x, trt.Top + trt.Height - sfact +1);

        MoveTo(start_x, start_y);
        LineTo(start_x, trt.Top + trt.Height - sfact);
        LineTo(end_x, trt.Top + trt.Height - sfact);
       end else

       // ** Draw symbol: [][]
       if Self.DrawSymbol = dsUnMaximize then
       begin
        start_x := trt.Left + sfact;
        start_y := trt.Top  + sfact;
        end_x   := trt.Left + trt.Width - sfact;
        end_y   := start_y;

        MoveTo(start_x, start_y);
        LineTo(end_x, end_y);
        LineTo(end_x, trt.Top + trt.Height - sfact +1);

        MoveTo(start_x, start_y);
        LineTo(start_x, trt.Top + trt.Height - sfact);
        LineTo(end_x, trt.Top + trt.Height - sfact);

        iVal := Round(sfact * 0.3);
        if iVal < 2 then iVal := 2;
        if iVal > 5 then iVal := 5;

        // Draw the partial second rectangle behind the first one:
        MoveTo(start_x+iVal, start_y);
        LineTo(start_x+iVal, start_y-iVal);
        LineTo(end_x+iVal, start_y-iVal);
        LineTo(end_x+iVal, trt.Top + trt.Height - sfact - iVal);
        LineTo(end_x, trt.Top + trt.Height - sfact - iVal);
       end else

       // ** Draw symbol: V
       if Self.DrawSymbol = dsTriangleDown then
       begin

        SetLength(points, 3);

        // Centered:
        if trt.Width < 65 then
        begin
         start_x := trt.Left + (trt.Width  div 2) - FDrawSymbolSize;
         start_y := trt.Top  + (trt.Height div 2);
        end else // to the right side:
        begin
         start_x := trt.Left + trt.Width - Round(FDrawSymbolSize*3.2) - LEFT_ALIGN_MARGIN;
         start_y := trt.Top  + (trt.Height div 2);
        end;

        points[0].X := start_x;
        points[0].Y := start_y - FDrawSymbolSize;
        points[1].X := start_x + FDrawSymbolSize*2;
        points[1].Y := start_y - FDrawSymbolSize;
        points[2].X := start_x + FDrawSymbolSize;
        points[2].Y := start_y + FDrawSymbolSize;

        Polygon(points);
        //FloodFill(points[0].X+1, points[0].Y, FDrawSymbolColor, fsSurface);
       end else

       // ** Draw symbol: V
       if Self.DrawSymbol = dsArrowDown then
       begin

        SetLength(points, 3);

        // Centered:
        if trt.Width < 65 then
        begin
         start_x := trt.Left + (trt.Width  div 2) - FDrawSymbolSize;
         start_y := trt.Top  + (trt.Height div 2);
        end else // to the right side:
        begin
         start_x := trt.Left + trt.Width - Round(FDrawSymbolSize*3.2) - LEFT_ALIGN_MARGIN;
         start_y := trt.Top  + (trt.Height div 2);
        end;

        points[0].X := start_x +1;
        points[0].Y := start_y - FDrawSymbolSize+1;
        points[1].X := start_x + FDrawSymbolSize;
        points[1].Y := start_y + FDrawSymbolSize;
        points[2].X := start_x + FDrawSymbolSize*2;
        points[2].Y := start_y - FDrawSymbolSize;

        Polyline(points);
       end else

       // ** Draw symbol: ^
       if Self.DrawSymbol = dsTriangleUp then
       begin

        SetLength(points, 3);

        // Centered:
        if trt.Width < 65 then
        begin
         start_x := trt.Left + (trt.Width  div 2) - FDrawSymbolSize;
         start_y := trt.Top  + (trt.Height div 2);
        end else // to the right side:
        begin
         start_x := trt.Left + trt.Width - Round(FDrawSymbolSize*3.2) - LEFT_ALIGN_MARGIN;
         start_y := trt.Top  + (trt.Height div 2);
        end;

        points[0].X := start_x;
        points[0].Y := start_y + FDrawSymbolSize;
        points[1].X := start_x + FDrawSymbolSize*2;
        points[1].Y := start_y + FDrawSymbolSize;
        points[2].X := start_x + FDrawSymbolSize;
        points[2].Y := start_y - FDrawSymbolSize;

        Polygon(points);
        //FloodFill(points[0].X+1, points[0].Y, FDrawSymbolColor, fsSurface);
       end else

       // ** Draw symbol: ^
       if Self.DrawSymbol = dsArrowUp then
       begin

        SetLength(points, 3);

        // Centered:
        if trt.Width < 65 then
        begin
         start_x := trt.Left + (trt.Width  div 2) - FDrawSymbolSize;
         start_y := trt.Top  + (trt.Height div 2);
        end else // to the right side:
        begin
         start_x := trt.Left + trt.Width - Round(FDrawSymbolSize*3.2) - LEFT_ALIGN_MARGIN;
         start_y := trt.Top  + (trt.Height div 2);
        end;

        points[0].X := start_x;
        points[0].Y := start_y + FDrawSymbolSize;
        points[1].X := start_x + FDrawSymbolSize;
        points[1].Y := start_y - FDrawSymbolSize;
        points[2].X := start_x + FDrawSymbolSize*2 +1;
        points[2].Y := start_y + FDrawSymbolSize  +1;

        Polyline(points);
       end;
     End;



     // *********************************
     // ** Draw borders *****************
     // *********************************


      if (FFocusBorderColor <> FBorderColor) and
         (FMouseInside) and
         (FocusColorEnabled) then Pen.Color := Self.FocusBorderColor
      else Pen.Color := Self.BorderColor;


     Pen.Width := 1;

     // ** Draw top border
     if FBorderTop and (fBorderWidth > 0) then
     begin
      // Start point: Top Left
      if FBorderWithMargins then
      begin
       start_x := Self.Margins.Left;
       start_y := Self.Margins.Top;
      end else
      begin
       start_x := 0;
       start_y := 0
      end;

      // End point: Top right
      if FBorderWithMargins then
      begin
       end_x := trt.Width - Self.Margins.Right -1;
      end else
      begin
       end_x := trt.Width;
      end;
      end_y := start_y + Self.BorderWidth;

      //draw
      for iCount := start_y to end_y-1 do begin
        MoveTo(start_x, iCount);
        LineTo(end_x, iCount);
      end;

     end;

     // ** Draw left border
     if FBorderLeft and (fBorderWidth > 0) then
     begin
      // Start point: Top Left
      if FBorderWithMargins then
      begin
       start_x := Self.Margins.Left;
       start_y := Self.Margins.Top;
      end else
      begin
       start_x := 0;
       start_y := 0
      end;

      // End point: bottom left
      if FBorderWithMargins then
      begin
       end_y := trt.Height - Self.Margins.Bottom -1;
      end else
      begin
       end_y := trt.Height;
      end;
      end_x := start_x + Self.BorderWidth;

      //draw
      for iCount := start_x to end_x-1 do begin
        MoveTo(iCount, start_y);
        LineTo(iCount, end_y);
      end;

     end;

     // ** Draw bottom border
     if FBorderBottom and (FBorderWidth > 0) then
     begin
      // Start point: bottom Left
      if FBorderWithMargins then
      begin
       start_x := Self.Margins.Left;
       start_y := trt.Height - Margins.Bottom - 1;
      end else
      begin
       start_x := 0;
       start_y := trt.Height - 1;
      end;

      // End point: bottom right
      if FBorderWithMargins then
      begin
       end_x := trt.Width - Self.Margins.Right -1;
      end else
      begin
       end_x := trt.Width;
      end;
      end_y := start_y - Self.BorderWidth;

      //draw
      for iCount := start_y downto end_y+1 do begin
        MoveTo(start_x, iCount);
        LineTo(end_x, iCount);
      end;

     end;

     // ** Draw right border
     if FBorderRight and (fBorderWidth > 0) then
     begin
      // Start point: Top right
      if FBorderWithMargins then
      begin
       start_x := trt.Width - Self.Margins.Right -1;
       start_y := Self.Margins.Top;
      end else
      begin
       start_x := trt.Width - 1;
       start_y := 0
      end;

      // End point: bottom right
      if FBorderWithMargins then
      begin
       end_y := trt.Height - Margins.Bottom - 1;
      end else
      begin
       end_y := trt.Height - 1;
      end;
      end_x := start_x - Self.BorderWidth;

      //draw
      for iCount := start_x downto end_x+1 do begin
        MoveTo(iCount, start_y);
        LineTo(iCount, end_y);
      end;

     end;

    end;

    // Copy memoryBitmap to screen
    Canvas.CopyRect(ClientRect, mem.Canvas, ClientRect);

  finally
    FreeAndNil(mem); // delete the bitmap
  end;

end;

end.
