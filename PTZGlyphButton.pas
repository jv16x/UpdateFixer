unit PTZGlyphButton;

{$R-,T-,X+,H+,B-,O+,Q-}

interface

{.$DEFINE Debug_ExplicitMadExceptUse}

uses
  {$IFDEF Debug_ExplicitMadExceptUse} madExcept, {$ENDIF}
  System.SysUtils, System.Classes, Vcl.Controls, Vcl.StdCtrls, Vcl.ExtCtrls,
  Vcl.Graphics, Winapi.Messages, Winapi.Windows, Winapi.GDIPAPI,
  Winapi.GDIPOBJ, Math, Vcl.ImageCollection;

Const
 TIMER_TIMEOUT = 100;

type
  TPTZGlyphButton = class(TCustomPanel)
  private
    FUpdateLock: Integer;
    FFadeStep: Integer;
    FDirection: Integer;
    FMouseDown: Boolean;
    FTimer: TTimer;
    FTimerStart : UInt64;
    FTimerLock : Boolean;
    FMouseEntered : Boolean;

    FFadeInSteps: Integer;
    FFadeInStepDelay: Integer;
    FFadeOutSteps: Integer;
    FFadeOutStepDelay: Integer;
    FClickSteps: Integer;
    FClickStepDelay: Integer;
    FBorderWidth: Integer;
    FBorderCornerRadius: Integer;
    FColor: TColor;
    FBorderColor: TColor;
    FFocusBorderColor: TColor;
    FFocusColor: TColor;
    FClickBorderColor: TColor;
    FClickColor: TColor;
    FBackgroundColor: TColor; // the color of the canvas under the button

    FLeftMarginGlyph : Integer;
    FLeftMarginText  : Integer;
    FTopMarginGlyph  : Integer;
    FTextAlignment : TAlignment ;

    FGlyphName : string;
    FGlyphSize : Integer;
    FGlyphForcedSize : Integer;
    FImageCollection: TImageCollection;
    FTagStr: String;
    FContentWidth : Integer;
    FGlyphCentered : Boolean;
    FDefaultButton : Boolean;
    FBorderWidthDef : Integer;

    procedure SetColor(NewColor: TColor);
    procedure SetBorderColor(NewColor: TColor);
    procedure SetFocusBorderColor(NewColor: TColor);
    procedure SetFocusColor(NewColor: TColor);
    procedure SetClickBorderColor(NewColor: TColor);
    procedure SetClickColor(NewColor: TColor);
    procedure SetBackgroundColor(NewColor: TColor);
    procedure SetBorderWidth(NewWidth: Integer);
    procedure SetDefaultButtonBorderWidth(NewWidth: Integer);
    procedure SetBorderCornerRadius(NewValue: Integer);

    procedure SetLeftMarginGlyph(NewValue: Integer);
    procedure SetLeftMarginText(NewValue: Integer);
    procedure SetTopMarginGlyph(NewValue: Integer);
    Procedure SetDefaultButton(NewValue : Boolean);

    procedure SetImageCollection(NewValue: TImageCollection);
    procedure SetGlyphName(NewValue: string);
    procedure SetGlyphForcedSize(NewValue: Integer);
    function GetContentWidth() : Integer;
  protected
    procedure OnTimer(Sender: TObject);

    procedure WMEraseBkGnd(var Message: TMessage); message WM_ERASEBKGND;
    procedure CMMouseLeave(var Message: TMessage); message CM_MOUSELEAVE;
    procedure CMMouseEnter(var Message: TMessage); message CM_MOUSEENTER;
    procedure WMLButtonDown(var Message: TWMLButtonDown); message WM_LBUTTONDOWN;
    procedure WMLButtonUp(var Message: TWMLButtonUp); message WM_LBUTTONUP;
    procedure Paint; override;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Free;

    procedure BeginUpdate();
    procedure EndUpdate();
    procedure CopySettingsFrom(const SrcBtn : TPTZGlyphButton);

    procedure UpdateWidth(ExtraMargin : Integer = 0);
  published
    property Caption;
    property Font;
    property AlignWithMargins;
    property Align;
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

    property Alignment: TAlignment  read FTextAlignment  write FTextAlignment;
    property DefaultButton: Boolean read FDefaultButton write SetDefaultButton;

    property FadeInSteps: Integer read FFadeInSteps write FFadeInSteps;
    property FadeInStepDelay: Integer read FFadeInStepDelay write FFadeInStepDelay;
    property FadeOutSteps: Integer read FFadeOutSteps write FFadeOutSteps;
    property FadeOutStepDelay: Integer read FFadeOutStepDelay write FFadeOutStepDelay;
    property ClickSteps: Integer read FClickSteps write FClickSteps;
    property ClickStepDelay: Integer read FClickStepDelay write FClickStepDelay;
    property BorderWidth: Integer read FBorderWidth write SetBorderWidth;
    property BorderWidthDefaultButton: Integer read FBorderWidthDef write SetDefaultButtonBorderWidth; // Border width if DefaultButton = True
    property BorderCornerRadius: Integer read FBorderCornerRadius write SetBorderCornerRadius;

    property LeftMarginGlyph: Integer read FLeftMarginGlyph write SetLeftMarginGlyph;
    property LeftMarginText: Integer read FLeftMarginText write SetLeftMarginText;
    property TopMarginGlyph: Integer read FTopMarginGlyph write SetTopMarginGlyph;

    property Color: TColor read FColor write SetColor;
    property BorderColor: TColor read FBorderColor write SetBorderColor;
    property FocusBorderColor: TColor read FFocusBorderColor write SetFocusBorderColor;
    property FocusColor: TColor read FFocusColor write SetFocusColor;
    property ClickBorderColor: TColor read FClickBorderColor write SetClickBorderColor;
    property ClickColor: TColor read FClickColor write SetClickColor;
    property BackgroundColor: TColor read FBackgroundColor write SetBackgroundColor;

    property ImageCollection: TImageCollection read FImageCollection write SetImageCollection;
    property GlyphName: string read FGlyphName write SetGlyphName;
    property GlyphSize: Integer read FGlyphSize;
    property GlyphForcedSize: Integer read FGlyphForcedSize write SetGlyphForcedSize;

    property ContentWidth: Integer read GetContentWidth;
    property GlyphCentered: Boolean read FGlyphCentered write FGlyphCentered;
    property TagStr: String read FTagStr write FTagStr;
  end;

procedure Register;

implementation


// Allows drawing of fading in colors, for example from white to grays to black
// Note: Indexing starts at zero!
Function CalculateFadeinColor(StartColor, EndColor : TColor; CurrentStep, FinalStep : Integer) : TColor;
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



constructor TPTZGlyphButton.Create(AOwner: TComponent);
begin
  inherited;
  FUpdateLock := 0;

  Self.BeginUpdate();

  Try
    Font.Name := 'Segoe UI';
    Self.ParentBackground := False;

    FDefaultButton    := False;
    FTextAlignment    := taLeftJustify;
    FFadeInSteps      := 0;
    FFadeInStepDelay  := 25;
    FFadeOutSteps     := 0;
    FFadeOutStepDelay := 25;
    FClickSteps       := 0;
    FClickStepDelay   := 25;

    FLeftMarginGlyph  := 10;
    FLeftMarginText   := 10;
    FTopMarginGlyph   := 0;
    FTagStr           := '';
    FContentWidth     := 0;
    FGlyphCentered    := False;

    FDirection  := 1;
    FFadeStep   := 0;
    FGlyphSize  := 0;
    FGlyphForcedSize := 0;

    FMouseEntered := False;
    FMouseDown  := False;

    FTimerLock  := False;
    FTimer      := nil;
    FTimerStart := 0;
  Finally
    Self.EndUpdate();
  End;

end;

destructor TPTZGlyphButton.Free;
begin
  if FTimer <> nil then
  begin
    FTimer.Free;
    FTimer := nil;
  end;
end;

procedure TPTZGlyphButton.WMEraseBkGnd(var Message: TMessage);
begin
  Message.Result := 1;
end;


procedure TPTZGlyphButton.CopySettingsFrom(const SrcBtn : TPTZGlyphButton);
begin

 Self.BeginUpdate();

 Self.FBorderWidth        := SrcBtn.BorderWidth;
 Self.FBorderWidthDef     := SrcBtn.FBorderWidthDef;
 Self.FBorderColor        := SrcBtn.BorderColor;
 Self.FBorderCornerRadius := SrcBtn.BorderCornerRadius;

 Self.FClickSteps       := SrcBtn.ClickSteps;
 Self.FClickStepDelay   := SrcBtn.ClickStepDelay;
 Self.FClickBorderColor := SrcBtn.ClickBorderColor;
 Self.FClickColor       := SrcBtn.FClickColor;
 Self.FColor            := SrcBtn.FColor;
 Self.FBackgroundColor  := SrcBtn.BackgroundColor;
 Self.FocusColor        := SrcBtn.FocusColor;
 Self.FocusBorderColor  := SrcBtn.FocusBorderColor;
 Self.FFadeInSteps      := SrcBtn.FFadeInSteps;
 Self.FFadeInStepDelay  := SrcBtn.FFadeInStepDelay;
 Self.FFadeOutSteps     := SrcBtn.FFadeOutSteps;
 Self.FFadeOutStepDelay := SrcBtn.FFadeOutStepDelay;
 Self.FLeftMarginGlyph  := SrcBtn.FLeftMarginGlyph;
 Self.FLeftMarginText   := SrcBtn.FLeftMarginText;
 Self.FTextAlignment    := SrcBtn.FTextAlignment;

 Self.AlignWithMargins  := SrcBtn.AlignWithMargins;
 Self.Margins.Left      := SrcBtn.Margins.Left;
 Self.Margins.Right     := SrcBtn.Margins.Right;
 Self.Margins.Top       := SrcBtn.Margins.Top;
 Self.Margins.Bottom    := SrcBtn.Margins.Bottom;

 Self.Font.Assign(SrcBtn.Font);
 Self.EndUpdate();

end;

procedure TPTZGlyphButton.BeginUpdate;
Begin
 Inc(FUpdateLock);
End;

procedure TPTZGlyphButton.EndUpdate;
Begin
 Dec(FUpdateLock);

 if FUpdateLock <= 0 then
 begin
  FUpdateLock := 0;
  Self.Invalidate;
  Self.Refresh;
 end;
End;


procedure TPTZGlyphButton.OnTimer(Sender: TObject);
Var
 Runtime : Integer;
begin

 if FTimerLock then EXIT;
 FTimerLock := True;

 Try

    Runtime := GetTickCount64() - FTimerStart;

    if FDirection = 1 then
    begin
      if FFadeStep < FFadeInSteps then
      begin
        FFadeStep := FFadeStep + 1;
        if (Runtime > TIMER_TIMEOUT) or (Runtime > FFadeInSteps*FFadeInStepDelay) then FFadeStep := FFadeInSteps;
        Invalidate;
      end
      else
      begin
        FTimer.Free;
        FTimer := nil;
      end;
    end
    else if FDirection = 2 then
    begin
      if FFadeStep < FClickSteps then
      begin
        FFadeStep := FFadeStep + 1;
        if (Runtime > TIMER_TIMEOUT) or (Runtime > FClickSteps*FClickStepDelay) then FFadeStep := FClickSteps;
        Invalidate;
      end
      else
      begin
        FTimer.Free;
        FTimer := nil;
      end;
    end
    else if FDirection = -1 then
    begin
      if FFadeStep < FFadeOutSteps then
      begin
        FFadeStep := FFadeStep + 1;
        if (Runtime > TIMER_TIMEOUT) or (Runtime > FFadeOutSteps*FFadeOutStepDelay) then FFadeStep := FFadeOutSteps;
        Invalidate;
      end
      else
      begin
        FTimer.Free;
        FTimer := nil;
      end;
    end
    else if FDirection = -2 then
    begin
      if FFadeStep < FClickSteps then
      begin
        FFadeStep := FFadeStep + 1;
        if (Runtime > TIMER_TIMEOUT) or (Runtime > FClickSteps*FClickStepDelay) then FFadeStep := FClickSteps;
        Invalidate;
      end
      else
      begin
        FTimer.Free;
        FTimer := nil;
      end;
    end;
 Finally
   FTimerLock := False;
 End;

end;

procedure TPTZGlyphButton.SetColor(NewColor: TColor);
begin
  if NewColor <> FColor then
  begin
    FColor := NewColor;
    If Self.FUpdateLock = 0 then Self.Invalidate;
  end;
end;

procedure TPTZGlyphButton.SetBorderColor(NewColor: TColor);
begin
  if NewColor <> FBorderColor then
  begin
    FBorderColor := NewColor;
    If Self.FUpdateLock = 0 then Self.Invalidate;
  end;
end;

procedure TPTZGlyphButton.SetFocusBorderColor(NewColor: TColor);
begin
  if NewColor <> FFocusBorderColor then
  begin
    FFocusBorderColor := NewColor;
    If Self.FUpdateLock = 0 then Self.Invalidate;
  end;
end;

procedure TPTZGlyphButton.SetFocusColor(NewColor: TColor);
begin
  if NewColor <> FFocusColor then
  begin
    FFocusColor := NewColor;
    If Self.FUpdateLock = 0 then Self.Invalidate;
  end;
end;

procedure TPTZGlyphButton.SetClickBorderColor(NewColor: TColor);
begin
  if NewColor <> FClickBorderColor then
  begin
    FClickBorderColor := NewColor;
    If Self.FUpdateLock = 0 then Self.Invalidate;
  end;
end;

procedure TPTZGlyphButton.SetClickColor(NewColor: TColor);
begin
  if NewColor <> FClickColor then
  begin
    FClickColor := NewColor;
    If Self.FUpdateLock = 0 then Self.Invalidate;
  end;
end;

procedure TPTZGlyphButton.SetBackgroundColor(NewColor: TColor);
begin
  if NewColor <> FBackgroundColor then
  begin
    FBackgroundColor := NewColor;
    If Self.FUpdateLock = 0 then Self.Invalidate;
  end;
end;

Procedure TPTZGlyphButton.SetDefaultButton(NewValue : Boolean);
Begin
 if NewValue <> FDefaultButton then
 begin
  FDefaultButton := NewValue;
  If Self.FUpdateLock = 0 then Self.Invalidate;
 end;
End;

procedure TPTZGlyphButton.SetBorderWidth(NewWidth: Integer);
begin
  if NewWidth <> FBorderWidth then
  begin
    FBorderWidth := NewWidth;
    If Self.FUpdateLock = 0 then Self.Invalidate;
  end;
end;

procedure TPTZGlyphButton.SetBorderCornerRadius(NewValue: Integer);
begin
  if NewValue <> FBorderCornerRadius then
  begin
    FBorderCornerRadius := NewValue;
    If Self.FUpdateLock = 0 then Self.Invalidate;
  end;
end;

procedure TPTZGlyphButton.SetDefaultButtonBorderWidth(NewWidth: Integer);
begin
  if NewWidth <> FBorderWidthDef then
  begin
    FBorderWidthDef := NewWidth;
    If Self.FUpdateLock = 0 then Self.Invalidate;
  end;
end;


procedure TPTZGlyphButton.SetLeftMarginGlyph(NewValue: Integer);
begin
  if NewValue <> FLeftMarginGlyph then
  begin
    FLeftMarginGlyph := NewValue;
    If Self.FUpdateLock = 0 then Self.Invalidate;
  end;
end;

procedure TPTZGlyphButton.SetLeftMarginText(NewValue: Integer);
begin
  if NewValue <> FLeftMarginText then
  begin
    FLeftMarginText := NewValue;
    If Self.FUpdateLock = 0 then Self.Invalidate;
  end;
end;

procedure TPTZGlyphButton.SetTopMarginGlyph(NewValue: Integer);
begin
  if NewValue <> FTopMarginGlyph then
  begin
    FTopMarginGlyph := NewValue;
    If Self.FUpdateLock = 0 then Self.Invalidate;
  end;
end;

procedure TPTZGlyphButton.SetImageCollection(NewValue: TImageCollection);
begin
  FImageCollection := NewValue;
  If Self.FUpdateLock = 0 then Self.Invalidate;
end;



procedure TPTZGlyphButton.SetGlyphForcedSize(NewValue: Integer);
begin
  FGlyphForcedSize := NewValue;
  If Self.FUpdateLock = 0 then Self.Invalidate;
end;


procedure TPTZGlyphButton.SetGlyphName(NewValue: string);
begin
  FGlyphName := NewValue;
  If Self.FUpdateLock = 0 then Self.Invalidate;
end;

function TPTZGlyphButton.GetContentWidth() : Integer;
begin
 if (Self = nil) then EXIT(0);

 Result := FContentWidth;

 If Result <= 0 then
 begin
  Result := Length(Self.Caption) * 2 + (FLeftMarginGlyph + FGlyphSize + FLeftMarginText);
 end;

End;

procedure TPTZGlyphButton.UpdateWidth(ExtraMargin : Integer = 0);
Var
 iVal : Integer;
begin
 if (FContentWidth <= 0) and (Self.Constraints.MinWidth <= 0) then EXIT;

 iVal := Round(GetContentWidth() * 1.1);
 if Self.DefaultButton then iVal := Round(iVal * 1.2);
 iVal := iVal + ExtraMargin;

 if Self.BorderWidth > 1 then iVal := iVal + Self.BorderWidth * 3;

 if iVal < Self.Constraints.MinWidth then iVal := Self.Constraints.MinWidth;
 if (Self.Constraints.MaxWidth > 1) and (iVal > Self.Constraints.MaxWidth) then iVal := Self.Constraints.MaxWidth;

 if (iVal > 0) and (Abs(Self.Width - iVal) > 5) then
 begin
   Self.Width := iVal;
 end;

End;


procedure TPTZGlyphButton.Paint;
var
  BufferBitmap: Vcl.Graphics.TBitmap;
  ForeColor: TColor;
  BorderColor: TColor;
  EntireRect: TRect;
  TextX: Integer;
  TextY: Integer;
  BitmapSize: Integer;
  MaxGlyphWidth : Integer;
  MaxGlyphHeight : Integer;
  x, y, k, Index: Integer;
  iTextHeight : Integer;
  iTextWidth  : Integer;
  iBorderWidth : Integer;
  CurDelta   : Integer;
  BestDelta  : Integer;
  BestSubIdx : Integer;
begin

  if FUpdateLock > 0 then
  begin
   Inherited;
   EXIT;
  end;


  BufferBitmap := Vcl.Graphics.TBitmap.Create();
  BufferBitmap.Width := Width;
  BufferBitmap.Height := Height;

  ForeColor   := FColor; // anti hint
  BorderColor := FBorderColor;
  TextY := 0;

  if FDirection = 1 then
  begin
    ForeColor := CalculateFadeinColor(FColor, FFocusColor, FFadeStep, FFadeInSteps);
    BorderColor := CalculateFadeinColor(FBorderColor, FFocusBorderColor, FFadeStep, FFadeInSteps);
  end
  else if FDirection = 2 then
  begin
    ForeColor := CalculateFadeinColor(FFocusColor, FClickColor, FFadeStep, FClickSteps);
    BorderColor := CalculateFadeinColor(FFocusBorderColor, FClickBorderColor, FFadeStep, FClickSteps);
  end
  else if FDirection = -1 then
  begin
    ForeColor := CalculateFadeinColor(FFocusColor, FColor, FFadeStep, FFadeOutSteps);
    BorderColor := CalculateFadeinColor(FFocusBorderColor, FBorderColor, FFadeStep, FFadeOutSteps);
  end
  else if FDirection = -2 then
  begin
    ForeColor := CalculateFadeinColor(FClickColor, FFocusColor, FFadeStep, FClickSteps);
    BorderColor := CalculateFadeinColor(FClickBorderColor, FFocusBorderColor, FFadeStep, FClickSteps);
  end
  else if FDirection = -10 then
  begin
    ForeColor := CalculateFadeinColor(FColor, FClickColor, FFadeStep, FClickSteps);
    BorderColor := CalculateFadeinColor(FBorderColor, FClickBorderColor, FFadeStep, FClickSteps);
  end;

  EntireRect.Left := 0;
  EntireRect.Top  := 0;
  EntireRect.Width  := Width;
  EntireRect.Height := Height;

  if FDefaultButton then iBorderWidth := FBorderWidthDef else iBorderWidth := FBorderWidth;

  if iBorderWidth > 0 then BufferBitmap.Canvas.Brush.Color := BorderColor
  else BufferBitmap.Canvas.Brush.Color := ForeColor;

  BufferBitmap.Canvas.FillRect(EntireRect);

  if iBorderWidth > 0 then
  begin
    EntireRect.Left := iBorderWidth+1;
    EntireRect.Top  := iBorderWidth+1;

    EntireRect.Width  := Width  - 2 * iBorderWidth -2;
    EntireRect.Height := Height - 2 * iBorderWidth -2;
    BufferBitmap.Canvas.Brush.Color := ForeColor;
    BufferBitmap.Canvas.FillRect(EntireRect);
  end;

  BitmapSize := 0;

  if (ImageCollection<>nil) and (FGlyphName<>'') then
  begin
    Index := ImageCollection.GetIndexByName(FGlyphName);
    if Index >= 0 then
    begin
      MaxGlyphWidth  := ClientWidth  - FLeftMarginGlyph;
      MaxGlyphHeight := ClientHeight - FTopMarginGlyph*2;
      BestDelta := MAXINT;
      BestSubIdx := 0;

      for k := 0 to ImageCollection.Images[Index].SourceImages.Count-1 do
      begin
       if (FGlyphForcedSize > 0) and
          (ImageCollection.Images[Index].SourceImages.Items[k].Image.Width = FGlyphForcedSize) and
          (ImageCollection.Images[Index].SourceImages.Items[k].Image.Height = FGlyphForcedSize) then
       begin
        BestSubIdx := k;
        Break;
       end;

       if (ImageCollection.Images[Index].SourceImages.Items[k].Image.Width  <= MaxGlyphWidth) and
          (ImageCollection.Images[Index].SourceImages.Items[k].Image.Height <= MaxGlyphHeight) then
       begin
        CurDelta := Abs(ImageCollection.Images[Index].SourceImages.Items[k].Image.Width - MaxGlyphWidth) +
                    Abs(ImageCollection.Images[Index].SourceImages.Items[k].Image.Height - MaxGlyphHeight);
        if (k = 0) or (CurDelta < BestDelta) then
        begin
         BestSubIdx := k;
         BestDelta := CurDelta;
        end;
       end;
      end;

      {
      while k < ImageCollection.Images[Index].SourceImages.Count do
      begin
        if (ImageCollection.Images[Index].SourceImages.Items[k].Image.Width  >= DesiredWidth) and
           (ImageCollection.Images[Index].SourceImages.Items[k].Image.Height >= DesiredHeight) then
        begin
          Break;
        end;

        k := k + 1;
      end;
        }

      if (BestSubIdx >= 0) and (Index >= 0) and (Index <= ImageCollection.Count-1) and
         (BestSubIdx <= ImageCollection.Images[Index].SourceImages.Count-1) then
      begin
        y := (ClientHeight - ImageCollection.Images[Index].SourceImages.Items[BestSubIdx].Image.Height) div 2;

        if FGlyphCentered then x := (ClientWidth - ImageCollection.Images[Index].SourceImages.Items[BestSubIdx].Image.Width) div 2 else x := 0;
        x := x + FLeftMarginGlyph;

        BufferBitmap.Canvas.Draw(x, y, ImageCollection.Images[Index].SourceImages.Items[BestSubIdx].Image);
        BitmapSize := ImageCollection.Images[Index].SourceImages.Items[BestSubIdx].Image.Width;
      end;
    end;
  end;

  FGlyphSize := BitmapSize;

  If Caption <> '' then
  begin
   BufferBitmap.Canvas.Font.Assign(Font);

   iTextHeight := BufferBitmap.Canvas.TextHeight(Caption);
   iTextWidth  := BufferBitmap.Canvas.TextWidth(Caption);

   TextY := (Height - iTextHeight) div 2 -1;

   if FTextAlignment = taLeftJustify then
    TextX := FLeftMarginGlyph + BitmapSize + FLeftMarginText
   else if FTextAlignment = taCenter then
     TextX := (FLeftMarginGlyph + BitmapSize) + (BufferBitmap.Width div 2 - iTextWidth div 2)
   else TextX := BufferBitmap.Width - (iTextWidth + FLeftMarginText);

   if TextX < 0 then TextX := 0;

   BufferBitmap.Canvas.TextOut(TextX, TextY, Caption);
   FContentWidth := iTextWidth + (FLeftMarginGlyph + BitmapSize + FLeftMarginText) + (iTextHeight div 2);

  End else FContentWidth := FLeftMarginGlyph * 2 + BitmapSize;

  Canvas.Draw(0, 0, BufferBitmap);

  BufferBitmap.Free;
end;

procedure TPTZGlyphButton.CMMouseEnter(var Message: TMessage);
begin
  inherited;

  If (FFadeInSteps <= 0) or (FFocusColor = FColor) then EXIT;

  if FTimer <> nil then FTimer.Free;

  FMouseEntered := True;
  FTimerLock := False;
  FDirection := 1;
  FFadeStep := 0;

  FTimerStart := GetTickCount64();
  FTimer := TTimer.Create(Self);
  FTimer.Interval := FFadeInStepDelay;
  FTimer.OnTimer := OnTimer;
end;

procedure TPTZGlyphButton.CMMouseLeave(var Message: TMessage);
begin
  inherited;

  If (FFadeOutSteps <= 0) or (FFocusColor = FColor) then EXIT;
  if FMouseEntered = False then EXIT;
  FMouseEntered := False;

  if FTimer <> nil then FTimer.Free;

  if FMouseDown then
  begin
    FDirection := -10;
    FFadeStep := 0;
  end
  else
  begin
    FDirection := -1;
    FFadeStep := 0;
  end;

  FTimerStart := GetTickCount64();
  FTimer := TTimer.Create(Self);
  FTimer.Interval := FFadeOutStepDelay;
  FTimer.OnTimer := OnTimer;
  FMouseDown := False;
end;

procedure TPTZGlyphButton.WMLButtonDown(var Message: TWMLButtonDown);
begin
  inherited;

  FMouseDown := True;
  If (FClickSteps <= 0) or (FClickColor = FColor) then EXIT;
  FMouseEntered := True;

  if FTimer <> nil then FTimer.Free;
  FDirection := 2;
  FFadeStep := 0;

  FTimerStart := GetTickCount64();
  FTimer := TTimer.Create(Self);
  FTimer.Interval := FClickSteps;
  FTimer.OnTimer := OnTimer;
end;

procedure TPTZGlyphButton.WMLButtonUp(var Message: TWMLButtonUp);
begin
  inherited;

  FMouseDown := False;
  If (FClickSteps <= 0) or (FClickColor = FColor) then EXIT;

  if FTimer <> nil then FTimer.Free;
  FDirection := -2;
  FFadeStep := 0;

  FTimerStart := GetTickCount64();
  FTimer := TTimer.Create(Self);
  FTimer.Interval := FClickSteps;
  FTimer.OnTimer := OnTimer;
end;


procedure Register;
begin
  RegisterComponents('Macecraft', [TPTZGlyphButton]);
end;





end.
