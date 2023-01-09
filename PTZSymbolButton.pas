unit PTZSymbolButton;

{$R-,T-,X+,H+,B-,O+,Q-}

interface

{.$DEFINE Debug_ExplicitMadExceptUse}

uses
  {$IFDEF Debug_ExplicitMadExceptUse} madExcept, {$ENDIF}
  System.SysUtils, System.Classes, Vcl.Controls, Vcl.StdCtrls,
  Vcl.ExtCtrls, Vcl.Graphics, Winapi.Messages, Winapi.Windows, Math;

type
  TPTZSymbol = (ptzRestore, ptzMaximize, ptzMinimize, ptzClose);

  TPTZSymbolButton = class(TCustomControl)
  private
    FFadeStep: Integer;
    FDirection: Integer;
    FMouseDown: Boolean;
    FTimer: TTimer;
    FLastMouseEvent: UInt64;

    { Private declarations }
    FFadeInSteps: Integer;
    FFadeInStepDelay: Integer;
    FFadeOutSteps: Integer;
    FFadeOutStepDelay: Integer;
    FClickSteps: Integer;
    FClickStepDelay: Integer;
    FBorderWidth: Integer;
    FColor: TColor;
    FBorderColor: TColor;
    FFocusBorderColor: TColor;
    FFocusColor: TColor;
    FSymbolColor: TColor;
    FSymbolFocusColor: TColor;
    FClickBorderColor: TColor;
    FClickColor: TColor;
    FSymbol: TPTZSymbol;
    FSymbolSize: Integer;
    FCurrentColor: TColor; // the currently drawn background color

    procedure SetColor(NewColor: TColor);
    procedure SetFocusColor(NewColor: TColor);
    procedure SetBorderColor(NewColor: TColor);
    procedure SetFocusBorderColor(NewColor: TColor);
    procedure SetSymbolColor(NewColor: TColor);
    procedure SetFocusSymbolColor(NewColor: TColor);
    procedure SetClickBorderColor(NewColor: TColor);
    procedure SetClickColor(NewColor: TColor);
    procedure SetBorderWidth(NewWidth: Integer);
    procedure SetSymbol(NewSymbol: TPTZSymbol);
    procedure SetSymbolSize(NewSymbolSize: Integer);
  protected
    procedure OnTimer(Sender: TObject);
    { Protected declarations }
    procedure WMEraseBkGnd(var Message: TMessage); message WM_ERASEBKGND;
    procedure CMMouseLeave(var Message: TMessage); message CM_MOUSELEAVE;
    procedure CMMouseEnter(var Message: TMessage); message CM_MOUSEENTER;
    procedure WMLButtonDown(var Message: TWMLButtonDown); message WM_LBUTTONDOWN;
    procedure WMLButtonUp(var Message: TWMLButtonUp); message WM_LBUTTONUP;
    procedure Paint; override;
  public
    { Public declarations }
    constructor Create(AOwner: TComponent); override;
    destructor Free;
  published
    { Published declarations }

    property Align;
    property OnClick;
    property Visible;
    property OnMouseMove;

    property FadeInSteps: Integer read FFadeInSteps write FFadeInSteps;
    property FadeInStepDelay: Integer read FFadeInStepDelay write FFadeInStepDelay;
    property FadeOutSteps: Integer read FFadeOutSteps write FFadeOutSteps;
    property FadeOutStepDelay: Integer read FFadeOutStepDelay write FFadeOutStepDelay;
    property ClickSteps: Integer read FClickSteps write FClickSteps;
    property ClickStepDelay: Integer read FClickStepDelay write FClickStepDelay;
    property BorderWidth: Integer read FBorderWidth write SetBorderWidth;
    property CurrentColor: TColor read FCurrentColor;

    property Color: TColor read FColor write SetColor;
    property FocusColor: TColor read FFocusColor write SetFocusColor;
    property BorderColor: TColor read FBorderColor write SetBorderColor;
    property FocusBorderColor: TColor read FFocusBorderColor write SetFocusBorderColor;
    property SymbolColor: TColor read FSymbolColor write SetSymbolColor;
    property SymbolFocusColor: TColor read FSymbolFocusColor write SetFocusSymbolColor;

    property ClickBorderColor: TColor read FClickBorderColor write SetClickBorderColor;
    property ClickColor: TColor read FClickColor write SetClickColor;
    property Symbol: TPTZSymbol read FSymbol write SetSymbol;
    property SymbolSize: Integer read FSymbolSize write SetSymbolSize;
  end;

procedure Register;

implementation


// Allows drawing of fading in colors, for example from white to grays to black
// Note: Indexing starts at zero!
function CalculateFadeinColor(StartColor, EndColor : TColor; CurrentStep, FinalStep : Integer) : TColor;
var
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
begin
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
end;


constructor TPTZSymbolButton.Create(AOwner: TComponent);
begin
  inherited;
  FFadeInSteps := 10;
  FFadeInStepDelay := 25;
  FFadeOutSteps := 10;
  FFadeOutStepDelay := 25;
  FClickSteps := 10;
  FClickStepDelay := 25;

  FCurrentColor := Self.Color;
  FLastMouseEvent := 0;
  FDirection := 1;
  FFadeStep := 0;
  FTimer := nil;
  FMouseDown := False;
  FSymbolSize := 8;
  FSymbol := ptzClose;
end;

destructor TPTZSymbolButton.Free;
begin
  if FTimer <> nil then
  begin
    FTimer.Free;
  end;
end;

procedure TPTZSymbolButton.WMEraseBkGnd(var Message: TMessage);
begin
  Message.Result := 1;
end;

procedure TPTZSymbolButton.OnTimer(Sender: TObject);
begin

  if FDirection = 1 then
  begin
    if FFadeStep < FFadeInSteps then
    begin
      FFadeStep := FFadeStep + 1;
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
      Invalidate;
    end
    else
    begin
      FTimer.Free;
      FTimer := nil;
    end;
  end;

end;

procedure TPTZSymbolButton.SetColor(NewColor: TColor);
begin
  if NewColor <> FColor then
  begin
    FColor := NewColor;
  end;
end;

procedure TPTZSymbolButton.SetBorderColor(NewColor: TColor);
begin
  if NewColor <> FBorderColor then
  begin
    FBorderColor := NewColor;
  end;
end;

procedure TPTZSymbolButton.SetFocusBorderColor(NewColor: TColor);
begin
  if NewColor <> FFocusBorderColor then
  begin
    FFocusBorderColor := NewColor;
  end;
end;

procedure TPTZSymbolButton.SetFocusColor(NewColor: TColor);
begin
  if NewColor <> FFocusColor then
  begin
    FFocusColor := NewColor;
  end;
end;

procedure TPTZSymbolButton.SetClickBorderColor(NewColor: TColor);
begin
  if NewColor <> FClickBorderColor then
  begin
    FClickBorderColor := NewColor;
  end;
end;

procedure TPTZSymbolButton.SetClickColor(NewColor: TColor);
begin
  if NewColor <> FClickColor then
  begin
    FClickColor := NewColor;
  end;
end;

procedure TPTZSymbolButton.SetSymbolColor(NewColor: TColor);
begin
  if NewColor <> FSymbolColor then
  begin
    FSymbolColor := NewColor;
  end;
end;

procedure TPTZSymbolButton.SetFocusSymbolColor(NewColor: TColor);
begin
  if NewColor <> FSymbolFocusColor then
  begin
    FSymbolFocusColor := NewColor;
  end;
end;

procedure TPTZSymbolButton.SetBorderWidth(NewWidth: Integer);
begin
  if NewWidth <> FBorderWidth then
  begin
    FBorderWidth := NewWidth;
    Invalidate;
  end;
end;

procedure TPTZSymbolButton.SetSymbol(NewSymbol: TPTZSymbol);
begin
  if NewSymbol <> FSymbol then
  begin
    FSymbol := NewSymbol;
    Invalidate;
  end;
end;

procedure TPTZSymbolButton.SetSymbolSize(NewSymbolSize: Integer);
begin
  if NewSymbolSize <> FSymbolSize then
  begin
    FSymbolSize := NewSymbolSize;
    Invalidate;
  end;
end;

procedure TPTZSymbolButton.Paint;
var
  BufferBitmap: Vcl.Graphics.TBitmap;
  ForeColor: TColor;
  BorderColor: TColor;
  SymbolColor: TColor;
  EntireRect: TRect;
  Shift: Integer;
begin

  BufferBitmap := Vcl.Graphics.TBitmap.Create();
  BufferBitmap.Width := Width;
  BufferBitmap.Height := Height;

  ForeColor   := FColor; // anti hint
  BorderColor := FBorderColor;
  SymbolColor := FSymbolColor;

  // hack fix:
  If (FDirection <> 1) and ((FLastMouseEvent < 10) or (GetTickCount64() - FLastMouseEvent > 1000)) then FDirection := 0;

  if FDirection = 1 then
  begin
    ForeColor := CalculateFadeinColor(FColor, FFocusColor, FFadeStep, FFadeInSteps);
    BorderColor := CalculateFadeinColor(FBorderColor, FFocusBorderColor, FFadeStep, FFadeInSteps);
    SymbolColor := CalculateFadeinColor(FSymbolColor, FSymbolFocusColor, FFadeStep, FFadeInSteps);
  end
  else if FDirection = 2 then
  begin
    ForeColor := CalculateFadeinColor(FFocusColor, FClickColor, FFadeStep, FClickSteps);
    BorderColor := CalculateFadeinColor(FFocusBorderColor, FClickBorderColor, FFadeStep, FClickSteps);
    SymbolColor := FSymbolFocusColor;
  end
  else if FDirection = -1 then
  begin
    ForeColor := CalculateFadeinColor(FFocusColor, FColor, FFadeStep, FFadeOutSteps);
    BorderColor := CalculateFadeinColor(FFocusBorderColor, FBorderColor, FFadeStep, FFadeOutSteps);
    SymbolColor := CalculateFadeinColor(FSymbolFocusColor, FSymbolColor, FFadeStep, FFadeOutSteps);
  end
  else if FDirection = -2 then
  begin
    ForeColor := CalculateFadeinColor(FClickColor, FFocusColor, FFadeStep, FClickSteps);
    BorderColor := CalculateFadeinColor(FClickBorderColor, FFocusBorderColor, FFadeStep, FClickSteps);
    SymbolColor := FSymbolFocusColor;
  end
  else if FDirection = -10 then
  begin
    ForeColor := CalculateFadeinColor(FColor, FClickColor, FFadeStep, FClickSteps);
    BorderColor := CalculateFadeinColor(FBorderColor, FClickBorderColor, FFadeStep, FClickSteps);
    SymbolColor := CalculateFadeinColor(FSymbolFocusColor, FSymbolColor, FFadeStep, FClickSteps);
  end;

  FCurrentColor := ForeColor;
  EntireRect.Left := 0;
  EntireRect.Top := 0;
  EntireRect.Width := Width;
  EntireRect.Height := Height;
  BufferBitmap.Canvas.Brush.Color := BorderColor;
  BufferBitmap.Canvas.FillRect(EntireRect);

  EntireRect.Left := BorderWidth;
  EntireRect.Top := BorderWidth;
  EntireRect.Width := Width - 2 * BorderWidth;
  EntireRect.Height := Height - 2 * BorderWidth;
  BufferBitmap.Canvas.Brush.Color := ForeColor;
  BufferBitmap.Canvas.FillRect(EntireRect);
  BufferBitmap.Canvas.Pen.Color := SymbolColor;

  EntireRect.Left := (Width - FSymbolSize) div 2;
  EntireRect.Top := (Height - FSymbolSize) div 2;
  EntireRect.Width := FSymbolSize;
  EntireRect.Height := FSymbolSize;

  if FSymbol = ptzClose then
  begin
    BufferBitmap.Canvas.MoveTo(EntireRect.Left, EntireRect.Top);
    BufferBitmap.Canvas.LineTo(EntireRect.Right + 1, EntireRect.Bottom + 1);
    BufferBitmap.Canvas.MoveTo(EntireRect.Left, EntireRect.Bottom);
    BufferBitmap.Canvas.LineTo(EntireRect.Right + 1, EntireRect.Top - 1);
  end
  else if FSymbol = ptzMinimize then
  begin
    BufferBitmap.Canvas.MoveTo(EntireRect.Left, EntireRect.Bottom);
    BufferBitmap.Canvas.LineTo(EntireRect.Right + 1, EntireRect.Bottom);
  end
  else if FSymbol = ptzMaximize then
  begin
    BufferBitmap.Canvas.MoveTo(EntireRect.Left, EntireRect.Bottom);
    BufferBitmap.Canvas.LineTo(EntireRect.Right + 1, EntireRect.Bottom);
    BufferBitmap.Canvas.LineTo(EntireRect.Right + 1, EntireRect.Top);
    BufferBitmap.Canvas.LineTo(EntireRect.Left, EntireRect.Top);
    BufferBitmap.Canvas.LineTo(EntireRect.Left, EntireRect.Bottom);
  end
  else if FSymbol = ptzRestore then
  begin
    Shift := Max(2, FSymbolSize div 8);

    BufferBitmap.Canvas.MoveTo(EntireRect.Left, EntireRect.Bottom);
    BufferBitmap.Canvas.LineTo(EntireRect.Right - Shift + 1, EntireRect.Bottom);
    BufferBitmap.Canvas.LineTo(EntireRect.Right - Shift + 1, EntireRect.Top + Shift);
    BufferBitmap.Canvas.LineTo(EntireRect.Left, EntireRect.Top + Shift);
    BufferBitmap.Canvas.LineTo(EntireRect.Left, EntireRect.Bottom);

    BufferBitmap.Canvas.MoveTo(EntireRect.Left + Shift, EntireRect.Top + Shift);
    BufferBitmap.Canvas.LineTo(EntireRect.Left + Shift, EntireRect.Top);
    BufferBitmap.Canvas.LineTo(EntireRect.Right + 1, EntireRect.Top);
    BufferBitmap.Canvas.LineTo(EntireRect.Right + 1, EntireRect.Bottom - Shift);
    BufferBitmap.Canvas.LineTo(EntireRect.Right - Shift + 1, EntireRect.Bottom - Shift);
  end;

  Canvas.Draw(0, 0, BufferBitmap);

  BufferBitmap.Free;

end;

procedure TPTZSymbolButton.CMMouseEnter(var Message: TMessage);
begin
  inherited;

  if FTimer <> nil then
  begin
    FTimer.Free;
  end;

  FLastMouseEvent := GetTickCount64();
  FDirection := 1;
  FFadeStep := 0;
  FTimer := TTimer.Create(Self);
  FTimer.Interval := FFadeInStepDelay;
  FTimer.OnTimer := OnTimer;
end;

procedure TPTZSymbolButton.CMMouseLeave(var Message: TMessage);
begin
  inherited;

  if FTimer <> nil then
  begin
    FTimer.Free;
  end;

  if FMouseDown then
    FDirection := -10
  else
    FDirection := -1;

  FFadeStep := 0;

  FTimer := TTimer.Create(Self);
  FTimer.Interval := FFadeOutStepDelay;
  FTimer.OnTimer := OnTimer;
  FMouseDown := False;
end;

procedure TPTZSymbolButton.WMLButtonDown(var Message: TWMLButtonDown);
begin
  inherited;

  FMouseDown := True;
  if FTimer <> nil then
  begin
    FTimer.Free;
  end;

  FLastMouseEvent := GetTickCount64();
  FDirection := 2;
  FFadeStep := 0;

  FTimer := TTimer.Create(Self);
  FTimer.Interval := FClickSteps;
  FTimer.OnTimer := OnTimer;
end;

procedure TPTZSymbolButton.WMLButtonUp(var Message: TWMLButtonUp);
begin
  inherited;

  FMouseDown := False;
  if FTimer <> nil then
  begin
    FTimer.Free;
  end;

  FLastMouseEvent := GetTickCount64();
  FDirection := -2;
  FFadeStep := 0;

  FTimer := TTimer.Create(Self);
  FTimer.Interval := FClickSteps;
  FTimer.OnTimer := OnTimer;
end;

procedure Register;
begin
  RegisterComponents('Macecraft', [TPTZSymbolButton]);
end;

end.
