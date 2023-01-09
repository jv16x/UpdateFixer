unit PTZProgressBar;

{$R-,T-,X+,H+,B-,O+,Q-}

interface

uses
  madExcept, System.SysUtils, System.Classes, System.Contnrs,
    Vcl.Controls, Vcl.ExtCtrls, Vcl.Graphics, Winapi.Messages,
    Winapi.Windows, Winapi.GDIPAPI, Winapi.GDIPOBJ;

type
  TPTZProgressBar = class(TCustomPanel)
  private
    FBackColor : TColor;
    FValue     : Integer;
    FMinValue  : Integer;
    FMaxValue  : Integer;

    procedure SetBackColor(NewColor: TColor);
  protected
    procedure WMEraseBkGnd(var Message: TMessage); message WM_ERASEBKGND;
    procedure SetValue(NewValue: Integer);
    procedure Paint; override;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Free;

  published
    property Value    : Integer read FValue    write SetValue;
    property MaxValue : Integer read FMaxValue write FMaxValue;
    property MinValue : Integer read FMinValue write FMinValue;

    property BackgroundColor: TColor read FBackColor write SetBackColor;

    property Align;
  end;

procedure Register;

implementation


procedure Register;
begin
  RegisterComponents('Macecraft', [TPTZProgressBar]);
end;


constructor TPTZProgressBar.Create(AOwner: TComponent);
begin
  inherited;

  FBackColor := clBtnFace;
  FValue := 0;
  FMinValue := 0;
  FMaxValue := 100;
end;

destructor TPTZProgressBar.Free;
begin
end;

procedure TPTZProgressBar.SetBackColor(NewColor: TColor);
begin
  if FBackColor <> NewColor then
  begin
    FBackColor := NewColor;
    Invalidate;
  end;
end;

procedure TPTZProgressBar.WMEraseBkGnd(var Message: TMessage);
begin
  Message.Result := 1;
end;

procedure TPTZProgressBar.SetValue(NewValue: Integer);
begin
  if FValue <> NewValue then
  begin
    FValue := NewValue;
    if FValue < FMinValue then FValue := FMinValue;
    if FValue > FMaxValue then FValue := FMaxValue;
    Invalidate;
  end;
end;

procedure TPTZProgressBar.Paint;
var
  BufferBitmap: TGPBitmap;
  BmpGraphics: TGPGraphics;
  CanvasGraphics: TGPGraphics;
  BackgroundBrush: TGPBrush;
  ProgressBrush1: TGPLinearGradientBrush;
  ProgressBrush2: TGPLinearGradientBrush;
  P1, P2, P3: TGPPointF;
  Color1, Color2, Color3: TGPColor;
  Half: Single;
  CurVal : Single;
begin

  try
    BufferBitmap := TGPBitmap.Create(Width, Height, PixelFormat32bppARGB);
    CanvasGraphics := TGPGraphics.Create(Canvas.Handle);
    BmpGraphics := TGPGraphics.Create(BufferBitmap);

    BmpGraphics.SetPageUnit(UnitPixel);
    BackgroundBrush := TGPSolidBrush.Create(MakeColor(255, GetRValue(ColorToRGB(FBackColor)),GetGValue(ColorToRGB(FBackColor)),GetBValue(ColorToRGB(FBackColor))));
    BmpGraphics.FillRectangle(BackgroundBrush, 0, 0, Width, Height);

    //BmpGraphics.SetSmoothingMode(SmoothingModeHighQuality);
    //BmpGraphics.SetInterpolationMode(InterpolationModeHighQualityBicubic);

    CurVal := FValue;

    {
    if FMaxValue > 0 then
    begin
     if FValue < FMaxValue then CurVal := Round(FValue / FMaxValue * 100)
     else CurVal := 100;
    End else CurVal := 0;
        }
    P1.X := 0;
    P1.Y := Height / 2;
    P2.X := Width * CurVal / 200.0 + 1;
    P2.Y := Height / 2;
    P3.X := Width * CurVal / 100.0 + 2;
    P3.Y := Height / 2;
    Color1 := MakeColor(255, 16,75,160); // MakeColor(255,0,0,180);
    Color2 := MakeColor(255,255,20,100);
    Color3 := MakeColor(255,255,200,0);

    Half := Width * FValue / 200.0;
    ProgressBrush1 := TGPLinearGradientBrush.Create(P1, P2, Color1, Color2);
    P2.X := Width * FValue / 200.0 - 1;
    ProgressBrush2 := TGPLinearGradientBrush.Create(P2, P3, Color2, Color3);

    BmpGraphics.FillRectangle(ProgressBrush1, 0.0, 0.0, Half, Height);
    BmpGraphics.FillRectangle(ProgressBrush2, Half, 0.0, Half, Height);

    CanvasGraphics.DrawImage(BufferBitmap, 0, 0, Width, Height);

    CanvasGraphics.Free;
    BmpGraphics.Free;
    ProgressBrush1.Free;
    ProgressBrush2.Free;
    BackgroundBrush.Free;

    BufferBitmap.Free;
  finally
  end;

end;


end.
