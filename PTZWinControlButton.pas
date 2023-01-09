unit PTZWinControlButton;

{$R-,T-,X+,H+,B-,O+,Q-}

interface

uses
  System.Classes, System.UITypes, Winapi.Messages, Vcl.Controls, Vcl.Graphics,
  Vcl.ExtCtrls, GDIPAPI, GDIPOBJ;

const
  CFadeSteps = 4;

type
  TPTZWinControlButtonType = (btMinimize, btMaximize, btRestore, btClose);

  TPTZWinControlButton = class(TGraphicControl)
  private
    fIdlePaintColor: TColor;
    fHighlightedPaintColor: TColor;
    fActualDrawColor: TColor;
    fButtonType: TPTZWinControlButtonType;

    fBackgroundBrush: TGPBrush;
    fIsMouseInShape: Boolean;

    fFadePhase: Integer;
    fFadeTimer: TTimer;
    fFadeStep: Byte;

    fShapeSize: Integer;
    fShapeMarginTop: Integer;
    fShapeMarginLeft: Integer;

    procedure SetHighlightedPaintColor(const Value: TColor);
    procedure SetIdlePaintColor(const Value: TColor);
    procedure SetButtonType(const Value: TPTZWinControlButtonType);
    procedure SetShapeSize(const Value: Integer);
    procedure SetShapeMarginLeft(const Value: Integer);
    procedure SetShapeMarginTop(const Value: Integer);
  protected
    procedure Paint; override;
    procedure CMColorChanged(var Message: TMessage); message CM_COLORCHANGED;
    procedure CMMouseEnter(var Message: TMessage); message CM_MOUSEENTER;
    procedure CMMouseLeave(var Message: TMessage); message CM_MOUSELEAVE;

    procedure DoOnFadeTimer(Sender: TObject);
  public
    constructor Create(aOwner: TComponent); override;
    destructor Destroy; override;
  published
    property Color;
    property ShapeSize: Integer read fShapeSize write SetShapeSize default 14;
    property ShapeMarginLeft: Integer read fShapeMarginLeft write SetShapeMarginLeft default -1;
    property ShapeMarginTop: Integer read fShapeMarginTop write SetShapeMarginTop default -1;
    property SymbolColor: TColor read fIdlePaintColor write SetIdlePaintColor default $A8A8A8;
    property SymbolFocusColor: TColor read fHighlightedPaintColor write SetHighlightedPaintColor default clWhite;
    property ButtonType: TPTZWinControlButtonType read fButtonType write SetButtonType;
    property OnClick;
  end;

Procedure Register;


implementation

uses
  System.SysUtils, System.Math, Winapi.Windows;

{ TPTZWinControlButton }

procedure TPTZWinControlButton.CMColorChanged(var Message: TMessage);
begin
  FreeAndNil(fBackgroundBrush);
end;

procedure TPTZWinControlButton.CMMouseEnter(var Message: TMessage);
begin
  inherited;
  fFadeTimer.Enabled := True;
  fIsMouseInShape := True;
end;

procedure TPTZWinControlButton.CMMouseLeave(var Message: TMessage);
begin
  inherited;
  fFadeTimer.Enabled := True;
  fIsMouseInShape := False;
end;

constructor TPTZWinControlButton.Create(aOwner: TComponent);
begin
  inherited;
  fShapeSize := 14;
  fShapeMarginTop := -1;
  fShapeMarginLeft := -1;
  fFadePhase := 0;
  fFadeStep := 0;
  fIsMouseInShape := False;

  fIdlePaintColor := $A8A8A8;
  fActualDrawColor := fIdlePaintColor;
  fHighlightedPaintColor := clWhite;
  Color := clDkGray;

  fBackgroundBrush := nil;

  fFadeTimer := TTimer.Create(nil);
  fFadeTimer.Interval := 60;
  fFadeTimer.Enabled := False;
  fFadeTimer.OnTimer := DoOnFadeTimer;

  Width := 20;
  Height := 20;
end;

destructor TPTZWinControlButton.Destroy;
begin
  FreeAndNil(fBackgroundBrush);
  inherited;
end;

procedure TPTZWinControlButton.DoOnFadeTimer(Sender: TObject);
begin
  if fFadeStep = 0 then
  begin
    fFadeStep := Max(Max(
      GetRValue(fHighlightedPaintColor) - GetRValue(fIdlePaintColor),
      GetGValue(fHighlightedPaintColor) - GetGValue(fIdlePaintColor)),
      GetBValue(fHighlightedPaintColor) - GetBValue(fIdlePaintColor)
       ) div CFadeSteps;
  end;

  if fIsMouseInShape then
  begin
    Inc(fFadePhase);
    if fFadePhase >= CFadeSteps - 1 then
    begin
      fActualDrawColor := fHighlightedPaintColor;
      fFadeTimer.Enabled := False;
    end
    else
    begin
      fActualDrawColor := MakeColor(
        Min( GetRValue(fIdlePaintColor) + fFadePhase * fFadeStep, 255),
        Min( GetGValue(fIdlePaintColor) + fFadePhase * fFadeStep, 255),
        Min( GetBValue(fIdlePaintColor) + fFadePhase * fFadeStep, 255)
        );
    end;
  end
  else
  begin
    Dec(fFadePhase);
    if fFadePhase <= 0 then
    begin
      fActualDrawColor := fIdlePaintColor;
      fFadeTimer.Enabled := False;
    end
    else
    begin
      fActualDrawColor := MakeColor(
        Min( GetRValue(fIdlePaintColor) + fFadePhase * fFadeStep, 255),
        Min( GetGValue(fIdlePaintColor) + fFadePhase * fFadeStep, 255),
        Min( GetBValue(fIdlePaintColor) + fFadePhase * fFadeStep, 255)
        );
    end;
  end;
  Invalidate;
end;

procedure TPTZWinControlButton.SetButtonType(const Value: TPTZWinControlButtonType);
begin
  if fButtonType <> Value then
  begin
    fButtonType := Value;
    Invalidate;
  end;
end;

procedure TPTZWinControlButton.SetHighlightedPaintColor(const Value: TColor);
begin
  if fHighlightedPaintColor <> Value then
  begin
    fHighlightedPaintColor := Value;
    fFadeStep := 0;
    Invalidate;
  end;
end;

procedure TPTZWinControlButton.SetIdlePaintColor(const Value: TColor);
begin
  if fIdlePaintColor <> Value then
  begin
    fIdlePaintColor := Value;
    fActualDrawColor := Value;
    fFadeStep := 0;
    Invalidate;
  end;
end;

procedure TPTZWinControlButton.SetShapeMarginLeft(const Value: Integer);
begin
  if fShapeMarginTop <> Value then
  begin
    fShapeMarginTop := Value;
    Invalidate;
  end;
end;

procedure TPTZWinControlButton.SetShapeMarginTop(const Value: Integer);
begin
  if fShapeMarginTop <> Value then
  begin
    fShapeMarginTop := Value;
    Invalidate;
  end;
end;

procedure TPTZWinControlButton.SetShapeSize(const Value: Integer);
begin
  if fShapeSize <> Value then
  begin
    fShapeSize := Value;
    Invalidate;
  end;
end;

procedure TPTZWinControlButton.Paint;
var
  canvasGraphics : TGPGraphics;
  bufferBitmap   : TGPBitmap;
  bmpGraphics    : TGPGraphics;
  bufferBitmapBg : TGPBitmap;
  bmpGraphicsBg  : TGPGraphics;
  pen            : TGPPen;
  drawSize       : Integer;
  leftMargin     : Integer;
  topMargin      : Integer;
  y              : Single;
  penSize        : Single;
  points         : TPointFDynArray;

  procedure SetSquarePoints(aOffset, aSize, aCornerSize: Single);
  begin
    points[0].X := aOffset;
    points[0].Y := aOffset + aCornerSize;
    points[1].X := aOffset + aCornerSize;
    points[1].Y := aOffset;
    points[2].X := aOffset + aSize - aCornerSize;
    points[2].Y := aOffset;
    points[3].X := aOffset + aSize;
    points[3].Y := aOffset + aCornerSize;
    points[4].X := aOffset + aSize;
    points[4].Y := aOffset + aSize - aCornerSize;
    points[5].X := aOffset + aSize - aCornerSize;
    points[5].Y := aOffset + aSize;
    points[6].X := aOffset + aCornerSize;
    points[6].Y := aOffset + aSize;
    points[7].X := aOffset;
    points[7].Y := aOffset + aSize - aCornerSize;
  end;
begin
  inherited;

  if ShapeSize <= 1 then
    Exit;

  drawSize := ShapeSize * 3;
  penSize := 1.6 * drawSize / 12;
//  if fButtonType in [btMinimize, btClose] then
//     penSize := penSize * 1.5;

  if fBackgroundBrush = nil then
  begin
    fBackgroundBrush := TGPSolidBrush.Create(MakeColor(GetRValue(Color),GetGValue(Color),GetBValue(Color)));
  end;

  Canvas.Lock;
  try
    pen := TGPPen.Create(MakeColor(GetRValue(fActualDrawColor),GetGValue(fActualDrawColor),GetBValue(fActualDrawColor)), penSize);
    canvasGraphics := TGPGraphics.Create(Canvas.Handle);

    bufferBitmapBg := TGPBitmap.Create(Width, Height, PixelFormat32bppARGB);
    bmpGraphicsBg := TGPGraphics.Create(BufferBitmapBg);
    bmpGraphicsBg.FillRectangle(FBackgroundBrush, 0, 0, Width, Height);

    bufferBitmap := TGPBitmap.Create(DrawSize, DrawSize, PixelFormat32bppARGB);
    bmpGraphics := TGPGraphics.Create(BufferBitmap);
    bmpGraphics.FillRectangle(FBackgroundBrush, 0, 0, DrawSize, DrawSize);

    bmpGraphics.SetSmoothingMode(SmoothingModeHighQuality);
    bmpGraphics.SetInterpolationMode(InterpolationModeHighQualityBicubic);

{    if fIsMouseInShape then
      pen := fHightlightedPen
    else
      pen := fIdlePen; }

    if fButtonType = btMinimize then
    begin
      y := DrawSize / 2 - 1;
      bmpGraphics.DrawLine(pen, 0, y, drawSize, y);
    end
    else
    if fButtonType = btMaximize then
    begin
      SetLength(points, 8);
      SetSquarePoints(penSize / 2 + 1, drawSize - penSize - 2, penSize * 1.0);
      bmpGraphics.DrawPolygon(pen, PGPPointF(@points[0]), 8);
    end
    else
    if fButtonType = btRestore then
    begin
      SetLength(points, 8);
      SetSquarePoints(penSize / 2 + 0.75, drawSize - penSize * 3, penSize * 0.65);
      bmpGraphics.DrawPolygon(pen, PGPPointF(@points[0]), 8);
      SetSquarePoints(penSize / 2 + 0.75 + 1.75 * pensize, drawSize - penSize * 3, penSize * 0.75);
      bmpGraphics.DrawPolygon(pen, PGPPointF(@points[0]), 8);
    end
    else
    if fButtonType = btClose then
    begin
      bmpGraphics.DrawLine(pen, penSize * 0.5, penSize * 0.5, DrawSize - penSize * 0.5, DrawSize - penSize * 0.5);
      bmpGraphics.DrawLine(pen, DrawSize - penSize * 0.5, penSize * 0.5, penSize * 0.5, DrawSize - penSize * 0.5);
    end;

    leftMargin := ShapeMarginLeft;
    if leftMargin < 0 then
    begin
      leftMargin := (Width - ShapeSize) div 2;
      if leftMargin < 0 then
        leftMargin := 0;
    end;

    topMargin := ShapeMarginTop;
    if topMargin < 0 then
    begin
      topMargin := (Height - ShapeSize) div 2;
      if topMargin < 0 then
        topMargin := 0;
    end;

    canvasGraphics.DrawImage(bufferBitmapBg, 0, 0, Width, Height);
    canvasGraphics.DrawImage(bufferBitmap, leftMargin, topMargin, ShapeSize, ShapeSize);

    bmpGraphicsBg.Free;
    bufferBitmapBg.Free;
    bmpGraphics.Free;
    bufferBitmap.Free;

    canvasGraphics.Free;

    pen.Free;
  finally
    Canvas.Unlock;
  end;
end;


procedure Register;
begin
  RegisterComponents('Macecraft', [TPTZWinControlButton]);
end;


end.
