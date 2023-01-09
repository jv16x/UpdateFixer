unit PTZPanel;

{$R-,T-,X+,H+,B-,O+,Q-}

interface


uses
  madExcept, Windows, Messages, SysUtils, Classes,
  Graphics, Controls, Forms, Math,
  Vcl.Themes,
  GDIPAPI, GDIPOBJ, GDIPUTIL,
  ExtCtrls, StdCtrls;


type
  TPTZPanel = class(TCustomPanel)
  private
    FCreated            : Boolean;
    FColor              : TColor;
    FBorderColor        : TColor;
    FBorderWidth        : Integer;
    FCornerRadius       : Integer;
    FUpdateLock         : Integer;

    FLastInitPaintState : String;
    FBackgroundColor    : Cardinal;
    FPen                : TGPPen;

    procedure Init_PaintHelpers();

    procedure SetColor(NewColor : TColor);
    procedure SetBorderColor(NewBorderColor : TColor);
    procedure SetBorderWidth(NewBorderWidth : Integer);
    procedure SetCornerRadius(NewCornerRadius: Integer);
    procedure WMEraseBkgnd(var Message: TWmEraseBkgnd); message WM_ERASEBKGND;
  protected
    procedure Paint; override;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    procedure EndUpdate();
    procedure BeginUpdate();
  published
   property Color          : TColor      read FColor            write SetColor;
   property BorderColor    : TColor      read FBorderColor      write SetBorderColor;
   property BorderWidth    : Integer     read FBorderWidth      write SetBorderWidth;
   property CornerRadius   : Integer     read FCornerRadius     write SetCornerRadius;

   property Align;
   property Visible;
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
  RegisterComponents('Macecraft', [TPTZPanel]);
end;

constructor TPTZPanel.Create(AOwner: TComponent);
begin
  FUpdateLock := 1;
  inherited Create(AOwner);

  Self.BevelInner       := bvNone;
  Self.BevelOuter       := bvNone;
  Self.BevelKind        := bkNone;
  Self.BorderStyle      := bsNone;
  Self.DoubleBuffered   := True;
  Self.ParentBackground := False;
  Self.Color            := clWhite;

  FPen := nil;
  FBorderColor  := RGB(216, 226, 238);
  FBorderWidth  := 1;
  FCornerRadius := 30;

  FCreated    := True;
  FUpdateLock := 0;
end;


destructor TPTZPanel.Destroy;
begin
 inherited;

 If FPen <> nil then FPen.Free;
end;


procedure TPTZPanel.SetColor(NewColor : TColor);
begin
  if FColor <> NewColor then
  begin
    FColor := NewColor;
    If FUpdateLock = 0 then Invalidate;
  end;
end;

procedure TPTZPanel.SetBorderColor(NewBorderColor : TColor);
begin
  if FBorderColor <> NewBorderColor then
  begin
    FBorderColor := NewBorderColor;
    If FUpdateLock = 0 then Invalidate;
  end;
end;

procedure TPTZPanel.SetBorderWidth(NewBorderWidth : Integer);
begin
  if FBorderWidth <> NewBorderWidth then
  begin
    FBorderWidth := NewBorderWidth;
    If FUpdateLock = 0 then Invalidate;
  end;
end;

procedure TPTZPanel.SetCornerRadius(NewCornerRadius: Integer);
begin
  if FCornerRadius <> NewCornerRadius then
  begin
    FCornerRadius := NewCornerRadius;
    If FUpdateLock = 0 then Invalidate;
  end;
end;

procedure TPTZPanel.WMEraseBkgnd(var Message: TWmEraseBkgnd);
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


procedure TPTZPanel.Init_PaintHelpers;
Var
 CurState : String;
begin

 if (FCreated = False) or (Self = nil) or (Application = nil) then EXIT; // just in case

 // We need to re-create the pens and brushes every time color data changes, hence the CurState checks:
 CurState := IntToStr(Self.Color) +':'+ IntToStr(FBorderColor) + ':' + IntToStr(FBorderWidth);

 if (FPen <> nil) and (CurState <> FLastInitPaintState) then
 begin
  FPen.Free;
  FPen := nil;
 end;

 if (FPen = nil) or (FLastInitPaintState = '') then
 begin
  FBackgroundColor := MakeColor( GetRValue(Self.Color), GetGValue(Self.Color), GetBValue(Self.Color) );
  FPen := TGPPen.Create(MakeColor(GetRValue(FBorderColor),GetGValue(FBorderColor),GetBValue(FBorderColor)), FBorderWidth);

  FLastInitPaintState := CurState;
 End;

End;

procedure TPTZPanel.BeginUpdate();
begin
 Inc(FUpdateLock);
End;

procedure TPTZPanel.EndUpdate();
begin
 Dec(FUpdateLock);
 If FUpdateLock = 0 then Self.Invalidate;
End;

procedure TPTZPanel.Paint;
var
  Graphics : TGPGraphics;
  path : TGPGraphicsPath;
  l, t, w, h, d : integer;
begin

  If (FCreated = False) or (Self = nil) or (Application = nil) then EXIT;

  Inherited;

  if (Self.Canvas = nil) or (Self.Canvas.Handle < 10) or (Self.Handle < 10) or (Self.Canvas.HandleAllocated = False) then EXIT;

  Try
   If FUpdateLock > 0 then EXIT;
   Init_PaintHelpers();
   Graphics := nil;
  Except
   Exit;
  End;

  Try
    Try
     Graphics := TGPGraphics.Create(Canvas.Handle);
     Graphics.SetSmoothingMode(SmoothingModeAntiAlias);
     Graphics.SetInterpolationMode(InterpolationModeHighQualityBicubic);
     Graphics.SetTextRenderingHint(TextRenderingHintAntiAliasGridFit);

     Graphics.Clear( FBackgroundColor );
    Except
     EXIT;
    End;

    if FBorderWidth > 0 then
    begin
      If FCornerRadius > 1 then
      begin
        path := TGPGraphicsPath.Create;
        l := 0; //FBorderWidth;
        t := 0; //FBorderWidth;
        w := Self.ClientWidth  - l*2 -1;
        h := Self.ClientHeight - t*2 -1;
        d := FCornerRadius div 2;

        // the lines beween the arcs are automatically added by the path
        path.AddArc(l, t, d, d, 180, 90); // topleft
        path.AddArc(l + w - d, t, d, d, 270, 90); // topright
        path.AddArc(l + w - d, t + h - d, d, d, 0, 90); // bottomright
        path.AddArc(l, t + h - d, d, d, 90, 90); // bottomleft
        path.CloseFigure();

        Graphics.DrawPath(FPen, Path);
        Path.Free;
      End else
      begin
        Graphics.DrawRectangle(FPen, 0, 0, Self.Width-1, Self.Height-1);
      End;
    end;

  Finally
   If Graphics <> nil then Graphics.Free;
  End;

End;


end.
