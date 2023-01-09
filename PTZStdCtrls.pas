unit PTZStdCtrls;

interface

uses
	WinAPI.Windows, WinAPI.Messages,
	System.Types, System.Classes,
	Vcl.Controls, Vcl.StdCtrls, Vcl.Forms,
  Vcl.Themes;

type
	TPTZAutoSize = (ptzNone, ptzWidth, ptzHeight, ptzBoth);
	TPTZAutoSizeSet = set of TPTZAutoSize;

const
	PTZ_AUTOSIZE_DEFAULT = ptzBoth;

type
	TPTZCheckBox = class(TCheckBox)
	private
		FPTZAutoSize: TPTZAutoSize;
		FAutoSizing: boolean;
		FSquareSize: integer;
    FMinHeight: integer;
		procedure CMFontChanged(var Message: TMessage); message CM_FONTCHANGED;
		procedure CMTextChanged(var Message: TMessage); message CM_TEXTCHANGED;
    procedure WMEraseBkgnd(var Message: TWmEraseBkgnd); message WM_ERASEBKGND;
	protected
		procedure AdjustAutoSizeDo(AutoSizeSet: TPTZAutoSizeSet = [ptzWidth, ptzHeight, ptzBoth]);
		procedure SetPTZAutoSize(const AValue: TPTZAutoSize); virtual;
		function CanResize(var NewWidth, NewHeight: Integer): Boolean; override;
	public
		constructor Create(AOwner: TComponent); override;
    procedure AdjustAutoSize();
	published
		property PTZAutoSize: TPTZAutoSize read FPTZAutoSize write SetPTZAutoSize default PTZ_AUTOSIZE_DEFAULT;
    property MinHeight : Integer read FMinHeight write FMinHeight default 0;
    property OnMouseUp;
    property OnKeyUp;
	end;

	TPTZRadioButton = class(TRadioButton)
	private
		FPTZAutoSize: TPTZAutoSize;
		FAutoSizing: boolean;
		FSquareSize: integer;
    FMinHeight: integer;
		procedure CMFontChanged(var Message: TMessage); message CM_FONTCHANGED;
		procedure CMTextChanged(var Message: TMessage); message CM_TEXTCHANGED;
    procedure WMEraseBkgnd(var Message: TWmEraseBkgnd); message WM_ERASEBKGND;
	protected
		procedure AdjustAutoSizeDo(AutoSizeSet: TPTZAutoSizeSet = [ptzWidth, ptzHeight, ptzBoth]);
		procedure SetPTZAutoSize(const AValue: TPTZAutoSize); virtual;
		function CanResize(var NewWidth, NewHeight: Integer): Boolean; override;
	public
		constructor Create(AOwner: TComponent); override;
    procedure AdjustAutoSize();
	published
		property PTZAutoSize: TPTZAutoSize read FPTZAutoSize write SetPTZAutoSize default PTZ_AUTOSIZE_DEFAULT;
    property MinHeight : Integer read FMinHeight write FMinHeight default 0;
    property OnMouseUp;
    property OnKeyUp;
	end;

procedure Register();

implementation

uses
  System.Math,
	VCL.Dialogs, System.SysUtils;

// COMMENTS ON IMPLEMENTATION:
// 1. Functionality, common to both TPTZCheckBox and TPTZRadioButton, is collected in the helper class TPTZHelper.
// 2. Resize events are controlled with overriding TControl.CanResize(). NB! TControl.CanAutoSize() is not appropriate
//    here, as it is connected to VCL's TControl.AutoSize property.

{**************************************************************}
{* TPTZHelper                                                 *}
{**************************************************************}

type
	TPTZHelper = class helper for TWinControl
	private
		function ptzCalcAutoSize(AnAutoSize: TPTZAutoSize; ASquareSize: integer): TSize;
		procedure ptzCorrectResizeRequest(AnAutoSize: TPTZAutoSize; var NewWidth, NewHeight: integer);
		procedure ptzSetBounds(AnAutoSize: TPTZAutoSize; ASquareSize: integer; AMinHeight: integer);
	end;

{ TPTZHelper }

function TPTZHelper.ptzCalcAutoSize(AnAutoSize: TPTZAutoSize; ASquareSize: integer): TSize;
var
	DC: HDC;
	TextMetric: TTextMetric;
	TextSize: TSize;
  Padding: integer;
begin
	DC := CreateCompatibleDC(0);
	if DC = 0 then RaiseLastOSError();
	try
		if SelectObject(DC, Font.Handle) = 0 then
			RaiseLastOSError();
		if not GetTextMetrics(DC, TextMetric) or not GetTextExtentPoint32(DC, PChar(Caption), Length(Caption), TextSize) then
			RaiseLastOSError();
	finally
		DeleteDC(DC);
	end;

	// OK, we have correct TextMetric and TextSize now

	Padding := TextMetric.tmAveCharWidth div 2;

	if AnAutoSize in [ptzWidth, ptzBoth] then
		result.cx := ASquareSize + TextSize.cx + Padding
	else
		result.cx := Width;

	if AnAutoSize in [ptzHeight, ptzBoth] then
		result.cy := Max(ASquareSize, TextSize.cy)
	else
		result.cy := Height;

  // Just in case
  result.cx := result.cx +2;
  result.cy := result.cy +2;

end;

procedure TPTZHelper.ptzCorrectResizeRequest(AnAutoSize: TPTZAutoSize; var NewWidth, NewHeight: integer);
begin
	if AnAutoSize in [ptzWidth, ptzBoth] then
		NewWidth := Width;
	if AnAutoSize in [ptzHeight, ptzBoth] then
		NewHeight := Height;
end;

procedure TPTZHelper.ptzSetBounds(AnAutoSize: TPTZAutoSize; ASquareSize: integer; AMinHeight: integer);
var
 h : Integer;
begin
	with ptzCalcAutoSize(AnAutoSize, ASquareSize) do
  begin
    h := cy;
    if h < AMinHeight then h := AMinHeight;
		SetBounds(Left, Top, cx, h);
  end;
end;

{**************************************************************}
{* TPTZCheckBox                                               *}
{**************************************************************}

constructor TPTZCheckBox.Create(AOwner: TComponent);
begin
	inherited;
	FSquareSize := Height;
	FPTZAutoSize := PTZ_AUTOSIZE_DEFAULT;
	try
		FAutoSizing := true;
		ptzSetBounds(FPTZAutoSize, FSquareSize, FMinHeight);
	finally
		FAutoSizing := false;
	end;
end;

procedure TPTZCheckBox.AdjustAutoSize();
begin
 AdjustAutoSizeDo();
end;

procedure TPTZCheckBox.AdjustAutoSizeDo(AutoSizeSet: TPTZAutoSizeSet = [ptzWidth, ptzHeight, ptzBoth]);
begin
	if PTZAutoSize in AutoSizeSet then
	try
		FAutoSizing := true;
		ptzSetBounds(PTZAutoSize, FSquareSize, FMinHeight);
	finally
		FAutoSizing := false;
	end;
end;

function TPTZCheckBox.CanResize(var NewWidth, NewHeight: Integer): Boolean;
begin
	if not FAutoSizing then
		ptzCorrectResizeRequest(PTZAutoSize, NewWidth, NewHeight);
	result := inherited;
	result := result or (NewWidth <> Width) or (NewHeight <> Height);
end;

procedure TPTZCheckBox.CMFontChanged(var Message: TMessage);
begin
	inherited;
	AdjustAutoSizeDo();
end;

procedure TPTZCheckBox.CMTextChanged(var Message: TMessage);
begin
	inherited;
	AdjustAutoSizeDo([ptzWidth, ptzBoth]);
end;

procedure TPTZCheckBox.WMEraseBkgnd(var Message: TWmEraseBkgnd);
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

procedure TPTZCheckBox.SetPTZAutoSize(const AValue: TPTZAutoSize);
begin
	if FPTZAutoSize <> AValue then
	begin
		ptzSetBounds(AValue, FSquareSize, FMinHeight);
		FPTZAutoSize := AValue;
	end;
end;


{**************************************************************}
{* TPTZRadioButton                                            *}
{**************************************************************}

constructor TPTZRadioButton.Create(AOwner: TComponent);
begin
	inherited;
	FSquareSize := Height;
	FPTZAutoSize := PTZ_AUTOSIZE_DEFAULT;
	try
		FAutoSizing := true;
		ptzSetBounds(FPTZAutoSize, FSquareSize, FMinHeight);
	finally
		FAutoSizing := false;
	end;
end;

procedure TPTZRadioButton.AdjustAutoSize();
begin
 AdjustAutoSizeDo();
end;

procedure TPTZRadioButton.AdjustAutoSizeDo(AutoSizeSet: TPTZAutoSizeSet);
begin
	if PTZAutoSize in AutoSizeSet then
	try
		FAutoSizing := true;
		ptzSetBounds(PTZAutoSize, FSquareSize, FMinHeight);
	finally
		FAutoSizing := false;
	end;
end;

function TPTZRadioButton.CanResize(var NewWidth, NewHeight: Integer): Boolean;
begin
	if not FAutoSizing then
		ptzCorrectResizeRequest(PTZAutoSize, NewWidth, NewHeight);
	result := inherited;
	result := result or (NewWidth <> Width) or (NewHeight <> Height);
end;

procedure TPTZRadioButton.CMFontChanged(var Message: TMessage);
begin
	inherited;
	AdjustAutoSizeDo();
end;

procedure TPTZRadioButton.CMTextChanged(var Message: TMessage);
begin
	inherited;
	AdjustAutoSizeDo([ptzWidth, ptzBoth]);
end;

procedure TPTZRadioButton.WMEraseBkgnd(var Message: TWmEraseBkgnd);
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

procedure TPTZRadioButton.SetPTZAutoSize(const AValue: TPTZAutoSize);
begin
	if FPTZAutoSize <> AValue then
	begin
		ptzSetBounds(AValue, FSquareSize, FMinHeight);
		FPTZAutoSize := AValue;
	end;
end;

{**************************************************************}
{* Components registration                                    *}
{**************************************************************}

procedure Register();
begin
	RegisterComponents('Macecraft', [TPTZCheckBox, TPTZRadioButton]);
end;

end.
