program UpdateFixer;

uses
  madExcept,
  madLinkDisAsm,
  madListHardware,
  madListProcesses,
  madListModules,
  Vcl.Forms,
  MainFormUnit in 'MainFormUnit.pas' {MainForm},
  PTZPanel in '..\jv16 PowerTools\_DEV\Components\CustomXE\PTZPanel.pas',
  PTZStdCtrls in '..\jv16 PowerTools\_DEV\Components\CustomXE\PTZStdCtrls.pas',
  PTZSymbolButton in '..\jv16 PowerTools\_DEV\Components\CustomXE\PTZSymbolButton.pas',
  PTZWinControlButton in '..\jv16 PowerTools\_DEV\Components\CustomXE\PTZWinControlButton.pas',
  ColorPanel in '..\FindAll\ColorPanel.pas',
  GUIPanel in '..\jv16 PowerTools\_DEV\Components\PT UI Panels\GUIPanel.pas',
  GUIPanelHVList in '..\jv16 PowerTools\_DEV\Components\PT UI Panels\GUIPanelHVList.pas',
  PTZGlyphButton in '..\jv16 PowerTools\_DEV\Components\CustomXE\PTZGlyphButton.pas',
  uMiniStringTools in '..\System Examiner\uMiniStringTools.pas',
  FastStringCaseUtils in 'C:\Code\PT CommonCode\FastStringCaseUtils.pas',
  PTZProgressBar in '..\jv16 PowerTools\_DEV\Components\CustomXE\PTZProgressBar.pas',
  InternetUtils in '..\jv16 PowerTools\_DEV\_AutoUpdate\InternetUtils.pas',
  Win64bitDetector in 'C:\Code\PT CommonCode\Win64bitDetector.pas',
  Vcl.Themes,
  Vcl.Styles;

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
