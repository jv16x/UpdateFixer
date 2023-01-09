unit MainFormUnit;


{
  Update Fixer version 1.0
  By Jouni Flemming (Macecraft Software)

  Official website: https://winupdatefixer.com/
  Source code license: GNU General Public License v3
  https://www.gnu.org/licenses/gpl-3.0.en.html

  Official Github: https://github.com/jv16x/UpdateFixer/


  You can contact me: jouni@winupdatefixer.com or jouni.flemming@macecraft.com
  If you do, please include “Update Fixer” in the subject line.


  Disclaimer:
  This source code is provided “as is” without any guarantees of any kind
  with the exception that we guarantee the Update Fixer application does not
  include any malware or other such hidden malicious functionality.


  This project uses MadExcept exception handler by http://madshi.net/
  Simply remove the MadExcept references if you wish to compile without it.


  This project also uses a few custom UI components, namely:
  PTZPanel, PTZStdCtrls, PTZSymbolButton, PTZWinControlButton, ColorPanel,
  GUIPanel, GUIPanelHVList, PTZGlyphButton, PTZProgressBar.

  You can remove these and replace the controls with standard VCL controls if you wish.


  The program has two main steps in its operation

  1) In the Analysis step - implemented mostly via the Analyze_xxx functions -
     we attempt to detect common problems in the system that can cause Windows Update to fail.
     One such common problem is that the System Services relating to Windows Update are disabled.

  2) In the processing step - implemented mostly via the Process_xxx functions -
     we process, i.e. fix the found issues.
     Notice that the process step only does changes as authorized by the user by selecting
     from the UI which fixing operations should be performed.
     It is possible that the user does not select all the found issues to be fixed,
     or that the user chooses to fix all the issues, even in those that were not actually detected.
     In such case, user input is interpreted to mean to change the settings of the specific item to its defaults.


  The fixing process uses three techniques: in-exe commands, mainly Windows API calls,
  running of batch files and running of PowerShell files.

  Doing this in these three ways was noted in testing to be the most robust way of performing the fixes.

  In other words, in some testing systems, simply attempting to do a fix by executing Windows API
  calls within the exe file alone did not work, but attempting to do the same fix by using a
  batch file or a PowerShell script file did, or vice versa.
  A more elegant way of performing all the fixes would naturally to implement everything without
  the need to use any batch or PowerShell script files, but I didn't have the time to do so.
  My main goal was to make this work (i.e. be able to fix Windows Update even when the official
  Windows Update Troubleshooter couldn't), not to make it work and work in the most elegant way possible

  Anyone reviewing this code is free to let me know of fixes and improvements how all this
  can be done without the use of Batch/PowerShell script files.


}



interface


// If enabled, displays any exception and error message to the user
{.$DEFINE Debug_ExceptionMessages}

// If enabled, generates a debug log to user's Windows Desktop
{.$DEFINE Debug_GenerateDebugLog}

// If enabled, displays some markers in the UI to show the exact progress of code execution
{.$DEFINE Debug_ShowProgress}

// If Enabled, displays the UI using vivid colors, to see where each UI element exactly is
{.$DEFINE Debug_Colors}



uses
  Winapi.Windows, Winapi.Messages,
  System.SysUtils,
  System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  PTZStdCtrls, Registry, IniFiles,
  Generics.Collections,
  uMiniStringTools, ShellAPI,
  GUIPanelHVList, PTZWinControlButton,
  GUIPanel, Vcl.Imaging.pngimage,
  Vcl.Themes, Math,
  System.NetEncoding,
  System.Character,
  AclAPI,
  AccCtrl,
  System.IOUtils, TLHelp32,
  Win64bitDetector,
  System.Win.TaskbarCore, System.Win.Taskbar,
  FastStringCaseUtils, InternetUtils,
  Vcl.ExtCtrls, ColorPanel, PTZPanel,
  Vcl.StdCtrls, PTZGlyphButton, PTZProgressBar,
  Vcl.AppEvnts, Vcl.Imaging.GIFImg, Vcl.Menus;

const
 APP_VERSION       = '1.0';
 DEBUG_STORE_BAT   = 0; // If 1, saves all the generated script files to user's desktop.
 DEBUG_PIRATED     = 0; // If 1, the pirated Windows detection will always detect OS as pirated in order to test how the UI looks like
 DEBUG_NO_ISSUES   = 0; // If 1, the analysis shall not find any problems in order to test how the UI looks like
 DEBUG_SOME_ISSUES = 0; // If 1, the analysis shall always find some problems in order to test how the UI looks like
 DEBUG_NO_BATCH    = 0; // If 1, the fixing shall not use any batch files
 DEBUG_SHOW_WINVER = 0; // If 1, the UI will display contents of FWinVer (version of Windows)
 DEBUG_WRITE_LOG   = 0; // If 1, the app will generate a debug log to user's desktop


 // We are using a simple xor encryption + base64 encoding
 // in order to not include certain strings in the source code,
 // as having these in plaintext in the program binary caused
 // many false positive malware warnings in VirusTotal and
 // the anti-virus companies took days to process the false positive reports
 // and we were under a deadline to release the app
 // I'll remove this encrypted string nonsense when the false positive issues are solved
 // The decryption happens in function _x()

 GLOB_Crypt_CmdExe    = '!aWZoI2t3dQ=='; // 'cmd.exe'
 GLOB_Crypt_Powerhell = '!emR7aHx8eHR+fzpwbnI='; // 'powershell.exe'
 GLOB_Crypt_RegIni    = '!SnlpamdheT93a3E1O3U4'; // '@regini.exe -b '
 GLOB_Crypt_RegExeDel = '!SnlpaiBqaHQyV1FZU0Nd'; // '@reg.exe DELETE'
 GLOB_Crypt_Del       = '!Sm9pYS4gQTE9VTQ6RTc='; // '@del /Q /F /S '
 GLOB_Crypt_TakeOwn   = '!Sn9tZmtgZ38yPFU1OUU4'; // '@takeown /A /R '
 GLOB_Crypt_Attrib    = '!Smp4eXxmcjE/QTQ4RTc1UTo='; // '@attrib -R -S -H '
 GLOB_Crypt_Timeout   = '!fmJhaGF6ZDE9ZzQnNjh2dnhpeXx1Px4BbHZo'; // 'timeout /t 2 /nobreak > NUL'
 GLOB_Crypt_ps1       = '!JHt/PA=='; // '.ps1'
 GLOB_Crypt_Runas     = '!eH5ibH0='; // 'runas'


 Win10DeliveryDirs : Array[0 .. 7] of String =
    ('C:\Windows\Temp\',
     'C:\Windows\CbsTemp\',
     'C:\Windows\SoftwareDistribution\',
     'C:\Windows\Logs\',
     'C:\Windows\Logs\WindowsUpdate\',
     'C:\Windows\System32\CatRoot2\',
     '<x>\Application Data\Microsoft\Network\', // <x> => FAllUserProfile, no trail!
     '<x>\Microsoft\Network\Downloader\'
     );

 // also encrypted:
 ServiceNamesArr_X : Array[0 .. 5] of String =
    ('!XX5teF1qYmc=',
     '!SEJYXg==',
     '!SXl1fXpcZnI=',
     '!R3hlXmt9ZnRg',
     '!TmhjYEJuZX9xew==',
     '!Xnl5fnpqdFh8YGB0ent9aw==');

 ServiceDescsArrX : Array[0 .. 5] of String =
    ('!XWJiaWF4YzFHY3B0YnI=',
     '!SGpvZml9f2R8dzRceGN9dXZye3hwawB1UEJKVkBCWgl5Tl5bR0xV',
     '!SXl1fXpgd2NzY3x8dTdLfGhtdX57bA==',
     '!XWJiaWF4YzFbfWdhd3t0fGg=',
     '!XWJiaWF4YzFffHBgenJrOVN1b2l/c0xEUA==',
     '!X3tobHpqMF5gcHxwZWNqeG50bj1NelJXS0BB');

 ServiceKeySubDirsX : Array[0 .. 2] of String =
    ('!Wmp+bGNqZHRgYA==', '!WW5veHxmZGg=', '!XnllamlqYlh8dXs=');


{
 // In plaintext:
 ServiceNamesArr : Array[0 .. 5] of String =
    ('WuauServ',
     'BITS',
     'CryptSvc',
     'MsiServer',
     'DcomLaunch',
     'TrustedInstaller');

 ServiceDescsArr : Array[0 .. 5] of String =
    ('Windows Update',
     'Background Intelligent Transfer Service',
     'Cryptographic Services',
     'Windows Installer',
     'Windows Modules Installer',
     'Update Orchestrator Service');

 ServiceKeySubDirs : Array[0 .. 2] of String =
    ('Parameters', 'Security', 'TriggerInfo');
}

type
  TMainForm = class(TForm)
    tmrShow: TTimer;
    pnlMainParent: TPTZPanel;
    lblFooter: TLabel;
    pnlWindowTitle: TColorPanel;
    imgLogoSmall: TImage;
    lblHeader: TLabel;
    hlistWinControls: TGUIPanelHList;
    btnWinClose: TPTZWinControlButton;
    pnlWaiting: TPanel;
    ProgressBar: TPTZProgressBar;
    lblDebug: TLabel;
    ApplicationEvents: TApplicationEvents;
    imgSpinner_DM_128: TImage;
    imgSpinner_NM_128: TImage;
    lblWorking: TLabel;
    lblFooter2: TLabel;
    vlistDone: TGUIPanelVList;
    btnClose: TPTZGlyphButton;
    pnlSpaceDone: TPanel;
    btnReboot: TPTZGlyphButton;
    vlistAnalyze: TGUIPanelVList;
    btnAnalyze: TPTZGlyphButton;
    lblAnalyze: TLabel;
    vlistFix: TGUIPanelVList;
    pnlSpaceTop: TPanel;
    btnFix: TPTZGlyphButton;
    lblFixInfo: TLabel;
    pnlSpaceBtm: TPanel;
    lblBackup: TLabel;
    vlistRecommended: TGUIPanelVList;
    lblCaptRecommended: TLabel;
    vlistOptional: TGUIPanelVList;
    lblCaptOptional: TLabel;
    pnlSpaceSubTop1: TPanel;
    pnlSpaceSubTop2: TPanel;
    ScrollBox2: TScrollBox;
    vlistOptionalSub: TGUIPanelVList;
    pnlWindows: TPanel;
    imgConfused: TImage;
    lblWindows: TLabel;
    lblCaptMain: TLabel;
    pnlSpaceTopMain: TPanel;
    pnlThanks: TPanel;
    imgDone: TImage;
    lblDone: TLabel;
    lblThanks: TLabel;
    vlistHolder: TGUIPanelVList;
    lblTempFiles: TLabel;
    lblDeliveryFiles: TLabel;
    lblBlockers: TLabel;
    lblRegistry: TLabel;
    lblService1: TLabel;
    chkTempFiles: TPTZCheckBox;
    chkDeliverFiles: TPTZCheckBox;
    chkBlockers: TPTZCheckBox;
    chkRegistry: TPTZCheckBox;
    chkService1: TPTZCheckBox;
    lblHostsFile: TLabel;
    chkHostsFile: TPTZCheckBox;
    pnlSpaceTmp: TPanel;
    pnlSpaceDelivery: TPanel;
    pnlSpaceHosts: TPanel;
    pnlSpaceRegistry: TPanel;
    pnlSpaceService1: TPanel;
    pnlSpaceBlock: TPanel;
    pnlNothing: TPanel;
    imgNothing: TImage;
    lblNothingToFix: TLabel;
    PopupMenu_Rec: TPopupMenu;
    chkService2: TPTZCheckBox;
    lblService2: TLabel;
    pnlSpaceService2: TPanel;
    PopupMenu_Opt: TPopupMenu;
    pnlSpaceService3: TPanel;
    lblService3: TLabel;
    chkService3: TPTZCheckBox;
    chkService4: TPTZCheckBox;
    pnlSpaceService4: TPanel;
    lblService4: TLabel;
    chkService5: TPTZCheckBox;
    pnlSpaceService5: TPanel;
    lblService5: TLabel;
    chkService0: TPTZCheckBox;
    pnlSpaceService0: TPanel;
    lblService0: TLabel;
    ScrollBox1: TScrollBox;
    vlistRecommendedSub: TGUIPanelVList;
    SelectAll1: TMenuItem;
    SelectNone1: TMenuItem;
    SelectAll2: TMenuItem;
    SelectNone2: TMenuItem;
    tmrUpdateUiSelections: TTimer;
    lblDone2: TLabel;
    procedure btnWinCloseClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure tmrShowTimer(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure FormResize(Sender: TObject);
    procedure pnlWindowTitleMouseDown(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure imgLogoSmallClick(Sender: TObject);
    procedure lblFooterClick(Sender: TObject);
    procedure lblFooterMouseEnter(Sender: TObject);
    procedure lblFooterMouseLeave(Sender: TObject);
    procedure btnFixClick(Sender: TObject);
    procedure ApplicationEventsException(Sender: TObject; E: Exception);
    procedure lblFooter2MouseEnter(Sender: TObject);
    procedure lblFooter2MouseLeave(Sender: TObject);
    procedure btnCloseClick(Sender: TObject);
    procedure btnRebootClick(Sender: TObject);
    procedure lblTempFilesClick(Sender: TObject);
    procedure lblDeliveryFilesClick(Sender: TObject);
    procedure lblRegistryClick(Sender: TObject);
    procedure lblService1Click(Sender: TObject);
    procedure lblBlockersClick(Sender: TObject);
    procedure FormKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
    procedure btnAnalyzeClick(Sender: TObject);
    procedure FormMouseWheel(Sender: TObject; Shift: TShiftState;
      WheelDelta: Integer; MousePos: TPoint; var Handled: Boolean);
    procedure lblHostsFileClick(Sender: TObject);
    procedure lblService2Click(Sender: TObject);
    procedure lblService3Click(Sender: TObject);
    procedure lblService4Click(Sender: TObject);
    procedure lblService5Click(Sender: TObject);
    procedure lblService0Click(Sender: TObject);
    procedure SelectAll1Click(Sender: TObject);
    procedure PopupMenu_RecPopup(Sender: TObject);
    procedure chkTempFilesKeyUp(Sender: TObject; var Key: Word;
      Shift: TShiftState);
    procedure chkTempFilesMouseUp(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure tmrUpdateUiSelectionsTimer(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
  private
    FAppDir            : String; // With a trailing slash
    FPTAppDir          : String; // With a trailing slash
    FDebugDir          : String; // With a trailing slash
    FTempDir           : String; // With a trailing slash
    FDesktopDir        : String; // With a trailing slash
    FAllUserProfile    : String; // NOTE: No trailing slash!
    FWinVer            : String; // Version of Windows, e.g. 'Windows 10'
    FUI_DarkMode       : Boolean; // UI in Dark Mode or not
    FUI_AutoPos        : Boolean; // Whether app window should be automatically centered
    FMIN_APP_HEIGHT    : Integer;
    FMIN_APP_WIDTH     : Integer;
    FMAX_APP_WIDTH     : Integer;
    FLastTmrShowRun    : UInt64;
    FLastTmrStarted    : UInt64;
    FUISelUpdLock      : Boolean;
    FDebugLog          : TStringList;
    FCheckboxes        : TList<TPTZCheckBox>;
    FServiceCheckboxes : TList<TPTZCheckBox>;
    FServiceLabels     : TList<TLabel>;
    FServicePanels     : TList<TPanel>;
    FAllOptionControls : TList<TControl>;
    FTransStringsCache : TDictionary<String,String>;
    FTransHashesCache  : TDictionary<String,String>;
    FEnvVars           : TDictionary<String,String>;
    FXStrings          : TDictionary<String,String>;
    FExistsCache       : TDictionary<String, Boolean>;
    FTaskbarHelper     : TWinTaskbar;
    FBatFile           : TStringList;
    FBlockerRemoval    : TStringList;
    FRegIniFilename    : String;

    FDebugLogFile      : String;
    FDeliveryDirsOK    : Boolean;
    FFreeSpaceOK       : Boolean;
    FHostsFileOK       : Boolean;
    FPiratedWindows    : Boolean;
    FServiceOKArr      : Array[0 .. 5] of Boolean;
    FRegistryOK        : Boolean;
    FBlockersFound     : Boolean;
    FCmdResultFile     : String;
    FPriviledgeSet     : Boolean;

    procedure Init_AppDirs();
    procedure Init_LoadColorScheme();
    Function Init_Read_PT_DarkMode_Setting() : Integer;
    procedure Init_CheckBoxes();
    procedure Init_ServiceLists();

    Procedure OpenUrl(const URL : String);

    {$IFDEF Debug_GenerateDebugLog}
      Procedure DebugLog(const Str : String);
    {$ENDIF}

    Procedure SetLabelHeight(const Lbl : TLabel; const ExtraMargin : Integer = 0);
    Procedure UI_UpdateDynamicContent();
    Procedure UI_UpdateSelectionCounts();
    Procedure UI_UpdateSelectionCounts_DO();
    Procedure UI_Setup_TabOrder();
    Procedure UI_IncProgress(const AllDone : Boolean = False);
    Procedure UI_Sleep(const SleepyTimeMSEC : Integer);

    function CreateMutexDo(MutexName : string; ReleaseMutexAfter : Boolean) : Boolean;

    Function UI_AnyServiceCheckboxChecked() : Boolean;
    Function UI_AnyCheckboxChecked() : Boolean;

    Function DirectoryExists_Cached(Const InputStr : String; const DualModeCheck : Boolean = True) : Boolean;
    Function FileExists_Cached(Const InputStr : String) : Boolean;

    procedure Init_Translation();
    procedure Init_Translation_LoadSection(const DataList : TStringList; const SectionName : String);
    Function GetStringHash(const Str : String) : String;

    Function _t(Const Str : String; Const StrID : String; Const InsertDataArr : Array of String) : String; Overload;
    Function _t(const Str : String; const StrID : String; const InsertData : String = '') : String;        Overload;
    Function _x(const Str : String) : String;

    Procedure RunBatchFileAndWait(Const FileName: string);
    function RunBatchFileAndWait_GetCount() : Integer;

    function RunPSFileAndWait_GetCount() : Integer;
    Procedure RunPSFileAndWait(Const FileName: string);

    Function ExpandEnvVariable(const EnvVar : String) : String;
    Function MyExitWindows(const RebootParam: Longword): Boolean;
    Function HasAttrib(const Filename : String; Attr : Integer) : Boolean;

    Function GetTempDir() : String;
    Function GetCurrentUserDir() : String;
    Function GetDesktopDir() : String;
    function SetPrivilege(privilegeName: String; enable: boolean): boolean;

    Function GetDriveFreeSpaceGB() : Integer;
    Function ShellExecuteDo(Const FileName: string; Const Params: string = ''): Boolean;

    function SID_GetUserSID() : Pointer;
    function MyGetUserName(): String;
    function MyGetComputerName(): String;

  public
    Function IsByDefaultReadOnlyServKey(const ServName : String) : Boolean;
    Function Analyze_System_Service_CanRead(const ServName : String) : Boolean;
    Function Analyze_System_Service_CanWrite(const ServName : String) : Boolean;
    Function Analyze_System_Service_IsOK(const ServName : String) : Boolean;
    Procedure Analyze_System_Services();

    Procedure Analyze_System_Registry();
    Procedure Analyze_System_Blockers();
    Procedure Analyze_DeliveryDirs();
    Procedure Analyze_HostsFile();
    Procedure Analyze_HostsFile_DO();
    Procedure Analyze_WinVer();

    Procedure Analyze_Start_Cmd();
    Function Analyze_GenuineWindows_CheckFile(const Filename : String) : Boolean;
    Procedure Analyze_GenuineWindows();

    Procedure Process_Init();
    Procedure Process_Init_Bat();
    Procedure Process_Init_PS();
    Procedure Process_Init_Pas();

    Procedure Process_Finalize();
    Procedure Process_Finalize_PS();

    Procedure Process_Registry();
    Procedure Process_Services();
    Procedure Process_Delivery_Files();
    Procedure Process_HostsFile();
    Procedure Process_HostsFile_DO();

    Procedure Process_Temporary_Files();
    Function GetAllUserDirs() : TStringList;
  end;

var
  MainForm: TMainForm;
  Color_NavBack    : TColor;
  Color_MainBack   : TColor;
  Color_MainFont   : TColor;
  Color_LinkActive : TColor = 13601024; // Light blue color when mouse is over the link text

  Color_Btn_WhiteBack         : TColor = 14803425; // RGB(225,225,225);
  Color_Btn_BorderColor       : TColor = 12829635; // RGB(195,195,195);
  Color_Btn_ClickColor        : TColor = 16119285; // RGB(245,245,245);
  Color_Btn_FocusColor        : TColor = 15461355; // RGB(235,235,235);
  Color_Btn_FocusBorderColor  : TColor = 16752680; // RGB(40,160,255);


implementation

{$R *.dfm}



procedure TMainForm.ApplicationEventsException(Sender: TObject; E: Exception);
begin

 {$IFDEF Debug_GenerateDebugLog}
 DebugLog('ApplicationEventsException: ' + E.Message);
 {$ENDIF}

 {$IFDEF Debug_ExceptionMessages}
 ShowMessage('ApplicationEventsException: ' + E.Message);
 {$ENDIF}

end;



Procedure TMainForm.Analyze_Start_Cmd();
Const
 //Cmd = 'cscript /Nologo "C:\Windows\System32\slmgr.vbs" /dli';
 CmdX = '!aXhvf2d/ZDE9XXt5eXB3OThYJkFJdk5FTVRXeXVeW11PRh8fclxcXFVBGkNURBoZFV9QVA==';

begin

 if DEBUG_NO_BATCH = 1 then EXIT;

 FCmdResultFile := GetTempDir() + 'update_fixer_can_be_deleted_' + IntToStr(GetTickCount) +'.tmp';
 ShellExecuteDo(_x(GLOB_Crypt_CmdExe), '/C ' + _x(CmdX) + ' > "' + FCmdResultFile + '"');

end;


Function TMainForm.ShellExecuteDo(Const FileName: string; Const Params: string = ''): Boolean;
var
  exInfo: TShellExecuteInfo;
begin

  {$IFDEF Debug_GenerateDebugLog} DebugLog('ShellExecuteDo: ' + FileName + ' | ' + Params); {$ENDIF}
  Result := False;
  FillChar(exInfo, SizeOf(exInfo), 0);

  with exInfo do
  begin
    cbSize := SizeOf(exInfo);
    fMask := SEE_MASK_NOCLOSEPROCESS or SEE_MASK_FLAG_DDEWAIT;
    Wnd := GetActiveWindow();
    exInfo.lpVerb := 'open';
    exInfo.lpParameters := PChar(Params);
    lpFile := PChar(FileName);
    nShow := SW_HIDE; //SW_SHOWNORMAL;
  end;

  if ShellExecuteEx(@exInfo) then Result := true;

  Application.ProcessMessages;
  Sleep(200);

end;

// Result : True => All is now done
Function TMainForm.Analyze_GenuineWindows_CheckFile(const Filename : String) : Boolean;
Var
 FileData : String;
begin
 Result := False;

 if FileExists_Cached(Filename) = False then EXIT;

 FileData := RawReadFile_UTF8(Filename);


 if FastPosExB('license', FileData) then Result := True;

 if FastPosExB('non-genuine', FileData) or
    FastPosExB('(null)', FileData) or
    FastPosExB('slui.exe', FileData) then FPiratedWindows := True;


 {$IFDEF Debug_GenerateDebugLog}
   DebugLog('Analyze_GenuineWindows_CheckFile: ' + FileData);
 {$ENDIF}

end;

Procedure TMainForm.Analyze_GenuineWindows();
Var
 i          : Integer;
 x          : Integer;
 Filename   : String;
 TmpFile    : String;
 Row        : String;
 ScriptData : TStringList;
begin


 // Method 1:
 If Analyze_GenuineWindows_CheckFile(FCmdResultFile) then EXIT;


 // Method 2 - should only happen in non English Windows:
 // c:\windows\system32\slmgr.vbs /DLI result is LOCALIZED,
 // Hence, we need to do this very hacky solution of creating a copy of slmgr.vbs,
 // editing that copy not to translate (localize) its output and run that instead
 // of running the original vbs file.
 // Todo: To detect whether user is using a genuine Windows with a more elegant way
 Filename := _x('!aTFQemdhdH5lYEhmb2RsfHcoLkFtc01GUA1SR1U='); //'c:\windows\system32\slmgr.vbs';
 If FileExists_Cached(Filename) = False then
 begin
  FPiratedWindows := True;
  EXIT;
 end;

 ScriptData := TStringList.Create;
 ScriptData.text := RawReadFile_UTF8(Filename);

 i := 0;
 While i <= ScriptData.Count-5 do
 begin
  Inc(i);
  Row := ScriptData[i];

  if FastPosExB('function GetResource(name)', Row) or
     FastPosExB('sub GetResource(name)', Row) then
  begin
   Inc(i);
   ScriptData[i] := '  GetResource = Eval(name)';
   for x := i+1 to ScriptData.Count-1 do
   begin
    if FastPosExB('End Function', ScriptData[x]) then Break;
    if FastPosExB('End Sub', ScriptData[x]) then Break;
    ScriptData[x] := '';
   end;
  end;
 end;

 Filename := FTempDir + 'se_can_delete_qq_' + IntToStr(GetTickCount64()) + '.vbs';
 TmpFile  := FTempDir + 'se_can_delete_qq_' + IntToStr(GetTickCount64()) + '.tmp';

 Try
  ScriptData.SaveToFile(Filename);
 Except
  ;
 End;

 ScriptData.Free;
 If FileExists_Cached(Filename) = False then EXIT;

 x := RunBatchFileAndWait_GetCount();
 ShellExecuteDo(_x(GLOB_Crypt_CmdExe), '/C cscript /Nologo "' + Filename + '" /DLI > "' + TmpFile + '"');

 for i := 1 to 8 do
 begin
  UI_Sleep(1000);
  if (RunBatchFileAndWait_GetCount() <= x) or (FileExists_Cached(TmpFile)) then Break;
 End;

 UI_Sleep(1000);
 Analyze_GenuineWindows_CheckFile(TmpFile);

 Try
  DeleteFile(TmpFile);
 Except
  ;
 End;

end;


Function TMainForm._x(const Str : String) : String;
Var
 i      : Integer;
 Base64 : TBase64Encoding;
 TmpStr : String;
begin


 Result := '';
 if Str = '' then
 begin
  {$IFDEF Debug_ExceptionMessages}
  ShowMessage('_x empty input!');
  {$ENDIF}

  {$IFDEF Debug_GenerateDebugLog}
  DebugLog('_x empty input!');
  {$ENDIF}

  EXIT;
 End;

 if FXStrings.TryGetValue(Str, Result) then EXIT;
 Base64 := TBase64Encoding.Create();

 // Decrypt:
 if Str[1] = '!' then
 begin
  TmpStr := Base64.Decode( Copy(Str, 2, Length(Str) ));

  {$IFDEF Debug_ExceptionMessages}
  If Length(TmpStr) < 3 then ShowMessage('_x invalid TmpStr: ' + TmpStr);
  {$ENDIF}

  for i := 1 to Length(TmpStr) do Result := Result + Chr(Ord(TmpStr[i]) xor ((i+9) mod 69));
 end else

 // Encrypt:
 begin
  TmpStr := '';
  for i := 1 to Length(Str) do TmpStr := TmpStr + Chr(Ord(Str[i]) xor ((i+9) mod 69));
  Result := '!' + Base64.Encode(TmpStr);
 end;


 {$IFDEF Debug_ExceptionMessages}
 If Length(Result) < 3 then ShowMessage('_x invalid output: ' + Result);
 {$ENDIF}


 Base64.Free;
 FXStrings.AddOrSetValue(Str, Result);

 {$IFDEF Debug_GenerateDebugLog}
 //DebugLog('_x: ' + Str + ' => ' + Result);
 {$ENDIF}



End;

procedure TMainForm.btnAnalyzeClick(Sender: TObject);
Var
 i : Integer;
 AllServicesOK : Boolean;
 tmpstr : String;
begin

 {$IFDEF Debug_GenerateDebugLog} DebugLog('Button click: Analyze'); {$ENDIF}

 // Let's init these already:
 GetTempDir();
 GetDesktopDir();

 {$IFDEF Debug_ExceptionMessages}
 if (High(ServiceNamesArr_X) <> High(ServiceDescsArrX)) or
    (FServiceCheckboxes.Count-1 <> High(ServiceDescsArrX)) or
    (FServiceCheckboxes.Count <> FServiceLabels.Count) or
    (FServiceCheckboxes.Count <> FServicePanels.Count) then ShowMessage('Internal Error: x1');
 {$ENDIF}

 Try
   SetErrorMode(SEM_FAILCRITICALERRORS);
 except
  {$IFDEF Debug_ExceptionMessages}on E : Exception do ShowMessage('SEM_FAILCRITICALERRORS Exception: ' + E.Message); {$ENDIF}
 end;


 btnAnalyze.Visible  := False;
 lblWorking.WordWrap := False;
 lblWorking.AutoSize := True;
 lblWorking.Caption := _t('Analyzing your computer. Please wait ...', 'UpdateFixer.working-analyze');

 vlistAnalyze.Visible := False;
 lblFooter.Visible := False;
 lblFooter2.Visible := False;
 ProgressBar.Value := 0;
 ProgressBar.MaxValue := 100;

 pnlWaiting.Align := alClient;
 pnlWaiting.Visible := True;
 pnlWaiting.BringToFront;

 UI_UpdateDynamicContent();


 // Reset all, just in case:
 FDeliveryDirsOK    := True;
 FFreeSpaceOK       := True;
 FRegistryOK        := True;
 FHostsFileOK       := True;
 FBlockersFound     := False;
 FPiratedWindows    := False;
 AllServicesOK      := True;
 for i := Low(FServiceOKArr) to High(FServiceOKArr) do FServiceOKArr[i] := True;


 // Start the Analysis:
 {$IFDEF Debug_GenerateDebugLog} DebugLog('Analyze Step 1'); {$ENDIF}
 Analyze_Start_Cmd();
 UI_IncProgress();

 {$IFDEF Debug_GenerateDebugLog} DebugLog('Analyze Step 2'); {$ENDIF}
 Analyze_WinVer();
 UI_IncProgress();

 {$IFDEF Debug_GenerateDebugLog} DebugLog('Analyze Step 3'); {$ENDIF}
 FFreeSpaceOK := (GetDriveFreeSpaceGB() >= 30);
 UI_IncProgress();

 {$IFDEF Debug_GenerateDebugLog} DebugLog('Analyze Step 4'); {$ENDIF}
 Analyze_DeliveryDirs();
 UI_IncProgress();

 {$IFDEF Debug_GenerateDebugLog} DebugLog('Analyze Step 5'); {$ENDIF}
 Analyze_System_Services();
 UI_IncProgress();

 {$IFDEF Debug_GenerateDebugLog} DebugLog('Analyze Step 6'); {$ENDIF}
 Analyze_System_Registry();
 UI_IncProgress();

 {$IFDEF Debug_GenerateDebugLog} DebugLog('Analyze Step 7'); {$ENDIF}
 Analyze_System_Blockers();
 UI_IncProgress();

 {$IFDEF Debug_GenerateDebugLog} DebugLog('Analyze Step 8'); {$ENDIF}
 Analyze_HostsFile();
 UI_IncProgress();

 {$IFDEF Debug_GenerateDebugLog} DebugLog('Analyze Step 9'); {$ENDIF}
 Analyze_GenuineWindows();
 UI_IncProgress();

 Try
  if FileExists_Cached(FCmdResultFile) then DeleteFile(FCmdResultFile);
 except
  ;
 End;


 {$IFDEF Debug_GenerateDebugLog}
   If FPiratedWindows = False then DebugLog('Analyze IsGenuineWindows: True')
   else DebugLog('Analyze IsGenuineWindows: FALSE!');
 {$ENDIF}

 {$IFDEF Debug_GenerateDebugLog} DebugLog('Analyze Done'); {$ENDIF}

 // **
 // Debug magic happens here:
 if DEBUG_NO_ISSUES = 1 then
 begin
   FDeliveryDirsOK    := True;
   FFreeSpaceOK       := True;
   FRegistryOK        := True;
   FHostsFileOK       := True;
   FBlockersFound     := False;
   FPiratedWindows    := False;
   for i := Low(FServiceOKArr) to High(FServiceOKArr) do FServiceOKArr[i] := True;
 end;

 If DEBUG_PIRATED = 1 then FPiratedWindows := True;
 // **


 // All is done, let's just build the results:
 if FPiratedWindows then
 begin
   lblWindows.Caption := _t('This copy of Windows does not seem to be genuine. ' +
    'If your Windows Update is not working and Update Fixer is unable to fix it, this is probably the reason. ' +
    'Update Fixer has not been designed to fix malware or pirated software related issues with Windows Update.', 'updatefixer.piracy-warning');

  lblThanks.Caption := Trim(lblThanks.Caption) + #13#10 + #13#10 +
    _t('Note: This copy of Windows does not seem to be genuine. Update Fixer has not been designed to fix malware or pirated software related issues with Windows Update.' , 'updatefixer.piracy-warning');

  pnlWindows.Visible := True;
 end else pnlWindows.Visible := False;



 // **
 // **
 // Temporary Files

 if FFreeSpaceOK then
 begin
  chkTempFiles.Checked := False;
  chkTempFiles.Parent  := vlistOptionalSub;
  lblTempFiles.Parent  := vlistOptionalSub;
  pnlSpaceTmp.Parent   := vlistOptionalSub;
  lblTempFiles.Caption := _t('Removes all temporary files from your system. There is enough space in your system drive and that is why this feature does not need to be used, but you can enable this if you want.', 'updatefixer.temp-files-ok');
 end else
 begin
  chkTempFiles.Checked := True;
  chkTempFiles.Parent  := vlistRecommendedSub;
  lblTempFiles.Parent  := vlistRecommendedSub;
  pnlSpaceTmp.Parent   := vlistRecommendedSub;
  lblTempFiles.Caption := _t('Removes all temporary files from your system. This is recommended, because your system drive has less than 30 GB of free space, which might prevent Windows Update from working.', 'updatefixer.temp-files-not-ok');
 end;



 // **
 // Delivery Files

 if FDeliveryDirsOK then
 begin
  chkDeliverFiles.Checked := False;
  chkDeliverFiles.Parent  := vlistOptionalSub;
  lblDeliveryFiles.Parent := vlistOptionalSub;
  pnlSpaceDelivery.Parent := vlistOptionalSub;

  lblDeliveryFiles.Caption := _t('Removes all Windows Update data delivery related files. These files normally make Windows Update work faster, but sometimes they can become corrupted and could cause Windows Update to stop working. The delivery system directory structure is also reset.', 'updatefixer.delivery-files');
  lblDeliveryFiles.Caption := Trim(lblDeliveryFiles.Caption) + ' '+
        _t('No problems relating to the data delivery system were found.', 'updatefixer.delivery-files-ok')

 end else
 begin
  chkDeliverFiles.Checked := True;
  chkDeliverFiles.Parent  := vlistRecommendedSub;
  lblDeliveryFiles.Parent := vlistRecommendedSub;
  pnlSpaceDelivery.Parent := vlistRecommendedSub;

  lblDeliveryFiles.Caption := _t('Removes all Windows Update data delivery related files. These files normally make Windows Update work faster, but sometimes they can become corrupted and could cause Windows Update to stop working. The delivery system directory structure is also reset.', 'updatefixer.delivery-files');
  lblDeliveryFiles.Caption := Trim(lblDeliveryFiles.Caption) + ' '+
        _t('Potential problems were found from the delivery system. You should run this option to fix the problems. ', 'updatefixer.delivery-files-ok');
 end;



 // **
 // Update Blockers

 if FBlockersFound = False then
 begin
  chkBlockers.Checked  := False;
  chkBlockers.Parent   := vlistOptionalSub;
  lblBlockers.Parent   := vlistOptionalSub;
  pnlSpaceBlock.Parent := vlistOptionalSub;
  lblBlockers.Caption  := _t('Disables or removes any software that is used to block Windows Update from working. No such software were detected and therefore there is no need to run this option.', 'updatefixer.blockers-not-found');

 end else
 begin
  chkBlockers.Checked  := True;
  chkBlockers.Parent   := vlistRecommendedSub;
  lblBlockers.Parent   := vlistRecommendedSub;
  pnlSpaceBlock.Parent := vlistRecommendedSub;
  lblBlockers.Caption  := _t('Disables or removes any software that is used to block Windows Update from working. This type of software were detected. Running this option is recommended if you want to fix Windows Update.', 'updatefixer.blockers-found')
 end;


 // **
 // Registry Settings (Group policy, mainly)

 if FRegistryOK then
 begin
  chkRegistry.Checked     := False;
  chkRegistry.Parent      := vlistOptionalSub;
  lblRegistry.Parent      := vlistOptionalSub;
  pnlSpaceRegistry.Parent := vlistOptionalSub;
  lblRegistry.Caption     := _t('Resets the system registry settings relating to Windows Update. No problems or unusual settings were detected from your system but if Windows Update is not working, you should probably run this option.', 'updatefixer.registry-ok')
 end else
 begin
  chkRegistry.Checked     := True;
  chkRegistry.Parent      := vlistRecommendedSub;
  lblRegistry.Parent      := vlistRecommendedSub;
  pnlSpaceRegistry.Parent := vlistRecommendedSub;
  lblRegistry.Caption     := _t('Resets the system registry settings of all Windows Update related system services. Unusual registry settings were detected which might cause Windows Update to not work. Using this option is recommended.', 'updatefixer.registry-not-ok');
 end;


 // **
 // Services

 for i := Low(FServiceOKArr) to High(FServiceOKArr) do
 begin
   FServiceCheckboxes[i].Caption := _t('Re-enable service: {1}', 'updatefixer.services-re-enable', _x(ServiceDescsArrX[i]));

   if FServiceOKArr[i] then
   begin
    FServiceCheckboxes[i].Checked := False;
    FServiceCheckboxes[i].Parent  := vlistOptionalSub;
    FServiceLabels[i].Parent      := vlistOptionalSub;
    FServicePanels[i].Parent      := vlistOptionalSub;
    FServiceLabels[i].Caption     := _t('Resets the settings of Windows Update related system service called "{1}". No problems or unusual settings were detected but if Windows Update is not working, you should probably run this option.', 'updatefixer.services-ok', _x(ServiceDescsArrX[i]));
   end else
   begin
    AllServicesOK                 := False;
    FServiceCheckboxes[i].Checked := True;
    FServiceCheckboxes[i].Parent  := vlistRecommendedSub;
    FServiceLabels[i].Parent      := vlistRecommendedSub;
    FServicePanels[i].Parent      := vlistRecommendedSub;
    FServiceLabels[i].Caption     := _t('Resets the settings of Windows Update related system service called "{1}". Unusual system service settings were detected which might cause Windows Update to not work. Using this option is recommended.', 'updatefixer.services-not-ok', _x(ServiceDescsArrX[i]));
   end;
 end;


 // **
 // Hosts file

 if FHostsFileOK then
 begin
  chkHostsFile.Checked := False;
  chkHostsFile.Parent  := vlistOptionalSub;
  lblHostsFile.Parent  := vlistOptionalSub;
  pnlSpaceHosts.Parent := vlistOptionalSub;
  lblHostsFile.Caption := _t('Resets the Windows Hosts file to remove any Microsoft and Windows Update related entries. No problems or unusual settings were detected from your Hosts file, there is no need to run this.', 'updatefixer.hosts-ok')
 end else
 begin
  chkHostsFile.Checked := True;
  chkHostsFile.Parent  := vlistRecommendedSub;
  lblHostsFile.Parent  := vlistRecommendedSub;
  pnlSpaceHosts.Parent := vlistRecommendedSub;
  lblHostsFile.Caption := _t('Resets the Windows Hosts file to remove any Microsoft and Windows Update related entries. Unusual settings were detected which might cause Windows Update to not work. Using this option is recommended.', 'updatefixer.hosts-not-ok');
 end;




 // Lastly, set the PopupMenus:
 for i := 0 to FAllOptionControls.Count-1 do
 begin

  if FAllOptionControls[i].Parent = vlistRecommendedSub then
  begin

   if FAllOptionControls[i] is TLabel then
      TLabel(FAllOptionControls[i]).PopupMenu := PopupMenu_Rec
   else if FAllOptionControls[i] is TPanel then
      TPanel(FAllOptionControls[i]).PopupMenu := PopupMenu_Rec
   else if FAllOptionControls[i] is TPTZCheckBox then
      TPTZCheckBox(FAllOptionControls[i]).PopupMenu := PopupMenu_Rec;

  end else
  if FAllOptionControls[i].Parent = vlistOptionalSub then
  begin

   if FAllOptionControls[i] is TLabel then
      TLabel(FAllOptionControls[i]).PopupMenu := PopupMenu_Opt
   else if FAllOptionControls[i] is TPanel then
      TPanel(FAllOptionControls[i]).PopupMenu := PopupMenu_Opt
   else if FAllOptionControls[i] is TPTZCheckBox then
      TPTZCheckBox(FAllOptionControls[i]).PopupMenu := PopupMenu_Opt;
  end;

 end;


 // Case 1: No issues found
 if (FFreeSpaceOK) and
    (FDeliveryDirsOK) and
    (AllServicesOK) and
    (FHostsFileOK) and
    (FRegistryOK) and
    (FBlockersFound = False) then
 begin
  lblFixInfo.Caption := _t('Update Fixer was unable to find any problems from this system.', 'UpdateFixer.errors-none');

  FServiceCheckboxes[0].Checked := True;
  chkRegistry.Checked := True;

  if FPiratedWindows then imgNothing.Visible := False
  else imgNothing.Visible := True;

  vlistRecommendedSub.Visible := False;
  pnlNothing.Parent := vlistRecommended;
  pnlNothing.Visible := True;
  lblNothingToFix.Visible := True;
  lblNothingToFix.Caption := _t(
    'If Windows Update is not working in this system, you can still try to click the Fix button, which will essentially reset the Windows Update system in an attempt to fix it. ' +
    'If Windows Update is working, it is recommended that you not click the Fix button as there is nothing to do.', 'UpdateFixer.errors-none-extended');

 end

 // Case 2: Some issues found
 else
 begin
  pnlNothing.Visible := False;
  vlistRecommendedSub.Visible := True;

  lblFixInfo.Caption := _t('Update Fixer was able to find potential problems from this system. ' +
    'If Windows Update is not working, you should click the Fix button and let Update Fixer attempt to fix the problems. ' +
    'Do notice that Windows Update could be working even with these problems present in the system. If Windows Update is currently working, there is no need to use this program to fix anything.', 'UpdateFixer.errors-found');

 end;
 // FFreeSpaceOK       : Boolean;
 // FServicesOK        : Boolean;
 // FServiceOKArr      : Array[1 .. 6] of Boolean;
 // FRegistryOK        : Boolean;
 // FBlockersFound     : Boolean;


 UI_Setup_TabOrder();
 UI_IncProgress(True);

 lblFooter.Visible := False;
 lblFooter2.Visible := True;
 vlistAnalyze.Visible := False;
 vlistFix.Visible := True;
 pnlWaiting.Visible := False;
 UI_UpdateDynamicContent();


end;

procedure TMainForm.btnCloseClick(Sender: TObject);
begin
 {$IFDEF Debug_GenerateDebugLog} DebugLog('Button Click: Close');{$ENDIF}

 Application.Terminate;
end;

Function TMainForm.UI_AnyCheckboxChecked() : Boolean;
begin

 Result := (chkTempFiles.Checked) or
           (chkDeliverFiles.Checked) or
           (chkRegistry.Checked) or
           (chkBlockers.Checked) or
           (chkHostsFile.Checked) or
           (UI_AnyServiceCheckboxChecked());

end;

Function TMainForm.UI_AnyServiceCheckboxChecked() : Boolean;
Var
 i : Integer;
begin

 Result := False;

 for i := 0 to FServiceCheckboxes.Count-1 do
  if FServiceCheckboxes[i].Checked then
  begin
   Result := True;
   Break;
  end;

end;

procedure TMainForm.btnFixClick(Sender: TObject);
Var
 i : Integer;
begin

 {$IFDEF Debug_ShowProgress} lblHeader.Caption := 'Starting... '; Application.ProcessMessages; {$ENDIF}

 if UI_AnyCheckboxChecked() = False then
 begin
  ShowMessage(_t('Please choose at least one option!', 'updatefixer.error-nothing-select'));
  EXIT;
 end;


 {$IFDEF Debug_GenerateDebugLog} DebugLog('Button click: Fix'); {$ENDIF}
 if DebugHook <> 0 then
 begin
   vlistAnalyze.Visible := False;
   vlistFix.Visible     := False;
   vlistDone.Visible    := True;
   lblFooter.Visible    := False;
   lblFooter2.Visible   := True;
   pnlWaiting.Visible   := False;
   UI_UpdateDynamicContent();
   EXIT;
 end;


 lblWorking.WordWrap := False;
 lblWorking.AutoSize := True;
 lblWorking.Caption := _t('Fixing Windows Update, this can take up to five minutes. Please wait ...', 'UpdateFixer.working-fixing');

 btnFix.Visible  := False;
 FBatFile.Clear;
 vlistFix.Visible := False;
 pnlWaiting.Align := alClient;
 pnlWaiting.Visible := True;
 pnlWaiting.BringToFront;
 lblFooter.Visible := False;
 lblFooter2.Visible := False;
 ProgressBar.Value := 0;
 ProgressBar.MaxValue := 100;
 UI_UpdateDynamicContent();

 {$IFDEF Debug_ShowProgress} lblHeader.Caption := 'Progress: '; Application.ProcessMessages; {$ENDIF}
 {$IFDEF Debug_GenerateDebugLog} DebugLog('Fix Main Start');{$ENDIF}

 Try

   Try
     {$IFDEF Debug_GenerateDebugLog} DebugLog('Fix Start: Process_Init');{$ENDIF}
     Process_Init();
     UI_IncProgress();
     {$IFDEF Debug_ShowProgress} lblHeader.Caption := lblHeader.Caption +'a'; Application.ProcessMessages; {$ENDIF}
   except
    on E : Exception do
    begin
     {$IFDEF Debug_GenerateDebugLog} DebugLog('Process-Init-1 Exception: ' + E.Message); {$ENDIF}
     {$IFDEF Debug_ExceptionMessages} ShowMessage('Process-Init-1 Exception: ' + E.Message); {$ENDIF}
    End;
   end;

   Try
     {$IFDEF Debug_GenerateDebugLog} DebugLog('Fix Start: Process_Init_Pas');{$ENDIF}
     Process_Init_Pas();
     UI_IncProgress();
     {$IFDEF Debug_ShowProgress} lblHeader.Caption := lblHeader.Caption +'b'; Application.ProcessMessages; {$ENDIF}
   except
    on E : Exception do
    begin
     {$IFDEF Debug_GenerateDebugLog} DebugLog('Process-Init-2 Exception: ' + E.Message); {$ENDIF}
     {$IFDEF Debug_ExceptionMessages} ShowMessage('Process-Init-2 Exception: ' + E.Message); {$ENDIF}
    End;
   end;

   Try
     {$IFDEF Debug_GenerateDebugLog} DebugLog('Fix Start: Process_Init_Bat');{$ENDIF}
     Process_Init_Bat();
     UI_IncProgress();
     {$IFDEF Debug_ShowProgress} lblHeader.Caption := lblHeader.Caption +'c'; Application.ProcessMessages; {$ENDIF}
   except
    on E : Exception do
    begin
     {$IFDEF Debug_GenerateDebugLog} DebugLog('Process-Init-3 Exception: ' + E.Message); {$ENDIF}
     {$IFDEF Debug_ExceptionMessages} ShowMessage('Process-Init-3 Exception: ' + E.Message); {$ENDIF}
    End;
   end;

   Try
     {$IFDEF Debug_GenerateDebugLog} DebugLog('Fix Start: Process_Init_PS');{$ENDIF}
     Process_Init_PS();
     UI_IncProgress();
     {$IFDEF Debug_ShowProgress} lblHeader.Caption := lblHeader.Caption +'d'; Application.ProcessMessages; {$ENDIF}
   except
    on E : Exception do
    begin
     {$IFDEF Debug_GenerateDebugLog} DebugLog('Process-Init-4 Exception: ' + E.Message); {$ENDIF}
     {$IFDEF Debug_ExceptionMessages} ShowMessage('Process-Init-4 Exception: ' + E.Message); {$ENDIF}
    End;
   end;


   // ** ** ** ** ** ** ** ** ** **
   // ** ** ** ** ** ** ** ** ** **

   Try
    if chkDeliverFiles.Checked then
    begin
      {$IFDEF Debug_GenerateDebugLog} DebugLog('Fix Start: Process_Delivery_Files');{$ENDIF}
      Process_Delivery_Files();
    end {$IFDEF Debug_GenerateDebugLog} else DebugLog('Fix SKIP: Process_Delivery_Files');{$ELSE} ; {$ENDIF}

    UI_IncProgress();
    {$IFDEF Debug_ShowProgress} lblHeader.Caption := lblHeader.Caption +'e'; Application.ProcessMessages; {$ENDIF}
   except
    on E : Exception do
    begin
     {$IFDEF Debug_GenerateDebugLog} DebugLog('Process-1 Exception: ' + E.Message); {$ENDIF}
     {$IFDEF Debug_ExceptionMessages} ShowMessage('Process-1 Exception: ' + E.Message); {$ENDIF}
    End;
   end;

   Try
     if chkRegistry.Checked then
     begin
      {$IFDEF Debug_GenerateDebugLog} DebugLog('Fix Start: Process_Registry');{$ENDIF}
      Process_Registry();
     end {$IFDEF Debug_GenerateDebugLog} else DebugLog('Fix SKIP: Process_Registry');{$ELSE} ; {$ENDIF}

     UI_IncProgress();
     {$IFDEF Debug_ShowProgress} lblHeader.Caption := lblHeader.Caption +'f'; Application.ProcessMessages; {$ENDIF}
   except
    on E : Exception do
    begin
     {$IFDEF Debug_GenerateDebugLog} DebugLog('Process-2 Exception: ' + E.Message); {$ENDIF}
     {$IFDEF Debug_ExceptionMessages} ShowMessage('Process-2 Exception: ' + E.Message); {$ENDIF}
    End;
   end;

   Try

     if UI_AnyServiceCheckboxChecked() then
     begin
      {$IFDEF Debug_GenerateDebugLog} DebugLog('Fix Start: Process_Services');{$ENDIF}
      Process_Services();
     end {$IFDEF Debug_GenerateDebugLog} else DebugLog('Fix SKIP: Process_Services');{$ELSE} ; {$ENDIF}

     UI_IncProgress();
     {$IFDEF Debug_ShowProgress} lblHeader.Caption := lblHeader.Caption +'g'; Application.ProcessMessages; {$ENDIF}
   except
    on E : Exception do
    begin
     {$IFDEF Debug_GenerateDebugLog} DebugLog('Process-3 Exception: ' + E.Message); {$ENDIF}
     {$IFDEF Debug_ExceptionMessages} ShowMessage('Process-3 Exception: ' + E.Message); {$ENDIF}
    End;
   end;


   Try

    if chkHostsFile.Checked then
    begin
     {$IFDEF Debug_GenerateDebugLog} DebugLog('Fix Start: Process_HostsFile');{$ENDIF}
     Process_HostsFile();
    end {$IFDEF Debug_GenerateDebugLog} else DebugLog('Fix Start: Process_HostsFile');{$ELSE} ; {$ENDIF}

    UI_IncProgress();
    {$IFDEF Debug_ShowProgress} lblHeader.Caption := lblHeader.Caption +'i'; Application.ProcessMessages; {$ENDIF}
   except
    on E : Exception do
    begin
     {$IFDEF Debug_GenerateDebugLog} DebugLog('Process-4 Exception: ' + E.Message); {$ENDIF}
     {$IFDEF Debug_ExceptionMessages} ShowMessage('Process-4 Exception: ' + E.Message); {$ENDIF}
    End;
   end;

   Try
    if chkTempFiles.Checked then
    begin
     {$IFDEF Debug_GenerateDebugLog} DebugLog('Fix Start: Process_Temporary_Files');{$ENDIF}
     Process_Temporary_Files();
    end {$IFDEF Debug_GenerateDebugLog} else DebugLog('Fix Start: Process_Temporary_Files');{$ELSE} ; {$ENDIF}

    UI_IncProgress();
    {$IFDEF Debug_ShowProgress} lblHeader.Caption := lblHeader.Caption +'j'; Application.ProcessMessages; {$ENDIF}
   except
    on E : Exception do
    begin
     {$IFDEF Debug_GenerateDebugLog} DebugLog('Process-5 Exception: ' + E.Message); {$ENDIF}
     {$IFDEF Debug_ExceptionMessages} ShowMessage('Process-5 Exception: ' + E.Message); {$ENDIF}
    End;
   end;

   Try
     {$IFDEF Debug_ShowProgress} lblHeader.Caption := 'Finalizing...'; Application.ProcessMessages; {$ENDIF}
     {$IFDEF Debug_GenerateDebugLog} DebugLog('Fix Start: Process_Finalize');{$ENDIF}
     Process_Finalize();
     UI_IncProgress(True);
     {$IFDEF Debug_ShowProgress} lblHeader.Caption := 'All done!'; Application.ProcessMessages; {$ENDIF}
   except
    on E : Exception do
    begin
     {$IFDEF Debug_GenerateDebugLog} DebugLog('Process-Finalize Exception: ' + E.Message); {$ENDIF}
     {$IFDEF Debug_ExceptionMessages} ShowMessage('Process-Finalize Exception: ' + E.Message); {$ENDIF}
    End;
   end;

 Finally
   vlistAnalyze.Visible := False;
   vlistFix.Visible     := False;
   vlistDone.Visible    := True;
   lblFooter.Visible    := False;
   lblFooter2.Visible   := True;
   pnlWaiting.Visible   := False;
   UI_UpdateDynamicContent();
 End;

 {$IFDEF Debug_GenerateDebugLog} DebugLog('Fix Main Done');{$ENDIF}

end;

procedure TMainForm.btnWinCloseClick(Sender: TObject);
begin
 Application.Terminate;
end;

procedure TMainForm.chkTempFilesKeyUp(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
 UI_UpdateSelectionCounts();
end;

procedure TMainForm.chkTempFilesMouseUp(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
begin
 UI_UpdateSelectionCounts();
end;


// Sleep in a way the UI doesn't appear non responsive.
// Simply doing Sleep(5000) would make Windows display 'application not responding' error to the user
Procedure TMainForm.UI_Sleep(const SleepyTimeMSEC : Integer);
Var
 x : Integer;
begin

 x := SleepyTimeMSEC div 400;
 if x < 1 then x := 1;

 while x > 0 do
 begin
  Dec(x);
  Sleep(400);
  Application.ProcessMessages;
 end;

end;


// Increases the progress shown to the user in the UI
Procedure TMainForm.UI_IncProgress(const AllDone : Boolean = False);
Var
 i : Integer;
 x : Integer;
begin

 ProgressBar.Value := ProgressBar.Value +2;
 FTaskbarHelper.SetProgressState(2);
 FTaskbarHelper.SetProgressValue(ProgressBar.Value, ProgressBar.MaxValue);

 Application.ProcessMessages;

  if AllDone then
  begin
   x := (ProgressBar.MaxValue-ProgressBar.Value) div 5;
   if x < 1 then x := 1;

   for i := 1 to 5 do
   begin
    ProgressBar.Value := ProgressBar.Value + x;
    FTaskbarHelper.SetProgressValue(ProgressBar.Value, ProgressBar.MaxValue);
    Application.ProcessMessages;
   end;

   ProgressBar.Value := ProgressBar.MaxValue;
   FTaskbarHelper.SetProgressValue(ProgressBar.Value, ProgressBar.MaxValue);

   Application.ProcessMessages;
   FTaskbarHelper.SetProgressState(0); // not running
  end;

end;

//Creates a mutex to see if the program is already running.
function TMainForm.CreateMutexDo(MutexName : string; ReleaseMutexAfter : Boolean) : Boolean;
const MUTEX_GLOBAL = 'Global\'; //Prefix to explicitly create the object in the global or session namespace. I.e. both client app (local user) and service (system account)

var MutexHandel : THandle;
    SecurityDesc: TSecurityDescriptor;
    SecurityAttr: TSecurityAttributes;
    ErrCode : integer;
begin
  //  By default (lpMutexAttributes =nil) created mutexes are accessible only by
  //  the user running the process. We need our mutexes to be accessible to all
  //  users, so that the mutex detection can work across user sessions.
  //  I.e. both the current user account and the System (Service) account.
  //  To do this we use a security descriptor with a null DACL.
  InitializeSecurityDescriptor(@SecurityDesc, SECURITY_DESCRIPTOR_REVISION);
  SetSecurityDescriptorDacl(@SecurityDesc, True, nil, False);
  SecurityAttr.nLength:=SizeOf(SecurityAttr);
  SecurityAttr.lpSecurityDescriptor:=@SecurityDesc;
  SecurityAttr.bInheritHandle:=False;

  //  The mutex is created in the global name space which makes it possible to
  //  access across user sessions.
  MutexHandel := CreateMutex(@SecurityAttr, True, PChar(MUTEX_GLOBAL + MutexName));
  ErrCode := GetLastError;

  //  If the function fails, the return value is 0
  //  If the mutex is a named mutex and the object existed before this function
  //  call, the return value is a handle to the existing object, GetLastError
  //  returns ERROR_ALREADY_EXISTS.
  if (ErrCode = ERROR_ALREADY_EXISTS) then
  begin
    result := false;
    closeHandle(MutexHandel);
  end
  else
  begin
    //  Mutex object has not yet been created, meaning that no previous
    //  instance has been created.
    result := true;

    If ReleaseMutexAfter then closeHandle(MutexHandel);
  end;

  // The Mutexhandle is not closed because we want it to exist during the
  // lifetime of the application. The system closes the handle automatically
  // when the process terminates.
end;


{$IFDEF Debug_GenerateDebugLog}
Procedure TMainForm.DebugLog(const Str : String);
begin

 FDebugLog.Add('[' + IntToStr(GetTickCount) + ']: ' + Str);
 if FastPosExB('Exception', Str) or
    FastPosExB('Start:', Str) or
    FastPosExB('Click:', Str) then FDebugLog.Add('');

 Try
  If (FTempDir <> '') and
     (FDesktopDir <> '') then
  begin
   if FDebugLogFile = '' then FDebugLogFile := 'upd_fixer_debug_' + IntToStr(GetTickCount)+ '.log';
   FDebugLog.SaveToFile(FDesktopDir + FDebugLogFile, TEncoding.UTF8);
  end;
 Except
  ;
 End;

end;
{$ENDIF}

procedure TMainForm.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
 {$IFDEF Debug_GenerateDebugLog} DebugLog('Close'); {$ENDIF}
end;

procedure TMainForm.FormCreate(Sender: TObject);
begin

 // Start hidden:
 Self.AlphaBlend := True;
 Self.AlphaBlendValue := 0;
 Self.BorderStyle := bsNone;
 Self.KeyPreview := True;
 Self.DoubleBuffered := True;
 FLastTmrShowRun := GetTickCount64();
 FLastTmrStarted := FLastTmrShowRun;
 tmrShow.Enabled := False;
 tmrUpdateUiSelections.Enabled := False;
 FUISelUpdLock := False;
 FPriviledgeSet := False;


 if CreateMutexDo('updatefixer', False) = False then
 begin
  Application.Terminate;
  EXIT;
 end;

 FCheckboxes        := TList<TPTZCheckBox>.Create;
 FServiceCheckboxes := TList<TPTZCheckBox>.Create;
 FServiceLabels     := TList<TLabel>.Create;
 FServicePanels     := TList<TPanel>.Create;
 FAllOptionControls := TList<TControl>.Create;
 FTransStringsCache := TDictionary<String,String>.Create;
 FTransHashesCache  := TDictionary<String,String>.Create;
 FEnvVars           := TDictionary<String,String>.Create;
 FXStrings          := TDictionary<String,String>.Create;
 FExistsCache       := TDictionary<String, Boolean>.Create;
 FTaskbarHelper     := TWinTaskbar.Create;
 FBatFile           := TStringList.Create;
 FBlockerRemoval    := TStringList.Create;
 FRegIniFilename    := '';
 FTempDir           := '';
 FDesktopDir        := '';
 FDebugLogFile      := '';
 FUI_AutoPos        := True;
 FCmdResultFile     := '';

 FMIN_APP_HEIGHT    := 400;
 FMIN_APP_WIDTH     := 400;
 FMAX_APP_WIDTH     := Min(1000, Round(MainForm.Monitor.Width * 0.8));

 FDebugLog := TStringList.Create;
 FDebugLog.Add('Init');

 vlistHolder.Visible := False;
 pnlMainParent.Align := alClient;

 vlistAnalyze.Parent := pnlMainParent;
 vlistFix.Parent     := pnlMainParent;
 vlistDone.Parent    := pnlMainParent;

 vlistAnalyze.Visible := True;
 vlistFix.Visible := False;
 vlistDone.Visible := False;

 vlistAnalyze.AlignWithMargins := True;
 vlistFix.AlignWithMargins := True;
 vlistDone.AlignWithMargins := True;

 vlistAnalyze.Margins.Left   := 20;
 vlistAnalyze.Margins.Right  := 20;
 vlistAnalyze.Margins.Bottom := 0;
 vlistAnalyze.Margins.Top    := 5;

 vlistFix.Margins.Left   := 20;
 vlistFix.Margins.Right  := 20;
 vlistFix.Margins.Bottom := 0;
 vlistFix.Margins.Top    := 5;

 vlistDone.Margins.Left   := 20;
 vlistDone.Margins.Right  := 20;
 vlistDone.Margins.Bottom := 0;
 vlistDone.Margins.Top    := 5;

 vlistAnalyze.Align := alTop;
 vlistFix.Align := alTop;
 vlistDone.Align := alTop;

 pnlWaiting.Caption := '';
 pnlWaiting.Visible := False;
 pnlWaiting.Parent := pnlMainParent;
 pnlWaiting.AlignWithMargins := True;
 pnlWaiting.Margins.Left   := 5;
 pnlWaiting.Margins.Top    := 5;
 pnlWaiting.Margins.Bottom := 5;
 pnlWaiting.Margins.Right  := 5;
 ProgressBar.Height := 5;

 Init_AppDirs();
 Init_LoadColorScheme();
 Init_Translation();
 Init_CheckBoxes();
 Init_ServiceLists();


 lblAnalyze.Caption := _t('Update Fixer is a freeware app that attempts to automatically fix Windows Update.', 'UpdateFixer.analyze-info1')

  +' '+#13#10+#13#10+ _t('Click the Analyze button to check whether Update Fixer can find any problems from your Windows Update.', 'UpdateFixer.analyze-info2')
  +' '+#13#10+#13#10+ _t('No changes to your system are made during the analysis and this app does not send any data to anywhere.', 'UpdateFixer.analyze-info3')
  +' '+#13#10+#13#10+ _t('We have worked hard to make this app work perfectly, but things can go wrong. ' +
                         'Therefore, please create a System Restore Point before applying any fixes. Thanks!', 'UpdateFixer.analyze-info4');

 lblFooter.Caption := _t('Version: {1}<br>(Click to check what is the latest version)', 'UpdateFixer.version-ex', APP_VERSION);
 lblFooter.Hint := _t('Click to check whether you are running the latest version of Update Fixer', 'UpdateFixer.hint-check-ver');


 lblCaptMain.Caption          := _t('Analysis finished', 'UpdateFixer.analysis-done');
 lblCaptMain.Font.Size        := MainForm.Font.Size + 6;
 lblCaptRecommended.Font.Size := lblCaptMain.Font.Size;
 lblCaptOptional.Font.Size    := lblCaptMain.Font.Size;

 pnlThanks.Height := 150; // note: it can display a privacy warning, too!
 lblDone.AlignWithMargins := True;
 lblDone.Margins.Left   := 10;
 lblDone.Margins.Right  := 10;
 lblDone.Margins.Top    := 10;
 lblDone.Margins.Bottom := 10;

 imgConfused.ShowHint := True;
 imgConfused.Hint := 'Confused cat is confused';

 lblFooter2.Caption  := 'WinUpdateFixer.com';
 lblFooter2.Visible  := False;
 lblFooter2.ShowHint := True;
 lblFooter2.Hint     := imgLogoSmall.Hint;

 lblDone.Caption   := _t('The first step of fixing is now done! '+
  'You must restart your computer to ensure all the changes are applied.', 'UpdateFixer.all-done-reboot');

 lblDone.Font.Size := MainForm.Font.Size+2;
 lblDone2.Caption   := _t('After your computer restarts, you might see a Command Prompt window. This is normal, it is used for the final step of the fixing process.', 'UpdateFixer.all-done-reboot');


 lblThanks.Caption := _t('This program is freeware. If you found this program useful, please share the word so others can use it, too.'+'<br><br>Thank you and have a nice day!', 'UpdateFixer.thanks');
 lblBackup.Caption := _t('Please create a System Restore Point if you proceed to fix anything!', 'UpdateFixer.do-backup');

 UI_UpdateDynamicContent();

end;

Function TMainForm.HasAttrib(const Filename : String; Attr : Integer) : Boolean;
begin
 Result := False;

 Try
  Result := (FileGetAttr(FileName) and Attr) > 0;
 Except
  ;
 End;

end;

Procedure TMainForm.UI_Setup_TabOrder();
Var
 i : Integer;
 x : Integer;
begin

 for i := 0 to FCheckboxes.Count-1 do
 begin
  if (FCheckboxes[i].Enabled = False) or
     (FCheckboxes[i].Visible = False) then
  begin
   FCheckboxes[i].TabStop := False;
   Continue;
  end;

  FCheckboxes[i].TabStop := True;
  x := FCheckboxes[i].Tag;

  if FCheckboxes[i].Parent = vlistOptionalSub then x := x + 2000;
  FCheckboxes[i].TabOrder := x;
 end;

 btnAnalyze.TabStop := True;
 btnFix.TabStop := True;
 btnAnalyze.TabOrder := 9999;
 btnFix.TabOrder := 9999;


end;


procedure TMainForm.tmrUpdateUiSelectionsTimer(Sender: TObject);
begin
 tmrUpdateUiSelections.Enabled := False;
 UI_UpdateSelectionCounts_DO();
end;

Procedure TMainForm.UI_UpdateSelectionCounts();
begin
 UI_UpdateSelectionCounts_DO();
 tmrUpdateUiSelections.Enabled := True;
end;

Procedure TMainForm.UI_UpdateSelectionCounts_DO();
Var
 i     : Integer;
 iRecC : Integer;
 iOptC : Integer;
 iRecS : Integer;
 iOptS : Integer;
begin

 if vlistFix.Visible = False then EXIT;
 if FUISelUpdLock then EXIT;
 FUISelUpdLock := True;

 Try
   iRecC := 0;
   iOptC := 0;
   iRecS := 0;
   iOptS := 0;

   for i := 0 to FCheckboxes.Count-1 do
   begin
    if (FCheckboxes[i].Visible = False) or
       (FCheckboxes[i].Enabled = False) then Continue;

    if FCheckboxes[i].Parent = vlistRecommendedSub then
    begin
     Inc(iRecC);
     if FCheckboxes[i].Checked then Inc(iRecS);
    end
    else if FCheckboxes[i].Parent = vlistOptionalSub then
    begin
     Inc(iOptC);
     if FCheckboxes[i].Checked then Inc(iOptS);
    end;
   end;

   if iRecC = 0 then
        lblCaptRecommended.Caption := _t('Recommended fixes: None', 'UpdateFixer.recommended-fixes-none')
   else
     lblCaptRecommended.Caption := _t('Recommended fixes: {1} selected out of {2}', 'UpdateFixer.recommended-fixes-x', [IntToStr(iRecS), IntToStr(iRecC)]);

   lblCaptOptional.Caption := _t('Optional fixes: {1} selected out of {2}', 'UpdateFixer.optional-fixes-x', [IntToStr(iOptS), IntToStr(iOptC)]);

 Finally
  FUISelUpdLock := False;
 End;
end;

Procedure TMainForm.UI_UpdateDynamicContent();
Var
 i    : Integer;
 iVal : Integer;
begin

 {$IFDEF Debug_Colors}
 MainForm.Color := clRed;
 pnlMainParent.Color := clPurple;
 vlistRecommended.Color := clGreen;
 vlistOptional.Color := clBlue;
 vlistAnalyze.Color := clBlue;
 vlistFix.Color := clGray;
 {$ENDIF}

 UI_UpdateSelectionCounts();

 if MainForm.Monitor.Width > 2000 then iVal := 1000
 else if MainForm.Monitor.Width > 1000 then iVal := 900
 else if MainForm.Monitor.Width > 900 then iVal := 800
 else if MainForm.Monitor.Width > 700 then iVal := 700
 else iVal := 600;

 if vlistDone.Visible or
    pnlWaiting.Visible or
    vlistAnalyze.Visible then
 begin
  iVal := iVal - 300;
  if iVal < 600 then iVal := 600;
 End;

 if iVal < FMIN_APP_WIDTH then iVal := FMIN_APP_WIDTH;
 if iVal > FMAX_APP_WIDTH then iVal := FMAX_APP_WIDTH;
 MainForm.Width := iVal;



 if pnlNothing.Visible then ScrollBox1.Visible := False
 else ScrollBox1.Visible := True;

 if MainForm.Monitor.Height > 2500 then iVal := 400
 else if MainForm.Monitor.Height > 2000 then iVal := 350
 else if MainForm.Monitor.Height > 1800 then iVal := 300
 else if MainForm.Monitor.Height > 1200 then iVal := 250
 else iVal := 200;

 if ScrollBox1.Visible and ScrollBox2.Visible then iVal := iVal div 2
 else iVal := iVal +50;

 ScrollBox1.Height := iVal;
 ScrollBox2.Height := iVal;

 // save some space:
 if (MainForm.Monitor.Height < 2000) and
    (vlistFix.Visible) and
    (ScrollBox1.Visible) and
    (ScrollBox2.Visible) then
 begin
  lblFooter.Visible  := False;
  lblFooter2.Visible := False;
 end;



 lblHeader.AutoSize := True;
 lblHeader.WordWrap := False;
 lblHeader.Top  := pnlWindowTitle.Height div 2 - lblHeader.Height div 2;
 lblHeader.Left := MainForm.Width div 2 - lblHeader.Width div 2;

 SetLabelHeight(lblCaptRecommended);
 SetLabelHeight(lblCaptOptional);
 SetLabelHeight(lblCaptMain);

 SetLabelHeight(lblAnalyze, 300);
 SetLabelHeight(lblBackup);
 SetLabelHeight(lblThanks);
 SetLabelHeight(lblDone);
 SetLabelHeight(lblDone2);

 SetLabelHeight(lblFixInfo);
 SetLabelHeight(lblFooter);
 SetLabelHeight(lblFooter2);

 SetLabelHeight(lblTempFiles, 30);
 SetLabelHeight(lblDeliveryFiles, 30);
 SetLabelHeight(lblBlockers, 30);
 SetLabelHeight(lblRegistry, 30);
 For i := 0 to FServiceLabels.Count-1 do SetLabelHeight(FServiceLabels[i], 30);
 SetLabelHeight(lblHostsFile, 30);


 If vlistAnalyze.Visible then
 begin
  vlistAnalyze.Top := pnlWindowTitle.Top + pnlWindowTitle.Height; // ensure window controls remain at the top
  vlistAnalyze.AdjustControls(True);
  iVal := vlistAnalyze.Height;

 end else
 If vlistFix.Visible then
 begin
  vlistRecommendedSub.AdjustControls(True);
  vlistOptionalSub.AdjustControls(True);
  vlistOptional.AdjustControls(True);
  vlistRecommended.AdjustControls(True);

  vlistFix.Top := pnlWindowTitle.Top + pnlWindowTitle.Height; // ensure window controls remain at the top
  vlistFix.AdjustControls(True);
  iVal := vlistFix.Height;

 end else
 if vlistDone.Visible then
 begin
  vlistDone.Top := pnlWindowTitle.Top + pnlWindowTitle.Height; // ensure window controls remain at the top
  vlistDone.AdjustControls(True);
  iVal := vlistDone.Height;
 End;

 iVal := iVal + pnlMainParent.Margins.Top + pnlMainParent.Margins.Bottom;
 iVal := iVal + pnlWindowTitle.Height;
 if lblFooter.Visible  then iVal := iVal + 10 + lblFooter.Height  + lblFooter.Margins.Top  + lblFooter.Margins.Bottom;
 if lblFooter2.Visible then iVal := iVal + 10 + lblFooter2.Height + lblFooter2.Margins.Top + lblFooter2.Margins.Bottom;
 iVal := iVal + 10;
 if MainForm.Monitor.Height > 1800 then iVal := iVal + 50;


 if iVal < FMIN_APP_HEIGHT then iVal := FMIN_APP_HEIGHT;
 MainForm.Height := iVal;


 if FUI_AutoPos then
 begin
  MainForm.Left := MainForm.Monitor.Width  div 2 - MainForm.Width  div 2;
  MainForm.Top  := MainForm.Monitor.Height div 2 - MainForm.Height div 2;
 end;

 if pnlWaiting.Visible then
 begin
  ProgressBar.Width := MainForm.Width div 2;
  ProgressBar.Left := pnlWaiting.Width div 2 - ProgressBar.Width div 2;

 if imgSpinner_DM_128.Visible then
 begin
  imgSpinner_DM_128.Left := pnlWaiting.Width  div 2 - imgSpinner_DM_128.Width div 2;
  imgSpinner_DM_128.Top  := pnlWaiting.Height div 2 - imgSpinner_DM_128.Height div 2 - pnlWindowTitle.Height - 10;
  ProgressBar.Top        := imgSpinner_DM_128.Top + imgSpinner_DM_128.Height + 30;
 end else
 if imgSpinner_NM_128.Visible then
 begin
  imgSpinner_NM_128.Left := pnlWaiting.Width  div 2 - imgSpinner_NM_128.Width div 2;
  imgSpinner_NM_128.Top  := pnlWaiting.Height div 2 - imgSpinner_NM_128.Height div 2 - pnlWindowTitle.Height - 10;
  ProgressBar.Top        := imgSpinner_NM_128.Top + imgSpinner_NM_128.Height + 30;
 end;

  lblWorking.Left := pnlWaiting.Width div 2 - lblWorking.Width div 2;
  lblWorking.Top  := ProgressBar.Top + ProgressBar.Height + 30;
 end;

end;

procedure TMainForm.FormKeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin

 // Enter:
 if (Key = 13) and ((Shift = [ssShift]) or (Shift = [ssCtrl])) then
 begin
  If vlistAnalyze.Visible then btnAnalyze.OnClick(btnAnalyze)
  else If vlistFix.Visible then btnFix.OnClick(btnFix)
  else If vlistDone.Visible then btnReboot.OnClick(btnReboot);
 End;

 // Esc:
 if (Key = 27) then Application.Terminate;

end;

procedure TMainForm.FormMouseWheel(Sender: TObject; Shift: TShiftState;
  WheelDelta: Integer; MousePos: TPoint; var Handled: Boolean);
Var
 iVal : Integer;
begin

 Handled := True;

 if vlistFix.Visible then
 begin
  iVal := Abs(WheelDelta);
  if iVal <  1 then iVal := 1;
  if iVal > 20 then iVal := 20;

  if (pnlNothing.Visible) or
     (MousePos.Y >
        MainForm.Top +
        pnlMainParent.Top +
        vlistFix.Top +
        vlistRecommended.Top +
        ScrollBox1.Top +
        vlistRecommended.Height) then
  begin

    if WheelDelta > 0 then
         ScrollBox2.VertScrollBar.Position := ScrollBox2.VertScrollBar.Position - iVal
    else ScrollBox2.VertScrollBar.Position := ScrollBox2.VertScrollBar.Position + iVal;

  end else
  begin

    if WheelDelta > 0 then
         ScrollBox1.VertScrollBar.Position := ScrollBox1.VertScrollBar.Position - iVal
    else ScrollBox1.VertScrollBar.Position := ScrollBox1.VertScrollBar.Position + iVal;

  end;
 end;


end;

procedure TMainForm.SelectAll1Click(Sender: TObject);
Var
 i       : Integer;
 iTag    : Integer;
 bSelect : Boolean;
 Target  : TGUIPanelVList;
begin

 iTag := (Sender as TMenuItem).Tag;
 bSelect := (iTag = 1) or (iTag = 3);
 if (iTag = 1) or (iTag = 2) then Target := vlistRecommendedSub
 else Target := vlistOptionalSub;

 {$IFDEF Debug_GenerateDebugLog} DebugLog('Menu click: ' + (Sender as TMenuItem).Caption); {$ENDIF}

 for i := 0 to FCheckboxes.Count-1 do
 begin
  if (FCheckboxes[i].Visible = False) or
     (FCheckboxes[i].Enabled = False) then Continue;

  if FCheckboxes[i].Parent = Target then
     FCheckboxes[i].Checked := bSelect;
 end;

 Application.ProcessMessages;
 UI_UpdateSelectionCounts();

end;

Procedure TMainForm.SetLabelHeight(const Lbl : TLabel; const ExtraMargin : Integer = 0);
Var
 x    : Integer;
 iRes : Integer;
Begin

 Try
   lblDebug.Font.Assign(Lbl.Font);
   lblDebug.AutoSize := True;
   lblDebug.WordWrap := False;
   lblDebug.Caption  := Lbl.Caption;
   lblDebug.Invalidate;

   if lblDebug.Width > vlistAnalyze.Width then
   begin
    x := Round(lblDebug.Width / vlistAnalyze.Width);
    if x < 2 then x := 2;

    lblDebug.Caption := 'Foobar';
    lblDebug.Invalidate;
    iRes := lblDebug.Height * x;
   end else iRes := lblDebug.Height;

   iRes := Round(iRes) + ExtraMargin;
   if iRes < 15 then iRes := 15;

   Lbl.AutoSize := False;
   Lbl.WordWrap := True;
   Lbl.Height := iRes;
 except
  {$IFDEF Debug_ExceptionMessages}on E : Exception do ShowMessage('SetLabelHeight Exception: ' + E.Message); {$ENDIF}
 end;

End;

procedure TMainForm.Init_CheckBoxes();
Var
 i : Integer;
begin

 FCheckboxes.Add(chkTempFiles);
 FCheckboxes.Add(chkDeliverFiles);
 FCheckboxes.Add(chkHostsFile);
 FCheckboxes.Add(chkRegistry);
 FCheckboxes.Add(chkBlockers);
 
 FCheckboxes.Add(chkService0);
 FCheckboxes.Add(chkService1);
 FCheckboxes.Add(chkService2);
 FCheckboxes.Add(chkService3);
 FCheckboxes.Add(chkService4);
 FCheckboxes.Add(chkService5);

 for i := 0 to FCheckboxes.Count-1 do
 begin
  FCheckboxes[i].PTZAutoSize := ptzHeight;
  FCheckboxes[i].ParentColor := False;
  FCheckboxes[i].ParentFont  := False;
  FCheckboxes[i].Font.Name   := MainForm.Font.Name;
  FCheckboxes[i].Font.Color  := Color_MainFont;
  FCheckboxes[i].Color       := Color_MainBack;
  FCheckboxes[i].Checked     := False;
  FCheckboxes[i].AdjustAutoSize();

  if Assigned(FCheckboxes[i].OnMouseUp) = False then
  begin
   FCheckboxes[i].OnMouseUp := chkTempFiles.OnMouseUp;
   FCheckboxes[i].OnKeyUp   := chkTempFiles.OnKeyUp;
  end;

 end;

end;

procedure TMainForm.Init_ServiceLists();
Var
 i : Integer;
begin

 FServiceCheckboxes.Add(chkService0);
 FServiceCheckboxes.Add(chkService1);
 FServiceCheckboxes.Add(chkService2);
 FServiceCheckboxes.Add(chkService3);
 FServiceCheckboxes.Add(chkService4);
 FServiceCheckboxes.Add(chkService5);

 FServiceLabels.Add(lblService0);
 FServiceLabels.Add(lblService1);
 FServiceLabels.Add(lblService2);
 FServiceLabels.Add(lblService3);
 FServiceLabels.Add(lblService4);
 FServiceLabels.Add(lblService5);

 FServicePanels.Add(pnlSpaceService0);
 FServicePanels.Add(pnlSpaceService1);
 FServicePanels.Add(pnlSpaceService2);
 FServicePanels.Add(pnlSpaceService3);
 FServicePanels.Add(pnlSpaceService4);
 FServicePanels.Add(pnlSpaceService5);

 for i := 0 to FServiceCheckboxes.Count-1 do FAllOptionControls.Add(FServiceCheckboxes[i]);
 for i := 0 to FServiceLabels.Count-1 do FAllOptionControls.Add(FServiceLabels[i]);
 for i := 0 to FServicePanels.Count-1 do FAllOptionControls.Add(FServicePanels[i]);

 FAllOptionControls.Add(chkTempFiles);
 FAllOptionControls.Add(lblTempFiles);
 FAllOptionControls.Add(pnlSpaceTmp);

 FAllOptionControls.Add(chkDeliverFiles);
 FAllOptionControls.Add(lblDeliveryFiles);
 FAllOptionControls.Add(pnlSpaceDelivery);

 FAllOptionControls.Add(chkHostsFile);
 FAllOptionControls.Add(lblHostsFile);
 FAllOptionControls.Add(pnlSpaceHosts);

 FAllOptionControls.Add(chkBlockers);
 FAllOptionControls.Add(lblBlockers);
 FAllOptionControls.Add(pnlSpaceBlock);

 FAllOptionControls.Add(chkRegistry);
 FAllOptionControls.Add(lblRegistry);
 FAllOptionControls.Add(pnlSpaceRegistry);

end;

procedure TMainForm.Init_AppDirs();
begin

 Try
   FAppDir := ExtractFilePath(Application.ExeName);
   if (DebugHook <> 0) and (FAppDir.EndsWith('\debug\', True)) then FAppDir := UpOneDir(UpOneDir(FAppDir));

   if FastPosExB('jv16', FAppDir) then FPTAppDir := FAppDir
   else FPTAppDir := 'C:\Program Files (x86)\jv16 PowerTools\';

   if (FPTAppDir <> '') and (FileExists(FPTAppDir + 'jv16pt.exe') = False) then FPTAppDir := '';

   FDebugDir := ExpandEnvVariable('%USERPROFILE%') + '\Desktop\';

   FAllUserProfile := ExpandEnvVariable('%ALLUSERSPROFILE%');
 except
  {$IFDEF Debug_ExceptionMessages}on E : Exception do ShowMessage('Init_AppDirs Exception: ' + E.Message); {$ENDIF}
 end;

 // If DEBUG_PT_DETECT_MESSAGES then ShowMessage('Init_AppDirs AppDir: ' + FAppDir + #13#10 + 'PTDir: ' + FPTAppDir);

end;

Function TMainForm.Init_Read_PT_DarkMode_Setting() : Integer;
Var
 ConfigDir : String;
 IniFile   : TMemIniFile;
begin
 Result := 1;

 if FPTAppDir = '' then EXIT;
 ConfigDir := FPTAppDir + 'Settings\';

 if DirectoryExists(ConfigDir) = False then EXIT;
 if FileExists(ConfigDir + 'Settings.dat') = False then EXIT;

 IniFile := TMemIniFile.Create(ConfigDir + 'Settings.dat');
 Result := IniFile.ReadInteger('UserInterface', 'ColorMode', 1);
 IniFile.Free;

end;


procedure TMainForm.lblBlockersClick(Sender: TObject);
begin
 chkBlockers.Checked := not chkBlockers.Checked;
end;

procedure TMainForm.lblDeliveryFilesClick(Sender: TObject);
begin
 chkDeliverFiles.Checked := not chkDeliverFiles.Checked;
end;

procedure TMainForm.lblFooter2MouseEnter(Sender: TObject);
begin
 lblFooter2.Font.Color := Color_LinkActive;
 lblFooter2.Font.Style := [TFontStyle.fsUnderline];

end;

procedure TMainForm.lblFooter2MouseLeave(Sender: TObject);
begin
 lblFooter2.Font.Color := Color_MainFont;
 lblFooter2.Font.Style := [];

end;

procedure TMainForm.lblFooterClick(Sender: TObject);
const
 URL = 'https://winupdatefixer.com/version.php?v=';

Var
 x        : Integer;
 FinalURL : String;
 Response : String;
 bFail    : Boolean;
begin

 FinalURL := URL + APP_VERSION;

 Try
  DownloadURL_BLOCKING(FinalURL, Response, 'Mozilla/5.0 (Windows; (UpdateFixer:' + APP_VERSION+'))');
 Except
  Response := '';
 End;

 Response := FastLowerCase_Trim(Response);
 bFail := True;

 x := Pos('[', Response);
 if x > 0 then
 begin
  Response := Trim(Copy(Response, x+1, 8));
  x := Pos(']', Response);
  if x > 0 then
  begin
   Response := Trim(Copy(Response, 1, x-1));
   bFail := False;

   if Response = APP_VERSION then
        lblFooter.Caption := _t('Version: {1} - This is the latest version.', 'UpdateFixer.version-latest', APP_VERSION)
   else lblFooter.Caption := _t('Version: {1} - Latest version is: {2}', 'UpdateFixer.version-not-latest', [APP_VERSION, Response]);

  end;
 end;

 SetLabelHeight(lblFooter);
 UI_UpdateDynamicContent();

 if bFail then ShowMessage(_t('Failed to retrieve what is the currently latest version!', 'UpdateFixer.version-check-fail'))
 else
 begin
  lblFooter.Cursor := crDefault;
  lblFooter.OnClick := nil;
  lblFooter.OnMouseEnter := nil;
  lblFooter.OnMouseLeave := nil;
 end;

end;

procedure TMainForm.lblFooterMouseEnter(Sender: TObject);
begin
 lblFooter.Font.Color := Color_LinkActive;
 lblFooter.Font.Style := [TFontStyle.fsUnderline];
end;

procedure TMainForm.lblFooterMouseLeave(Sender: TObject);
begin
 lblFooter.Font.Color := Color_MainFont;
 lblFooter.Font.Style := [];
end;

procedure TMainForm.lblHostsFileClick(Sender: TObject);
begin
 chkHostsFile.Checked := not chkHostsFile.Checked;
end;

procedure TMainForm.lblRegistryClick(Sender: TObject);
begin
 chkRegistry.Checked := not chkRegistry.Checked;
end;

procedure TMainForm.lblService1Click(Sender: TObject);
begin
 chkService1.Checked := not chkService1.Checked;
end;

procedure TMainForm.lblService2Click(Sender: TObject);
begin
 chkService2.Checked := not chkService2.Checked;
end;

procedure TMainForm.lblService3Click(Sender: TObject);
begin
 chkService3.Checked := not chkService3.Checked;
end;

procedure TMainForm.lblService4Click(Sender: TObject);
begin
 chkService4.Checked := not chkService4.Checked;
end;

procedure TMainForm.lblService5Click(Sender: TObject);
begin
 chkService5.Checked := not chkService5.Checked;
end;

procedure TMainForm.lblService0Click(Sender: TObject);
begin
 chkService0.Checked := not chkService0.Checked;
end;

procedure TMainForm.lblTempFilesClick(Sender: TObject);
begin
 chkTempFiles.Checked := not chkTempFiles.Checked;
end;

procedure TMainForm.Init_LoadColorScheme();
Var
 x : Integer;
 R : TRegistry;
begin

 FUI_DarkMode := False;

 // iVal := Tools.Settings.GetData('Settings', 'UserInterface', 'ColorMode', 1);
 // rdDarkModeAuto.Checked := (iVal = 1);
 // rdDarkModeEnabled.Checked := (iVal = 2);
 // rdDarkModeDisabled.Checked := (iVal = 3);

 // PT Dark Mode setting: 1 => Same as Windows
 // PT Dark Mode setting: 2 => Always Dark Mode
 // PT Dark Mode setting: 3 => Never Dark Mode

 x := Init_Read_PT_DarkMode_Setting();
 if x = 2 then FUI_DarkMode := True
 Else
 if x = 1 then
 begin
   Try
     R := TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
     R.RootKey := HKEY_CURRENT_USER;
     If R.OpenKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize', True) then
     begin
      if (R.ValueExists('AppsUseLightTheme')) and (R.ReadInteger('AppsUseLightTheme') = 0) then FUI_DarkMode := True;
     End;

     R.Free;
   Except
     ;
   End;
 end;

 {$IFDEF Debug_GenerateDebugLog}
   if FUI_DarkMode then DebugLog('Init_LoadColorScheme: Dark')
   else DebugLog('Init_LoadColorScheme: Light');
 {$ENDIF}

 if FUI_DarkMode then
 begin
  if Assigned(TStyleManager.ActiveStyle) then
     TStyleManager.TrySetStyle('Windows10 Dark');

  Color_MainBack  := RGB(0, 0, 0);
  Color_NavBack   := RGB(31, 31, 31); // This is the color from Windows 10 Dark Mode
  Color_MainFont  := RGB(250,250,250);
  pnlMainParent.BorderColor := Color_NavBack;

  Color_Btn_WhiteBack  := RGB(51,51,51);
  Color_Btn_ClickColor := RGB(226,226,226);
  Color_Btn_FocusColor := RGB(61,61,61);

  ProgressBar.BackgroundColor :=  RGB(15, 15, 15);
 end else
 begin
  Color_MainBack := RGB(255, 255, 255);
  Color_NavBack  := RGB(90, 184, 228);
  Color_MainFont := RGB(29, 29, 29);
  pnlMainParent.BorderColor := Color_NavBack;

  ProgressBar.BackgroundColor := RGB(245, 245, 245);

  btnWinClose.SymbolColor := RGB(229, 229, 229);
  btnWinClose.SymbolFocusColor := RGB(255, 255, 255);
 end;

 if FUI_DarkMode then
 begin
  imgSpinner_DM_128.Parent := pnlWaiting;
  if imgSpinner_DM_128.Picture.Graphic is TGIFImage then TGIFImage(imgSpinner_DM_128.Picture.Graphic).Animate := True;
  imgSpinner_DM_128.Visible := True;
  imgSpinner_NM_128.Visible := False;
  if imgSpinner_NM_128.Picture.Graphic is TGIFImage then TGIFImage(imgSpinner_NM_128.Picture.Graphic).Animate := False;
 end else
 begin
  imgSpinner_NM_128.Parent := pnlWaiting;
  if imgSpinner_NM_128.Picture.Graphic is TGIFImage then TGIFImage(imgSpinner_NM_128.Picture.Graphic).Animate := True;
  imgSpinner_NM_128.Visible := True;
  imgSpinner_DM_128.Visible := False;
  if imgSpinner_DM_128.Picture.Graphic is TGIFImage then TGIFImage(imgSpinner_DM_128.Picture.Graphic).Animate := False;
 end;



 Self.Color           := Color_MainBack;
 Self.Font.Color      := Color_MainFont;

 pnlMainParent.ParentColor      := False;
 pnlMainParent.ParentBackground := False;
 pnlMainParent.ParentColor      := False;
 pnlMainParent.ParentBackground := False;
 pnlWaiting.ParentBackground    := False;
 pnlWaiting.ParentColor         := False;

 pnlMainParent.Color  := Color_MainBack;
 vlistAnalyze.Color   := Color_MainBack;
 vlistFix.Color       := Color_MainBack;
 vlistDone.Color      := Color_MainBack;
 pnlWaiting.Color     := Color_MainBack;

 pnlWindowTitle.Color := Color_NavBack;
 lblHeader.Font.Color := clWhite;
 lblFooter.Font.Color := Color_MainFont;
 btnWinClose.Color := Color_NavBack;

 btnFix.AlignWithMargins := True;
 btnFix.Margins.Left     := 5;
 btnFix.Margins.Right    := 5;
 btnFix.Margins.Top      := 10;
 btnFix.Margins.Bottom   := 10;
 btnFix.Color            := Color_Btn_WhiteBack;
 btnFix.BorderColor      := Color_Btn_BorderColor;
 btnFix.ClickColor       := Color_Btn_ClickColor;
 btnFix.FocusColor       := Color_Btn_FocusColor;
 btnFix.FocusBorderColor := Color_Btn_FocusBorderColor;
 btnFix.BorderWidth      := 1;
 btnFix.BorderWidthDefaultButton := 2;

 btnAnalyze.CopySettingsFrom(btnFix);
 btnClose.CopySettingsFrom(btnFix);
 btnReboot.CopySettingsFrom(btnFix);

End;


procedure TMainForm.FormResize(Sender: TObject);
begin

 lblHeader.Top  := pnlWindowTitle.Height div 2 - lblHeader.Height div 2;
 lblHeader.Left := MainForm.Width  div 2 - lblHeader.Width div 2;

end;

procedure TMainForm.FormShow(Sender: TObject);
begin
 tmrShow.Enabled := True;

 Try
   SetErrorMode(SEM_FAILCRITICALERRORS);
 except
  ;
 end;

end;

procedure TMainForm.imgLogoSmallClick(Sender: TObject);
begin
  OpenUrl('https://winupdatefixer.com');
end;

Procedure TMainForm.OpenUrl(const URL : String);
Var
 TmpStr1  : String;
 TmpStr2  : String;
 TmpStr3  : String;
Begin

 TmpStr1 := Trim(URL);
 TmpStr2 := '';
 TmpStr3 := 'Open';

 Try
   ShellExecute(0, PChar(TmpStr3), PChar(TmpStr1), nil, nil, SW_SHOW);
 Except
  ;
 End;
end;

procedure TMainForm.pnlWindowTitleMouseDown(Sender: TObject;
  Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
begin
 ReleaseCapture;
 SendMessage(MainForm.Handle, WM_SYSCOMMAND, 61458, 0);
 FUI_AutoPos := False;

 if DebugHook <> 0 then UI_UpdateDynamicContent();

end;

procedure TMainForm.tmrShowTimer(Sender: TObject);
Var
 CurTicks : UInt64;
 NewVal   : Integer;
begin

 CurTicks := GetTickCount64();
 if CurTicks - FLastTmrShowRun < 10 then EXIT;
 FLastTmrShowRun := CurTicks;

 NewVal := MainForm.AlphaBlendValue + 25;
 if (NewVal > 255) or
    (CurTicks - FLastTmrStarted > 1000) then NewVal := 255;
 MainForm.AlphaBlendValue := NewVal;

 if MainForm.AlphaBlendValue >= 255 then
 begin
  MainForm.AlphaBlendValue := 255;
  MainForm.AlphaBlend := False;
  tmrShow.Enabled := False;
 end;


end;

function TMainForm.SetPrivilege(privilegeName: String; enable: boolean): boolean;
var
 tpPrev,
 tp        : TTokenPrivileges;
 token     : THandle;
 dwRetLen  : DWord;
begin

 if FPriviledgeSet then EXIT(TRUE);
 FPriviledgeSet := True;

 {$IFDEF Debug_GenerateDebugLog}
   DebugLog('SetPrivilege: ' + privilegeName);
 {$ENDIF}

 result := False;

 try
   OpenProcessToken(GetCurrentProcess, TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, token);

   tp.PrivilegeCount := 1;
   if LookupPrivilegeValue(nil, pchar(privilegeName), tp.Privileges[0].LUID) then
   begin
     if enable then
       tp.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED
     else
       tp.Privileges[0].Attributes := 0;

     dwRetLen := 0;
     result := AdjustTokenPrivileges(token, False, tp, SizeOf(tpPrev), tpPrev, dwRetLen);
   end;

   CloseHandle(token);
 except
  ;
 end;

end;

function TMainForm.MyGetComputerName(): String;
var
  buffer    : PChar;
  bufferSize: DWORD;
begin
  bufferSize := MAX_COMPUTERNAME_LENGTH+1;
  GetMem(buffer, bufferSize);
  try
    GetComputerName(buffer, bufferSize);
    Result := Trim(buffer);
  finally
    FreeMem(buffer, bufferSize);
  end;



 {$IFDEF Debug_GenerateDebugLog}
   DebugLog('MyGetComputerName: ' + Result);
 {$ENDIF}

end;

function TMainForm.MyGetUserName(): String;
var
  buffer    : PChar;
  bufferSize: DWORD;
begin
  bufferSize := 128;
  buffer := AllocMem(bufferSize);
  try
    GetUserName(buffer, bufferSize);
    Result :=  Trim(buffer);
  finally
    FreeMem(buffer, bufferSize);
  end;


 {$IFDEF Debug_GenerateDebugLog}
   DebugLog('MyGetUserName: ' + Result);
 {$ENDIF}

end;

function TMainForm.SID_GetUserSID() : Pointer;
var
 PSID: Pointer;
 SIDSize, DomainSize, peUse: Cardinal;
 Machine,AccountName: PChar;
 Domain: String;
 Success: Boolean;
begin

  result := nil;
  Machine:= PChar(MyGetComputerName);
  AccountName:= PChar(MyGetUserName);
  SIDSize := 0;
  DomainSize := 0;
  Success:= LookupAccountNameW(Machine,AccountName,nil,SIDSize,nil, DomainSize,peUse);
  if (not Success) and (GetLastError = ERROR_INSUFFICIENT_BUFFER) then
  begin
      GetMem(PSID,SIDSize);
      SetLength(Domain, DomainSize);
      try
        if not LookupAccountNameW(Machine, AccountName,PSID,
          SIDSize, PChar(Domain),DomainSize,peUse) then
        begin
          if psid <> nil  then
          begin
            exit;
          end
          else
            result := PSID;
        end
        else
          result := PSID;
      finally
      //  FreeMem(Domain);
        //FreeMem(PSID);
      end;
  end
//  else
//    RaiseLastOSError;
end;

Procedure TMainForm.Process_Init_Pas();
var
  i : Integer;
  SID: PSID;
  peUse, cchDomain, cchName, dwResult : DWORD;
  Name, Domain: array of Char;
  pDACL: PACL;
  pEA: PEXPLICIT_ACCESS_W;
  sObject: String;
  Sd: PSecurityDescriptor;
  UserSID: Pointer;
  ServName : String;
  UsrID : String;
begin

  // 'SeTakeOwnershipPrivilege'
  SetPrivilege('SeTakeOwnershipPrivilege', true);
  //SetPrivilege(_x('!WW5YbGVqX2Z8dmZmfn5oSWhyanRyekdE'), true);

  UsrID := _x('!WSY9IDsiIyM/JiAg');     // 'S-1-5-32-545' - also: S-1-5-32-545='users';  S-1-1-0='everyone'

  for i := Low(ServiceNamesArr_X) to High(ServiceNamesArr_X) do
  begin
    if FServiceCheckboxes[i].Checked = False then Continue;

    ServName := _x(ServiceNamesArr_X[i]);
    if Analyze_System_Service_IsOK(ServName) = False then
    begin
     If IsByDefaultReadOnlyServKey(ServName) then Continue;
    end else Continue;


    SID := nil;
    ConvertStringSidToSid(PChar(UsrID), SID);
    if SID = nil then Break;

    // 'MACHINE\SYSTEM\CurrentControlSet\Services\'
    sObject := _x('!R0pPRUdBVU1BSkdBU1pEWm9pbnhwa2NOTFdWSkp0TV12eElfWEZTVEFv') + ServName;

    {$IFDEF Debug_GenerateDebugLog}
      DebugLog('Process_Init_Pas: ' + sObject);
    {$ENDIF}

    //ShowMessage('debug: ' + sObject);
    cchName := 0;
    cchDomain := 0;

    Try
      if LookupAccountSidW(nil, SID, nil, cchName, nil, cchDomain, peUse) then
      begin

       {$IFDEF Debug_GenerateDebugLog}
         DebugLog('Process_Init_Pas LookupAccountSidW-1 Done: ' + IntToStr(cchName) + ' | ' + IntToStr(cchDomain));
       {$ENDIF}

        if cchName < 1 then Continue;
        if cchDomain < 1 then Continue;

        SetLength(Name, cchName);
        SetLength(Domain, cchDomain);

        if LookupAccountSidW(nil, SID, @Name[0], cchName, @Domain[0], cchDomain, peUse) then
        begin
          pEA := AllocMem(SizeOf(EXPLICIT_ACCESS));
          BuildExplicitAccessWithNameW(@pEA, PChar(Name), GENERIC_ALL,GRANT_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);

          dwResult := SetEntriesInAclW(1, @pEA, nil, pDACL);

          {$IFDEF Debug_GenerateDebugLog}
            DebugLog('SetEntriesInAclW dwResult: ' + IntToStr(dwResult));
          {$ENDIF}

          if dwResult = ERROR_SUCCESS then
          begin
                if sid <> nil then
                begin
                  GetMem(Sd, 1024);
                  //Sd := AllocMem(1024);
                  InitializeSecurityDescriptor(Sd, SECURITY_DESCRIPTOR_REVISION);

                  //SetSecurityDescriptorOwnerSd,UserSID, False);
                  UserSID := SID_GetUserSID();
                  dwResult := SetNamedSecurityInfoW(PChar(sObject), SE_REGISTRY_KEY,
                              OWNER_SECURITY_INFORMATION, UserSID, nil, nil, nil);

                  {$IFDEF Debug_GenerateDebugLog}
                    DebugLog('SetNamedSecurityInfoW1 dwResult: ' + IntToStr(dwResult));
                  {$ENDIF}

                  {
                  if dwResult = ERROR_SUCCESS then ShowMessage('SetNamedSecurityInfo x1 success!')
                  else
                  if (dwResult <> ERROR_SUCCESS) and (dwResult <> ERROR_INVALID_PARAMETER) then
                     ShowMessage('SetNamedSecurityInfo Take Ownership failed: ' + SysErrorMessage(GetLastError));
                             }
                  //FreeMem(Sd);
                end;


            dwResult := SetNamedSecurityInfoW(PChar(sObject), SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, nil, nil, pDACL, nil);

            {$IFDEF Debug_GenerateDebugLog}
              DebugLog('SetNamedSecurityInfoW2 dwResult: ' + IntToStr(dwResult));
            {$ENDIF}

             {
            if dwResult = ERROR_SUCCESS then ShowMessage('SetNamedSecurityInfo x2 success!');

            if dwResult <> ERROR_SUCCESS then
              ShowMessage('SetNamedSecurityInfo failed: ' + SysErrorMessage(GetLastError));   }

            //LocalFree(Cardinal(pDACL));
          end;
         // else
         //   ShowMessage('SetEntriesInAcl failed: ' + SysErrorMessage(dwResult));

          //FreeMem(pEA);
        end;
      end;
    except
     on E : Exception do
     begin
      {$IFDEF Debug_GenerateDebugLog} DebugLog('Process-Init-1 Exception: ' + E.Message); {$ENDIF}
      {$IFDEF Debug_ExceptionMessages} ShowMessage('Process-Init-1 Exception: ' + E.Message); {$ENDIF}
     End;
    end;
  end;

  //ShowMessage('Process_Init_Pas Done!');

end;

Procedure TMainForm.Process_Init();
const
 //CMD0 = '@DISM /Online /Cleanup-Image /CheckHealth  > NUL 2>&1';
 CMD0x = '!Sk9FXkMvP158f317czc3WnZ+fXNrbw1oT0JDQAYIa0FPSEdlS05cRVoTFAsWeW11GgkCGw8=';

 //CMD_Base = '@net stop <x>  > NUL 2>&1';
 CMD_Base = '!SmVpeS58ZH5iMyhtKDc4JzpVSVE+LR4HEw==';

 //PS_Base = 'Stop-Service -Name <x> -ErrorAction SilentlyContinue ';
 PS_BaseX = '!WX9jfSNcdWNkendwNjpWeHd+PCFmIQAMZ1FWSlRmS11DREINfUZcVFxHWEx1WFZNU1VJWB4=';

 //CMD1 = '@taskkill /im wuauclt.exe /f > NUL 2>&1';
 CMD1x = '!Sn9tfmVkeX1+Mzt8ezdvbHtuf3FqMUVZRwMLQwYZCGd/ZwwfEAkB';

Var
 i        : Integer;
 Filename : String;
 PS_File  : TStringList;
Begin

 {$IFDEF Debug_GenerateDebugLog}
   DebugLog('Process_Init Start: ' + APP_VERSION);
 {$ENDIF}

 FBatFile.Add('@echo off');
 FBatFile.Add('@echo Update Fixer '+APP_VERSION);
 FBatFile.Add('@echo WinUpdateFixer.com' );
 FBatFile.Add('@echo Copyright 2023 Macecraft Software. All Rights Reserved.' );
 FBatFile.Add('@echo .'); // empty line
 FBatFile.Add('@echo ' + _t('Hello! This is Update Fixer fixing your Windows Update.', 'updatefixer.bat-start1') );
 FBatFile.Add('@echo ' + _t('If you can see this window, it is okay, nothing is wrong, Update Fixer is just working. There is no need to do anything.', 'updatefixer.bat-start2') );
 FBatFile.Add('@echo ' + _t('This will take a few minutes. This window will automatically close after the process has completed.', 'updatefixer.bat-start3') );
 FBatFile.Add('@echo ' + _t('Have a cup of tea. Everything is fine. Thank you!', 'updatefixer.bat-start4') );
 FBatFile.Add('');
 FBatFile.Add(':: WARNING: This file has been customized to this specific system. Do not run this file on any other systems!');
 FBatFile.Add('');
 FBatFile.Add(':: Detected Windows version is: ' + FWinVer);
 FBatFile.Add('');

 FBatFile.Add(_x(CMD0x));

 for i := Low(ServiceNamesArr_X) to High(ServiceNamesArr_X) do
   FBatFile.Add( StringReplace(_x(CMD_Base), '<x>', _x(ServiceNamesArr_X[i]), [rfReplaceAll, rfIgnoreCase]) );

 FBatFile.Add( _x(CMD1x));
 Filename := GetTempDir() + 'update_fixer_can_delete_' + IntToStr(GetTickCount) + _x(GLOB_Crypt_ps1);
 FBatFile.Add(_x(GLOB_Crypt_Del) + '"'+Filename+'" > NUL 2>&1');


 PS_File := TStringList.Create;

 for i := Low(ServiceNamesArr_X) to High(ServiceNamesArr_X) do
   PS_File.Add( StringReplace(_x(PS_BaseX), '<x>', _x(ServiceNamesArr_X[i]), [rfReplaceAll, rfIgnoreCase]) );

 PS_File.SaveToFile(Filename);
 if DEBUG_STORE_BAT = 1 then PS_File.SaveToFile( GetDesktopDir() + 'init' + _x(GLOB_Crypt_ps1) );
 PS_File.Free;


 If DebugHook = 0 then RunPSFileAndWait(Filename);


 if DEBUG_STORE_BAT <> 1 then
 begin
   Try
    if FileExists_Cached(Filename) then DeleteFile(Filename);
   Except
    ;
   End;
 end;


End;


Procedure TMainForm.Process_Finalize_PS();
const
 PS_SCRIPT =
  'ZnVuY3Rpb24gRW5hYmxlLVByaXZpbGVnZSB7DQogcGFyYW0oDQogIFtWYWxpZGF0ZVNldCgNCiAgICJTZUFzc2lnblByaW1hcnlUb2tlblByaXZpbGVnZSIsICJTZUF1ZGl0UHJpdmlsZWdlIiwgIlNlQmFja3VwUHJpdmlsZWdlIiwNCiAgICJTZUNoYW5nZU5vdGlmeVByaXZpbGVnZSIsICJTZUNyZWF0ZUdsb2JhbFByaXZpbGVnZSIsIC'+
  'JTZUNyZWF0ZVBhZ2VmaWxlUHJpdmlsZWdlIiwNCiAgICJTZUNyZWF0ZVBlcm1hbmVudFByaXZpbGVnZSIsICJTZUNyZWF0ZVN5bWJvbGljTGlua1ByaXZpbGVnZSIsICJTZUNyZWF0ZVRva2VuUHJpdmlsZWdlIiwNCiAgICJTZURlYnVnUHJpdmlsZWdlIiwgIlNlRW5hYmxlRGVsZWdhdGlvblByaXZpbGVnZSIsICJTZUltcGVyc29uYXRl'+
  'UHJpdmlsZWdlIiwgIlNlSW5jcmVhc2VCYXNlUHJpb3JpdHlQcml2aWxlZ2UiLA0KICAgIlNlSW5jcmVhc2VRdW90YVByaXZpbGVnZSIsICJTZUluY3JlYXNlV29ya2luZ1NldFByaXZpbGVnZSIsICJTZUxvYWREcml2ZXJQcml2aWxlZ2UiLA0KICAgIlNlTG9ja01lbW9yeVByaXZpbGVnZSIsICJTZU1hY2hpbmVBY2NvdW50UHJpdmlsZW'+
  'dlIiwgIlNlTWFuYWdlVm9sdW1lUHJpdmlsZWdlIiwNCiAgICJTZVByb2ZpbGVTaW5nbGVQcm9jZXNzUHJpdmlsZWdlIiwgIlNlUmVsYWJlbFByaXZpbGVnZSIsICJTZVJlbW90ZVNodXRkb3duUHJpdmlsZWdlIiwNCiAgICJTZVJlc3RvcmVQcml2aWxlZ2UiLCAiU2VTZWN1cml0eVByaXZpbGVnZSIsICJTZVNodXRkb3duUHJpdmlsZWdl'+
  'IiwgIlNlU3luY0FnZW50UHJpdmlsZWdlIiwNCiAgICJTZVN5c3RlbUVudmlyb25tZW50UHJpdmlsZWdlIiwgIlNlU3lzdGVtUHJvZmlsZVByaXZpbGVnZSIsICJTZVN5c3RlbXRpbWVQcml2aWxlZ2UiLA0KICAgIlNlVGFrZU93bmVyc2hpcFByaXZpbGVnZSIsICJTZVRjYlByaXZpbGVnZSIsICJTZVRpbWVab25lUHJpdmlsZWdlIiwgIl'+
  'NlVHJ1c3RlZENyZWRNYW5BY2Nlc3NQcml2aWxlZ2UiLA0KICAgIlNlVW5kb2NrUHJpdmlsZWdlIiwgIlNlVW5zb2xpY2l0ZWRJbnB1dFByaXZpbGVnZSIpXQ0KICAkUHJpdmlsZWdlLA0KICAkUHJvY2Vzc0lkID0gJHBpZCwNCiAgW1N3aXRjaF0gJERpc2FibGUNCiApDQoNCiAkZGVmaW5pdGlvbiA9IEAnDQogdXNpbmcgU3lzdGVtOw0K'+
  'IHVzaW5nIFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlczsNCiAgDQogcHVibGljIGNsYXNzIEFkalByaXYNCiB7DQogIFtEbGxJbXBvcnQoImFkdmFwaTMyLmRsbCIsIEV4YWN0U3BlbGxpbmcgPSB0cnVlLCBTZXRMYXN0RXJyb3IgPSB0cnVlKV0NCiAgaW50ZXJuYWwgc3RhdGljIGV4dGVybiBib29sIEFkanVzdFRva2VuUHJpdm'+
  'lsZWdlcyhJbnRQdHIgaHRvaywgYm9vbCBkaXNhbGwsDQogICByZWYgVG9rUHJpdjFMdWlkIG5ld3N0LCBpbnQgbGVuLCBJbnRQdHIgcHJldiwgSW50UHRyIHJlbGVuKTsNCiAgDQogIFtEbGxJbXBvcnQoImFkdmFwaTMyLmRsbCIsIEV4YWN0U3BlbGxpbmcgPSB0cnVlLCBTZXRMYXN0RXJyb3IgPSB0cnVlKV0NCiAgaW50ZXJuYWwgc3Rh'+
  'dGljIGV4dGVybiBib29sIE9wZW5Qcm9jZXNzVG9rZW4oSW50UHRyIGgsIGludCBhY2MsIHJlZiBJbnRQdHIgcGh0b2spOw0KICBbRGxsSW1wb3J0KCJhZHZhcGkzMi5kbGwiLCBTZXRMYXN0RXJyb3IgPSB0cnVlKV0NCiAgaW50ZXJuYWwgc3RhdGljIGV4dGVybiBib29sIExvb2t1cFByaXZpbGVnZVZhbHVlKHN0cmluZyBob3N0LCBzdH'+
  'JpbmcgbmFtZSwgcmVmIGxvbmcgcGx1aWQpOw0KICBbU3RydWN0TGF5b3V0KExheW91dEtpbmQuU2VxdWVudGlhbCwgUGFjayA9IDEpXQ0KICBpbnRlcm5hbCBzdHJ1Y3QgVG9rUHJpdjFMdWlkDQogIHsNCiAgIHB1YmxpYyBpbnQgQ291bnQ7DQogICBwdWJsaWMgbG9uZyBMdWlkOw0KICAgcHVibGljIGludCBBdHRyOw0KICB9DQogIA0K'+
  'ICBpbnRlcm5hbCBjb25zdCBpbnQgU0VfUFJJVklMRUdFX0VOQUJMRUQgPSAweDAwMDAwMDAyOw0KICBpbnRlcm5hbCBjb25zdCBpbnQgU0VfUFJJVklMRUdFX0RJU0FCTEVEID0gMHgwMDAwMDAwMDsNCiAgaW50ZXJuYWwgY29uc3QgaW50IFRPS0VOX1FVRVJZID0gMHgwMDAwMDAwODsNCiAgaW50ZXJuYWwgY29uc3QgaW50IFRPS0VOX0'+
  'FESlVTVF9QUklWSUxFR0VTID0gMHgwMDAwMDAyMDsNCiAgcHVibGljIHN0YXRpYyBib29sIEVuYWJsZVByaXZpbGVnZShsb25nIHByb2Nlc3NIYW5kbGUsIHN0cmluZyBwcml2aWxlZ2UsIGJvb2wgZGlzYWJsZSkNCiAgew0KICAgYm9vbCByZXRWYWw7DQogICBUb2tQcml2MUx1aWQgdHA7DQogICBJbnRQdHIgaHByb2MgPSBuZXcgSW50'+
  'UHRyKHByb2Nlc3NIYW5kbGUpOw0KICAgSW50UHRyIGh0b2sgPSBJbnRQdHIuWmVybzsNCiAgIHJldFZhbCA9IE9wZW5Qcm9jZXNzVG9rZW4oaHByb2MsIFRPS0VOX0FESlVTVF9QUklWSUxFR0VTIHwgVE9LRU5fUVVFUlksIHJlZiBodG9rKTsNCiAgIHRwLkNvdW50ID0gMTsNCiAgIHRwLkx1aWQgPSAwOw0KICAgaWYoZGlzYWJsZSkNCi'+
  'AgIHsNCiAgICB0cC5BdHRyID0gU0VfUFJJVklMRUdFX0RJU0FCTEVEOw0KICAgfQ0KICAgZWxzZQ0KICAgew0KICAgIHRwLkF0dHIgPSBTRV9QUklWSUxFR0VfRU5BQkxFRDsNCiAgIH0NCiAgIHJldFZhbCA9IExvb2t1cFByaXZpbGVnZVZhbHVlKG51bGwsIHByaXZpbGVnZSwgcmVmIHRwLkx1aWQpOw0KICAgcmV0VmFsID0gQWRqdXN0'+
  'VG9rZW5Qcml2aWxlZ2VzKGh0b2ssIGZhbHNlLCByZWYgdHAsIDAsIEludFB0ci5aZXJvLCBJbnRQdHIuWmVybyk7DQogICByZXR1cm4gcmV0VmFsOw0KICB9DQogfQ0KJ0ANCg0KICRwcm9jZXNzSGFuZGxlID0gKEdldC1Qcm9jZXNzIC1pZCAkUHJvY2Vzc0lkKS5IYW5kbGUNCiAkdHlwZSA9IEFkZC1UeXBlICRkZWZpbml0aW9uIC1QYX'+
  'NzVGhydQ0KICR0eXBlWzBdOjpFbmFibGVQcml2aWxlZ2UoJHByb2Nlc3NIYW5kbGUsICRQcml2aWxlZ2UsICREaXNhYmxlKQ0KfQ0KDQpFbmFibGUtUHJpdmlsZWdlIFNlVGFrZU93bmVyc2hpcFByaXZpbGVnZSANCg0KJHJlZ0tleVBhdGggPSAiU1lTVEVNXEN1cnJlbnRDb250cm9sU2V0XFNlcnZpY2VzXDx4PiINCiRzZXJ2aWNlTmFt'+
  'ZSA9ICI8eD4iDQokYWRtaW4gPSAiQWRtaW5pc3RyYXRvcnMiDQoNCiRyZWdLZXkgPSBbTWljcm9zb2Z0LldpbjMyLlJlZ2lzdHJ5XTo6TG9jYWxNYWNoaW5lLk9wZW5TdWJLZXkoJHJlZ0tleVBhdGgsW01pY3Jvc29mdC5XaW4zMi5SZWdpc3RyeUtleVBlcm1pc3Npb25DaGVja106OlJlYWRXcml0ZVN1YlRyZWUsW1N5c3RlbS5TZWN1cm'+
  'l0eS5BY2Nlc3NDb250cm9sLlJlZ2lzdHJ5UmlnaHRzXTo6VGFrZU93bmVyc2hpcCkNCiRyZWdBQ0wgPSAkcmVnS2V5LkdldEFjY2Vzc0NvbnRyb2woKQ0KJHJlZ0FDTC5TZXRPd25lcihbU3lzdGVtLlNlY3VyaXR5LlByaW5jaXBhbC5OVEFjY291bnRdJGFkbWluKQ0KJHJlZ0tleS5TZXRBY2Nlc3NDb250cm9sKCRyZWdBQ0wpDQoNCiRy'+
  'ZWdLZXkgPSBbTWljcm9zb2Z0LldpbjMyLlJlZ2lzdHJ5XTo6TG9jYWxNYWNoaW5lLk9wZW5TdWJLZXkoJHJlZ0tleVBhdGgsW01pY3Jvc29mdC5XaW4zMi5SZWdpc3RyeUtleVBlcm1pc3Npb25DaGVja106OlJlYWRXcml0ZVN1YlRyZWUsW1N5c3RlbS5TZWN1cml0eS5BY2Nlc3NDb250cm9sLlJlZ2lzdHJ5UmlnaHRzXTo6Q2hhbmdlUG'+
  'VybWlzc2lvbnMpDQokcmVnQUNMID0gJHJlZ0tleS5HZXRBY2Nlc3NDb250cm9sKCkNCiRyZWdSdWxlID0gTmV3LU9iamVjdCBTeXN0ZW0uU2VjdXJpdHkuQWNjZXNzQ29udHJvbC5SZWdpc3RyeUFjY2Vzc1J1bGUgKCRhZG1pbiwiRnVsbENvbnRyb2wiLCJDb250YWluZXJJbmhlcml0IiwiTm9uZSIsIkFsbG93IikNCiRyZWdBQ0wuU2V0'+
  'QWNjZXNzUnVsZSgkcmVnUnVsZSkNCiRyZWdLZXkuU2V0QWNjZXNzQ29udHJvbCgkcmVnQUNMKQ0KDQpTZXQtU2VydmljZSAtTmFtZSAkc2VydmljZU5hbWUgLVN0YXR1cyBydW5uaW5nIC1TdGFydHVwVHlwZSBhdXRvbWF0aWM=';

Var
 i        : Integer;
 j        : Integer;
 Filename : String;
 Content  : String;
 ServName : String;
 TmpList  : TStringList;
 Base64   : TBase64Encoding;
begin

 {$IFDEF Debug_GenerateDebugLog} DebugLog('Process_Finalize_PS Start'); {$ENDIF}
 TmpList := TStringList.Create;

 Try
  Base64 := TBase64Encoding.Create();
  Content := Base64.Decode(PS_SCRIPT);
 Except
  ;
 End;


 for i := Low(ServiceNamesArr_X) to High(ServiceNamesArr_X) do
 begin
   if FServiceCheckboxes[i].Checked = False then Continue;

   ServName := _x(ServiceNamesArr_X[i]);
   if Analyze_System_Service_IsOK(ServName) = False then
   begin
    If IsByDefaultReadOnlyServKey(ServName) then Continue;
   end else Continue;

   {$IFDEF Debug_GenerateDebugLog}
     DebugLog('Process_Finalize_PS Do: ' + ServName);
   {$ENDIF}

   TmpList.Clear;
   TmpList.Add( StringReplace(Content, '<x>', ServName, [rfReplaceAll, rfIgnoreCase]) );

   for j := Low(ServiceKeySubDirsX) to High(ServiceKeySubDirsX) do
    TmpList.Add( StringReplace(Content, '<x>', ServName +'\'+ _x(ServiceKeySubDirsX[j]), [rfReplaceAll, rfIgnoreCase]) );

   Try
     Filename := GetTempDir() + 'UpdateFixer_Can_Be_Deleted_' + IntToStr(i) + '_' + IntToStr(GetTickCount) + _x(GLOB_Crypt_ps1);
     TmpList.SaveToFile(Filename);

     if DEBUG_STORE_BAT = 1 then TmpList.SaveToFile(GetDesktopDir() + 'finalize' + IntToStr(i) + _x(GLOB_Crypt_ps1));

     RunPSFileAndWait(Filename);
   Except
     ;
   End;

   Try
    if FileExists(Filename) then DeleteFile(Filename);
   Except
     ;
   End;
 end;

 TmpList.Free;
 {$IFDEF Debug_GenerateDebugLog} DebugLog('Process_Finalize_PS Done'); {$ENDIF}

end;


Procedure TMainForm.Process_Finalize();
const
 //CMD_Base = '@net start <x> > NUL 2>&1';
 CMD_BaseX = '!SmVpeS58ZHBgZzQpbik4JzpVSVE+LR4HEw==';

 //CMD2 = '@wuauclt /ResetAuthorization /DetectNow > NUL 2>&1';
 CMD2x = '!Snx5bHtsfGUyPEZwZXJsWG9vdHJsdlpAVkpLSwYIbExeTk9ZYEBHEQwTemB6FwoHHAo=';

 //CMD3 = '@wusa update /quiet /forcerestart > NUL 2>&1';
 CMD3x = '!Snx5fm8vZWF2cmBwNjhpbHN+aD0xeU9TQUZWQFVTSVteCxINYHp8EQANEgQ=';

 // RegKey = 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
 RegKeyX = '!WURKWVlOQlROXn12ZHhrdnxvQEp3cUROVVB4ZlNVWkxEX3pIXFxZXlxvZkBYeFZaXw==';

Var
 i : Integer;
 x : Integer;
 R : TRegistry;
 Filename_RunNow   : String;
 Filename_RunLater : String;
Begin


 {$IFDEF Debug_GenerateDebugLog}
   DebugLog('Process_Finalize Start');
 {$ENDIF}

 Filename_RunNow   := GetTempDir() + 'UpdateFixer_Can_Be_Deleted_1' + IntToStr(GetTickCount) + '.bat';
 Filename_RunLater := GetCurrentUserDir() + 'UpdateFixer_Can_Be_Deleted_2' + IntToStr(GetTickCount) + '.bat';

 if (chkBlockers.Checked) and
    (FBlockerRemoval.Count > 0) then FBatFile.AddStrings(FBlockerRemoval);
 {$IFDEF Debug_ShowProgress} lblHeader.Caption := lblHeader.Caption +'0'; Application.ProcessMessages; {$ENDIF}


 FBatFile.Add('@echo .');
 FBatFile.Add('@echo ' + _t('All done!', 'updatefixer.bat-end') );
 FBatFile.Add('@' + _x(GLOB_Crypt_Timeout) );

 FBatFile.Add('');
 FBatFile.Add(':: WARNING: This file has been customized to this specific system. Do not run this file on any other systems!');
 FBatFile.Add('');
 {$IFDEF Debug_ShowProgress} lblHeader.Caption := lblHeader.Caption +'1'; Application.ProcessMessages; {$ENDIF}

 FBatFile.SaveToFile(Filename_RunNow);


 // Add the service starting code to only to script running AFTER:
 for i := Low(ServiceNamesArr_X) to High(ServiceNamesArr_X) do
   FBatFile.Add( StringReplace(_x(CMD_BaseX), '<x>', _x(ServiceNamesArr_X[i]), [rfReplaceAll, rfIgnoreCase]) );

 {$IFDEF Debug_ShowProgress} lblHeader.Caption := lblHeader.Caption +'2'; Application.ProcessMessages; {$ENDIF}

 if DebugHook = 0 then
 begin
  Process_Finalize_PS();
  {$IFDEF Debug_ShowProgress} lblHeader.Caption := lblHeader.Caption +'3'; Application.ProcessMessages; {$ENDIF}


  RunBatchFileAndWait(Filename_RunNow);
  {$IFDEF Debug_ShowProgress} lblHeader.Caption := lblHeader.Caption +'4'; Application.ProcessMessages; {$ENDIF}

  if UI_AnyServiceCheckboxChecked() then Process_Finalize_PS();
 End;

 {$IFDEF Debug_ShowProgress} lblHeader.Caption := lblHeader.Caption +'5'; Application.ProcessMessages; {$ENDIF}


 // Add some progress:
 i := 10;
 x := FBatFile.Count div 10;
 if x < 1 then x := 1;
 while i+10 < FBatFile.Count-1 do
 begin
  FBatFile.Insert(i, '@echo .');
  Inc(i,x);
 end;


 {$IFDEF Debug_ShowProgress} lblHeader.Caption := lblHeader.Caption +'6'; Application.ProcessMessages; {$ENDIF}

 If FRegIniFilename <> '' then FBatFile.Add( _x(GLOB_Crypt_Del) + '"'+FRegIniFilename+'" > NUL 2>&1');

 FBatFile.Add(_x(CMD2X));
 FBatFile.Add(_x(CMD3X));
 FBatFile.Add(_x(GLOB_Crypt_Del) + '"'+Filename_RunLater+'" > NUL 2>&1');
 FBatFile.SaveToFile(Filename_RunLater);

 if DEBUG_STORE_BAT = 1 then FBatFile.SaveToFile(GetDesktopDir() + 'finalize.bat');
 {$IFDEF Debug_ShowProgress} lblHeader.Caption := lblHeader.Caption +'7'; Application.ProcessMessages; {$ENDIF}


 if DebugHook = 0 then
 begin

  R := TRegistry.Create(KEY_WRITE or KEY_WOW64_64KEY);
  R.RootKey := HKEY_LOCAL_MACHINE;
  if R.OpenKey(_x(RegKeyX), False) then
  begin
   R.WriteString('UpdateFixer', Filename_RunLater);
  end;
  R.Free;

 end;
 {$IFDEF Debug_ShowProgress} lblHeader.Caption := lblHeader.Caption +'8'; Application.ProcessMessages; {$ENDIF}

 Try
  if FileExists(Filename_RunNow) then DeleteFile(Filename_RunNow);
 Except
   ;
 End;

 {$IFDEF Debug_GenerateDebugLog}
   DebugLog('Process_Finalize Done');
 {$ENDIF}
End;




Procedure TMainForm.Process_Init_PS();
const
 PS_SCRIPT =
  'ZnVuY3Rpb24gRW5hYmxlLVByaXZpbGVnZSB7DQogcGFyYW0oDQogIFtWYWxpZGF0ZVNldCgNCiAgICJTZUFzc2lnblByaW1hcnlUb2tlblByaXZpbGVnZSIsICJTZUF1ZGl0UHJpdmlsZWdlIiwgIlNlQmFja3VwUHJpdmlsZWdlIiwNCiAgICJTZUNoYW5nZU5vdGlmeVByaXZpbGVnZSIsICJTZUNyZWF0ZUdsb2JhbFByaXZpbGVnZSIsIC' +
  'JTZUNyZWF0ZVBhZ2VmaWxlUHJpdmlsZWdlIiwNCiAgICJTZUNyZWF0ZVBlcm1hbmVudFByaXZpbGVnZSIsICJTZUNyZWF0ZVN5bWJvbGljTGlua1ByaXZpbGVnZSIsICJTZUNyZWF0ZVRva2VuUHJpdmlsZWdlIiwNCiAgICJTZURlYnVnUHJpdmlsZWdlIiwgIlNlRW5hYmxlRGVsZWdhdGlvblByaXZpbGVnZSIsICJTZUltcGVyc29uYXRl' +
  'UHJpdmlsZWdlIiwgIlNlSW5jcmVhc2VCYXNlUHJpb3JpdHlQcml2aWxlZ2UiLA0KICAgIlNlSW5jcmVhc2VRdW90YVByaXZpbGVnZSIsICJTZUluY3JlYXNlV29ya2luZ1NldFByaXZpbGVnZSIsICJTZUxvYWREcml2ZXJQcml2aWxlZ2UiLA0KICAgIlNlTG9ja01lbW9yeVByaXZpbGVnZSIsICJTZU1hY2hpbmVBY2NvdW50UHJpdmlsZW' +
  'dlIiwgIlNlTWFuYWdlVm9sdW1lUHJpdmlsZWdlIiwNCiAgICJTZVByb2ZpbGVTaW5nbGVQcm9jZXNzUHJpdmlsZWdlIiwgIlNlUmVsYWJlbFByaXZpbGVnZSIsICJTZVJlbW90ZVNodXRkb3duUHJpdmlsZWdlIiwNCiAgICJTZVJlc3RvcmVQcml2aWxlZ2UiLCAiU2VTZWN1cml0eVByaXZpbGVnZSIsICJTZVNodXRkb3duUHJpdmlsZWdl' +
  'IiwgIlNlU3luY0FnZW50UHJpdmlsZWdlIiwNCiAgICJTZVN5c3RlbUVudmlyb25tZW50UHJpdmlsZWdlIiwgIlNlU3lzdGVtUHJvZmlsZVByaXZpbGVnZSIsICJTZVN5c3RlbXRpbWVQcml2aWxlZ2UiLA0KICAgIlNlVGFrZU93bmVyc2hpcFByaXZpbGVnZSIsICJTZVRjYlByaXZpbGVnZSIsICJTZVRpbWVab25lUHJpdmlsZWdlIiwgIl' +
  'NlVHJ1c3RlZENyZWRNYW5BY2Nlc3NQcml2aWxlZ2UiLA0KICAgIlNlVW5kb2NrUHJpdmlsZWdlIiwgIlNlVW5zb2xpY2l0ZWRJbnB1dFByaXZpbGVnZSIpXQ0KICAkUHJpdmlsZWdlLA0KICAkUHJvY2Vzc0lkID0gJHBpZCwNCiAgW1N3aXRjaF0gJERpc2FibGUNCiApDQoNCiAkZGVmaW5pdGlvbiA9IEAnDQogdXNpbmcgU3lzdGVtOw0K' +
  'IHVzaW5nIFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlczsNCiAgDQogcHVibGljIGNsYXNzIEFkalByaXYNCiB7DQogIFtEbGxJbXBvcnQoImFkdmFwaTMyLmRsbCIsIEV4YWN0U3BlbGxpbmcgPSB0cnVlLCBTZXRMYXN0RXJyb3IgPSB0cnVlKV0NCiAgaW50ZXJuYWwgc3RhdGljIGV4dGVybiBib29sIEFkanVzdFRva2VuUHJpdm' +
  'lsZWdlcyhJbnRQdHIgaHRvaywgYm9vbCBkaXNhbGwsDQogICByZWYgVG9rUHJpdjFMdWlkIG5ld3N0LCBpbnQgbGVuLCBJbnRQdHIgcHJldiwgSW50UHRyIHJlbGVuKTsNCiAgDQogIFtEbGxJbXBvcnQoImFkdmFwaTMyLmRsbCIsIEV4YWN0U3BlbGxpbmcgPSB0cnVlLCBTZXRMYXN0RXJyb3IgPSB0cnVlKV0NCiAgaW50ZXJuYWwgc3Rh' +
  'dGljIGV4dGVybiBib29sIE9wZW5Qcm9jZXNzVG9rZW4oSW50UHRyIGgsIGludCBhY2MsIHJlZiBJbnRQdHIgcGh0b2spOw0KICBbRGxsSW1wb3J0KCJhZHZhcGkzMi5kbGwiLCBTZXRMYXN0RXJyb3IgPSB0cnVlKV0NCiAgaW50ZXJuYWwgc3RhdGljIGV4dGVybiBib29sIExvb2t1cFByaXZpbGVnZVZhbHVlKHN0cmluZyBob3N0LCBzdH' +
  'JpbmcgbmFtZSwgcmVmIGxvbmcgcGx1aWQpOw0KICBbU3RydWN0TGF5b3V0KExheW91dEtpbmQuU2VxdWVudGlhbCwgUGFjayA9IDEpXQ0KICBpbnRlcm5hbCBzdHJ1Y3QgVG9rUHJpdjFMdWlkDQogIHsNCiAgIHB1YmxpYyBpbnQgQ291bnQ7DQogICBwdWJsaWMgbG9uZyBMdWlkOw0KICAgcHVibGljIGludCBBdHRyOw0KICB9DQogIA0K' +
  'ICBpbnRlcm5hbCBjb25zdCBpbnQgU0VfUFJJVklMRUdFX0VOQUJMRUQgPSAweDAwMDAwMDAyOw0KICBpbnRlcm5hbCBjb25zdCBpbnQgU0VfUFJJVklMRUdFX0RJU0FCTEVEID0gMHgwMDAwMDAwMDsNCiAgaW50ZXJuYWwgY29uc3QgaW50IFRPS0VOX1FVRVJZID0gMHgwMDAwMDAwODsNCiAgaW50ZXJuYWwgY29uc3QgaW50IFRPS0VOX0' +
  'FESlVTVF9QUklWSUxFR0VTID0gMHgwMDAwMDAyMDsNCiAgcHVibGljIHN0YXRpYyBib29sIEVuYWJsZVByaXZpbGVnZShsb25nIHByb2Nlc3NIYW5kbGUsIHN0cmluZyBwcml2aWxlZ2UsIGJvb2wgZGlzYWJsZSkNCiAgew0KICAgYm9vbCByZXRWYWw7DQogICBUb2tQcml2MUx1aWQgdHA7DQogICBJbnRQdHIgaHByb2MgPSBuZXcgSW50' +
  'UHRyKHByb2Nlc3NIYW5kbGUpOw0KICAgSW50UHRyIGh0b2sgPSBJbnRQdHIuWmVybzsNCiAgIHJldFZhbCA9IE9wZW5Qcm9jZXNzVG9rZW4oaHByb2MsIFRPS0VOX0FESlVTVF9QUklWSUxFR0VTIHwgVE9LRU5fUVVFUlksIHJlZiBodG9rKTsNCiAgIHRwLkNvdW50ID0gMTsNCiAgIHRwLkx1aWQgPSAwOw0KICAgaWYoZGlzYWJsZSkNCi' +
  'AgIHsNCiAgICB0cC5BdHRyID0gU0VfUFJJVklMRUdFX0RJU0FCTEVEOw0KICAgfQ0KICAgZWxzZQ0KICAgew0KICAgIHRwLkF0dHIgPSBTRV9QUklWSUxFR0VfRU5BQkxFRDsNCiAgIH0NCiAgIHJldFZhbCA9IExvb2t1cFByaXZpbGVnZVZhbHVlKG51bGwsIHByaXZpbGVnZSwgcmVmIHRwLkx1aWQpOw0KICAgcmV0VmFsID0gQWRqdXN0' +
  'VG9rZW5Qcml2aWxlZ2VzKGh0b2ssIGZhbHNlLCByZWYgdHAsIDAsIEludFB0ci5aZXJvLCBJbnRQdHIuWmVybyk7DQogICByZXR1cm4gcmV0VmFsOw0KICB9DQogfQ0KJ0ANCg0KICRwcm9jZXNzSGFuZGxlID0gKEdldC1Qcm9jZXNzIC1pZCAkUHJvY2Vzc0lkKS5IYW5kbGUNCiAkdHlwZSA9IEFkZC1UeXBlICRkZWZpbml0aW9uIC1QYX' +
  'NzVGhydQ0KICR0eXBlWzBdOjpFbmFibGVQcml2aWxlZ2UoJHByb2Nlc3NIYW5kbGUsICRQcml2aWxlZ2UsICREaXNhYmxlKQ0KfQ0KDQpFbmFibGUtUHJpdmlsZWdlIFNlVGFrZU93bmVyc2hpcFByaXZpbGVnZSANCg0KJHJlZ0tleVBhdGggPSAiPHg+Ig0KJGFkbWluID0gIkFkbWluaXN0cmF0b3JzIg0KDQokcmVnS2V5ID0gW01pY3Jv' +
  'c29mdC5XaW4zMi5SZWdpc3RyeV06OkxvY2FsTWFjaGluZS5PcGVuU3ViS2V5KCRyZWdLZXlQYXRoLFtNaWNyb3NvZnQuV2luMzIuUmVnaXN0cnlLZXlQZXJtaXNzaW9uQ2hlY2tdOjpSZWFkV3JpdGVTdWJUcmVlLFtTeXN0ZW0uU2VjdXJpdHkuQWNjZXNzQ29udHJvbC5SZWdpc3RyeVJpZ2h0c106OlRha2VPd25lcnNoaXApDQokcmVnQU' +
  'NMID0gJHJlZ0tleS5HZXRBY2Nlc3NDb250cm9sKCkNCiRyZWdBQ0wuU2V0T3duZXIoW1N5c3RlbS5TZWN1cml0eS5QcmluY2lwYWwuTlRBY2NvdW50XSRhZG1pbikNCiRyZWdLZXkuU2V0QWNjZXNzQ29udHJvbCgkcmVnQUNMKQ0KDQokcmVnS2V5ID0gW01pY3Jvc29mdC5XaW4zMi5SZWdpc3RyeV06OkxvY2FsTWFjaGluZS5PcGVuU3Vi' +
  'S2V5KCRyZWdLZXlQYXRoLFtNaWNyb3NvZnQuV2luMzIuUmVnaXN0cnlLZXlQZXJtaXNzaW9uQ2hlY2tdOjpSZWFkV3JpdGVTdWJUcmVlLFtTeXN0ZW0uU2VjdXJpdHkuQWNjZXNzQ29udHJvbC5SZWdpc3RyeVJpZ2h0c106OkNoYW5nZVBlcm1pc3Npb25zKQ0KJHJlZ0FDTCA9ICRyZWdLZXkuR2V0QWNjZXNzQ29udHJvbCgpDQokcmVnUn' +
  'VsZSA9IE5ldy1PYmplY3QgU3lzdGVtLlNlY3VyaXR5LkFjY2Vzc0NvbnRyb2wuUmVnaXN0cnlBY2Nlc3NSdWxlICgkYWRtaW4sIkZ1bGxDb250cm9sIiwiQ29udGFpbmVySW5oZXJpdCIsIk5vbmUiLCJBbGxvdyIpDQokcmVnQUNMLlNldEFjY2Vzc1J1bGUoJHJlZ1J1bGUpDQokcmVnS2V5LlNldEFjY2Vzc0NvbnRyb2woJHJlZ0FDTCk=';

// The above is base64 encoded version of this PowerShell script template, that is
// used to take ownership and reset the permissions of a given \Services registry key
// in order to fix it.
// The code:
(*
   function Enable-Privilege {
   param(
    [ValidateSet(
     "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
     "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
     "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
     "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
     "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
     "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
     "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
     "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
     "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
     "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
     "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
    $Privilege,
    $ProcessId = $pid,
    [Switch] $Disable
   )

   $definition = @'
   using System;
   using System.Runtime.InteropServices;

   public class AdjPriv
   {
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
     ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TokPriv1Luid
    {
     public int Count;
     public long Luid;
     public int Attr;
    }

    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
    {
     bool retVal;
     TokPriv1Luid tp;
     IntPtr hproc = new IntPtr(processHandle);
     IntPtr htok = IntPtr.Zero;
     retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
     tp.Count = 1;
     tp.Luid = 0;
     if(disable)
     {
      tp.Attr = SE_PRIVILEGE_DISABLED;
     }
     else
     {
      tp.Attr = SE_PRIVILEGE_ENABLED;
     }
     retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
     retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
     return retVal;
    }
   }
  '@

   $processHandle = (Get-Process -id $ProcessId).Handle
   $type = Add-Type $definition -PassThru
   $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)
  }

  Enable-Privilege SeTakeOwnershipPrivilege

  $regKeyPath = "SYSTEM\CurrentControlSet\Services\<x>"
  $serviceName = "<x>"
  $admin = "Administrators"

  $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($regKeyPath,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::TakeOwnership)
  $regACL = $regKey.GetAccessControl()
  $regACL.SetOwner([System.Security.Principal.NTAccount]$admin)
  $regKey.SetAccessControl($regACL)

  $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($regKeyPath,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions)
  $regACL = $regKey.GetAccessControl()
  $regRule = New-Object System.Security.AccessControl.RegistryAccessRule ($admin,"FullControl","ContainerInherit","None","Allow")
  $regACL.SetAccessRule($regRule)
  $regKey.SetAccessControl($regACL)

Set-Service -Name $serviceName -Status running -StartupType automatic
*)

Var
 i        : Integer;
 j        : Integer;
 Filename : String;
 Content  : String;
 ServName : String;
 TmpList  : TStringList;
 Base64   : TBase64Encoding;
begin

 TmpList := TStringList.Create;

 Try
  Base64 := TBase64Encoding.Create();
  Content := Base64.Decode(PS_SCRIPT);
 Except
  ;
 End;


 for i := Low(ServiceNamesArr_X) to High(ServiceNamesArr_X) do
 begin
   if FServiceCheckboxes[i].Checked = False then Continue;

   ServName := _x(ServiceNamesArr_X[i]);
   if Analyze_System_Service_IsOK(ServName) = False then
   begin
    If IsByDefaultReadOnlyServKey(ServName) then Continue;
   end else Continue;

   TmpList.Clear;
   TmpList.Add( StringReplace(Content, '<x>', ServName, [rfReplaceAll, rfIgnoreCase]) );

   for j := Low(ServiceKeySubDirsX) to High(ServiceKeySubDirsX) do
    TmpList.Add( StringReplace(Content, '<x>', ServName +'\'+ _x(ServiceKeySubDirsX[j]), [rfReplaceAll, rfIgnoreCase]) );

   Try
     Filename := GetTempDir() + 'UpdateFixer_Can_Be_Deleted_ix' + IntToStr(i) + '_' + IntToStr(GetTickCount) + _x(GLOB_Crypt_ps1);
     TmpList.SaveToFile(Filename);

     if DEBUG_STORE_BAT = 1 then TmpList.SaveToFile(GetDesktopDir() + 'init_' + IntToStr(i) + _x(GLOB_Crypt_ps1));

     RunPSFileAndWait(Filename);
   Except
     ;
   End;

   Try
    if FileExists(Filename) then DeleteFile(Filename);
   Except
     ;
   End;
 end;

 TmpList.Free;
end;

Procedure TMainForm.Process_Init_Bat();
const
 //BaseKey = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\';
 BaseKeyX = '!QkBJVFFDX1JTX0tYV1RQUFReQE5HTHRkb39nUFRVTUdeaENDWl1fXWFWQGllUkpPU1hZTmI=';

 //RegIniSuffix =  ' [1 7 11 17 21]';
 RegIniSuffixX = '!KlA9LTkvISAyIiM1JCZF';

Var
 i : Integer;
 j : Integer;
 Filename1  : String;
 Filename2  : String;
 RegIniFile : TStringList;
 InitBat    : TStringList;
Begin

 Filename1 := GetTempDir() + 'UpdateFixer_can_be_deleted_i1_' + IntToStr(GetTickCount) + '.txt';
 Filename2 := GetTempDir() + 'UpdateFixer_can_be_deleted_i1_' + IntToStr(GetTickCount) + '.bat';

 {$IFDEF Debug_GenerateDebugLog}
   DebugLog('Process_Init_Bat Filename1: ' + Filename1);
   DebugLog('Process_Init_Bat Filename2: ' + Filename2);
 {$ENDIF}

 RegIniFile := TStringList.Create;

 for i := Low(ServiceNamesArr_X) to High(ServiceNamesArr_X) do
   if FServiceCheckboxes[i].Checked then
   begin
     RegIniFile.Add(_x(BaseKeyX) + _x(ServiceNamesArr_X[i]) + _x(RegIniSuffixX));

     for j := Low(ServiceKeySubDirsX) to High(ServiceKeySubDirsX) do
       RegIniFile.Add(_x(BaseKeyX) + _x(ServiceNamesArr_X[i]) +'\'+ _x(ServiceKeySubDirsX[j]) + _x(RegIniSuffixX));
   end;

 RegIniFile.SaveToFile(Filename1);
 if DEBUG_STORE_BAT = 1 then RegIniFile.SaveToFile( GetDesktopDir() + 'reg_ini_txt0.txt' );

 RegIniFile.Free;

 InitBat := TStringList.Create;
 InitBat.Add(_x(GLOB_Crypt_RegIni) + Filename1 + '  > NUL 2>&1');
 InitBat.Add(_x(GLOB_Crypt_RegIni) + '"' + Filename1 + '"  > NUL 2>&1');
 if DEBUG_STORE_BAT = 1 then InitBat.SaveToFile( GetDesktopDir() + 'reg_init.bat' );

 InitBat.SaveToFile(Filename2);
 InitBat.Free;

 RunBatchFileAndWait(Filename2);


 if DEBUG_STORE_BAT <> 1 then
 begin
   Try
    if FileExists_Cached(Filename1) then DeleteFile(Filename1);
    if FileExists_Cached(Filename2) then DeleteFile(Filename2);
   Except
    ;
   End;
 end;

End;

Procedure TMainForm.Process_Services();
const
 //CMD_Base = '@sc.exe config <x> start= auto > NUL 2>&1';
 CMD_BaseX = '!SnhvI2t3dTFxfHpzf3A4JWIlPG5qflJVHwNFUFJICBcKZXlhDh0OFwM=';

 DllsArrX : Array[1 .. 37] of String =
   ('!a39g', '!f3lgYGFh', '!Z3hkeWNj', '!eWNoYm15Zw==',
    '!aHljen1qZXg=', '!YHhvf2d/ZA==', '!fGl/bnxmYGU=', '!eWh+f3th',
    '!Z3h0YGI=', '!Z3h0YGI8', '!Z3h0YGI5', '!a2h4dX59aGg=',
    '!eWRqeX56cg==', '!fWJieXx6Y2U=', '!bnh/aGBn', '!eHhtaGBn',
    '!bXtnbn1/', '!eWhvb298dQ==', '!eWdubn1/', '!aXl1fXprfHY=',
    '!ZWdpbHt7IyM=', '!ZWdpPjw=', '!eWNpYWI8Ig==', '!Y2VleX5keQ==',
    '!ZG54YWFof38=', '!fX5tfWc=', '!fX5teGthdw==', '!fX5teGthdyA=',
    '!fX5vYXp6eQ==', '!fX58fg==', '!fX58fjw=', '!fX57aGw=',
    '!e2Zrfw==', '!e2Zrf359aGg=', '!fX5vYXp6aA==',
    '!Z357aGw=', '!fX57aGx5');

{
 DllsArr: Array[1 .. 37] of String =
 ('atl', 'urlmon', 'mshtml', 'shdocvw', 'browseui', 'jscript',
  'vbscript', 'scrrun', 'msxml', 'msxml3', 'msxml6', 'actxprxy',
  'softpub', 'wintrust', 'dssenh', 'rsaenh', 'gpkcsp', 'sccbase',
  'slbcsp', 'cryptdlg', 'oleaut32', 'ole32', 'shell32', 'initpki',
  'netlogon', 'wuapi', 'wuaueng', 'wuaueng1',
  'wucltui', 'wups', 'wups2',
  'wuweb', 'qmgr', 'qmgrprxy', 'wucltux', 'muweb', 'wuwebv');
}

 //BaseKey = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\';
 BaseKeyX = '!QkBJVFFDX1JTX0tYV1RQUFReQE5HTHRkb39nUFRVTUdeaENDWl1fXWFWQGllUkpPU1hZTmI=';

 //RegIniSuffix =  ' [1 7 11 17 21]';
 RegIniSuffixX = '!KlA9LTkvISAyIiM1JCZF';

Var
 i : Integer;
 j : Integer;
 Filename : String;
 RegIniFile : TStringList;
Begin


 Filename := GetTempDir() + 'UpdateFixer_can_be_deleted_' + IntToStr(GetTickCount) + '.txt';
 RegIniFile := TStringList.Create;

 for i := Low(ServiceNamesArr_X) to High(ServiceNamesArr_X) do
   if FServiceCheckboxes[i].Checked then
   begin
     RegIniFile.Add(_x(BaseKeyX) + _x(ServiceNamesArr_X[i]) + _x(RegIniSuffixX));

     for j := Low(ServiceKeySubDirsX) to High(ServiceKeySubDirsX) do
       RegIniFile.Add(_x(BaseKeyX) + _x(ServiceNamesArr_X[i]) +'\'+ _x(ServiceKeySubDirsX[j]) + _x(RegIniSuffixX));
   end;

 RegIniFile.SaveToFile(Filename);
 if DEBUG_STORE_BAT = 1 then RegIniFile.SaveToFile( GetDesktopDir() + 'reg_ini_txt1.txt' );

 RegIniFile.Free;

 FBatFile.Add(_x(GLOB_Crypt_RegIni) + Filename + '  > NUL 2>&1');
 FBatFile.Add(_x(GLOB_Crypt_RegIni) + '"' + Filename + '"  > NUL 2>&1');
 FBatFile.Add('@' + _x(GLOB_Crypt_Timeout));

 for i := Low(ServiceNamesArr_X) to High(ServiceNamesArr_X) do
   if FServiceCheckboxes[i].Checked then
      FBatFile.Add( StringReplace(_x(CMD_BaseX), '<x>', _x(ServiceNamesArr_X[i]), [rfReplaceAll, rfIgnoreCase]) );


 for i := Low(DllsArrX) to High(DllsArrX) do
 begin
    Filename := _x(DllsArrX[i]) + '.dll';

    if FileExists_Cached('C:\Windows\System32\' + Filename) or
       FileExists_Cached('C:\Windows\SysWOW64\' + Filename) then
       FBatFile.Add(_x('!Snlpan15YiIgPXFtczc3ajo=') + Filename + ' > NUL 2>&1');

       //FBatFile.Add('@regsvr32.exe /s ' + Filename + ' > NUL 2>&1');
 end;

 FBatFile.Add('@' + _x(GLOB_Crypt_Timeout));

End;

procedure TMainForm.PopupMenu_RecPopup(Sender: TObject);
begin

 if pnlNothing.Visible then
 begin
  SelectAll1.Visible  := False;
  SelectNone1.Visible := False;
 end;

end;

Procedure TMainForm.Process_Delivery_Files();

// Todo: replace the 'C:\Windows\' paths with detected Windows path,
// which in 99.99% cases is 'C:\Windows\', though

const
 CMD0a  = '"C:\Windows\SoftwareDistribution\" > NUL 2>&1';
 CMD0b  = '"C:\Windows\System32\CatRoot2\" > NUL 2>&1';
 CMD0c  = '"C:\Windows\Logs\WindowsUpdate\" > NUL 2>&1';
 CMD0d  = '"C:\Windows\WinSxS\pending.xml" > NUL 2>&1';
 CMD0e  = '"%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\" > NUL 2>&1';
 CMD0f  = '"%ALLUSERSPROFILE%\Microsoft\Network\Downloader\" > NUL 2>&1';
 CMD0eb = '"%ALLUSERSPROFILE%\Application Data\Microsoft\Network\" > NUL 2>&1';
 CMD0fb = '"%ALLUSERSPROFILE%\Microsoft\Network\" > NUL 2>&1';
 CMD0ec = '"%ALLUSERSPROFILE%\Application Data\Microsoft\" > NUL 2>&1';
 CMD0fc = '"%ALLUSERSPROFILE%\Microsoft\" > NUL 2>&1';

 CMD0g  = '"C:\Windows\SoftwareDistribution\*" /D > NUL 2>&1';
 CMD0h  = '"C:\Windows\Logs\WindowsUpdate\*" /D > NUL 2>&1';
 CMD0k  = '"C:\Windows\WinSxS\pending.xml" > NUL 2>&1';
 CMD0i  = '"%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\*" /D > NUL 2>&1';
 CMD0j  = '"%ALLUSERSPROFILE%\Microsoft\Network\Downloader\*" /D > NUL 2>&1';
 CMD0l  = '"C:\Windows\WindowsUpdate.log" > NUL 2>&1';
 CMD0ib = '"%ALLUSERSPROFILE%\Application Data\Microsoft\*" /D > NUL 2>&1';
 CMD0jb = '"%ALLUSERSPROFILE%\Microsoft\*" /D > NUL 2>&1';

 CMD1 = '"C:\Windows\SoftwareDistribution\Download\*" > NUL 2>&1';
 CMD2 = '"C:\Windows\SoftwareDistribution\DataStore\*" > NUL 2>&1';
 CMD3 = '"C:\Windows\SoftwareDistribution\SLS\*" > NUL 2>&1';
 CMD4 = '"%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\qmgr*.dat" > NUL 2>&1';
 CMD5 = '"%ALLUSERSPROFILE%\Microsoft\Network\Downloader\qmgr*.dat" > NUL 2>&1';
 CMD6 = '"C:\Windows\System32\CatRoot2\*" > NUL 2>&1';
 CMD7 = '"C:\Windows\Logs\WindowsUpdate\*" > NUL 2>&1';
 CMD8 = '"C:\Windows\WindowsUpdate.log" > NUL 2>&1';

Var
 i : Integer;
 Dir : String;
 TmpDir : String;
Begin


 FBatFile.Add( _x(GLOB_Crypt_TakeOwn) + CMD0a);
 FBatFile.Add( _x(GLOB_Crypt_TakeOwn) + CMD0b);
 FBatFile.Add( _x(GLOB_Crypt_TakeOwn) + CMD0c);
 FBatFile.Add( _x(GLOB_Crypt_TakeOwn) + CMD0d);
 FBatFile.Add( _x(GLOB_Crypt_TakeOwn) + StringReplace(CMD0e, '%ALLUSERSPROFILE%', FAllUserProfile, [rfIgnoreCase]));
 FBatFile.Add( _x(GLOB_Crypt_TakeOwn) + StringReplace(CMD0f, '%ALLUSERSPROFILE%', FAllUserProfile, [rfIgnoreCase]));
 FBatFile.Add( _x(GLOB_Crypt_TakeOwn) + StringReplace(CMD0eb, '%ALLUSERSPROFILE%', FAllUserProfile, [rfIgnoreCase]));
 FBatFile.Add( _x(GLOB_Crypt_TakeOwn) + StringReplace(CMD0fb, '%ALLUSERSPROFILE%', FAllUserProfile, [rfIgnoreCase]));
 FBatFile.Add( _x(GLOB_Crypt_TakeOwn) + StringReplace(CMD0ec, '%ALLUSERSPROFILE%', FAllUserProfile, [rfIgnoreCase]));
 FBatFile.Add( _x(GLOB_Crypt_TakeOwn) + StringReplace(CMD0fc, '%ALLUSERSPROFILE%', FAllUserProfile, [rfIgnoreCase]));

 FBatFile.Add( _x(GLOB_Crypt_Attrib) + CMD0g);
 FBatFile.Add( _x(GLOB_Crypt_Attrib) + CMD0k);
 FBatFile.Add( _x(GLOB_Crypt_Attrib) + StringReplace(CMD0i, '%ALLUSERSPROFILE%', FAllUserProfile, [rfIgnoreCase]));
 FBatFile.Add( _x(GLOB_Crypt_Attrib) + StringReplace(CMD0j, '%ALLUSERSPROFILE%', FAllUserProfile, [rfIgnoreCase]));
 FBatFile.Add( _x(GLOB_Crypt_Attrib) + StringReplace(CMD0ib, '%ALLUSERSPROFILE%', FAllUserProfile, [rfIgnoreCase]));
 FBatFile.Add( _x(GLOB_Crypt_Attrib) + StringReplace(CMD0jb, '%ALLUSERSPROFILE%', FAllUserProfile, [rfIgnoreCase]));
 FBatFile.Add( _x(GLOB_Crypt_Attrib) + CMD0k);
 FBatFile.Add( _x(GLOB_Crypt_Attrib) + CMD0l);

 FBatFile.Add( _x(GLOB_Crypt_Del) + CMD1);
 FBatFile.Add( _x(GLOB_Crypt_Del) + CMD2);
 FBatFile.Add( _x(GLOB_Crypt_Del) + CMD3);
 FBatFile.Add( _x(GLOB_Crypt_Del) + StringReplace(CMD4, '%ALLUSERSPROFILE%', FAllUserProfile, [rfIgnoreCase]));
 FBatFile.Add( _x(GLOB_Crypt_Del) + StringReplace(CMD5, '%ALLUSERSPROFILE%', FAllUserProfile, [rfIgnoreCase]));
 FBatFile.Add( _x(GLOB_Crypt_Del) + CMD6);
 FBatFile.Add( _x(GLOB_Crypt_Del) + CMD7);
 FBatFile.Add( _x(GLOB_Crypt_Del) + CMD8);


 // A curious case of Windows Update not working in Windows 8 because of missing
 // C:\Windows\System32\Macromed\Flash
 // Note: I have tested in multiple Win8 VM's that Windows Update does work with this directory missing
 // However, since this user is reporting this issue AND there is no harm in re-creating this missing
 // directory in Windows 8, hence this is being done.
 //
 // Source:
 // In our case it was that ... drumroll ... %System32%\Macromed\Flash directory was missing. Created it, re-run updates - et voila - all updates went through.
 // https://www.reddit.com/r/sysadmin/comments/zl7pbg/psa_windows_update_failing_with_0x800f0922_how_to/
 if FastPosExB('Windows 8', FWinVer) then
 begin
  FBatFile.Add('@mkdir C:\Windows\System32\Macromed > NUL 2>&1');
  FBatFile.Add('@mkdir C:\Windows\System32\Macromed\Flash > NUL 2>&1');
 end;

 if FastPosExB('Windows 1', FWinVer) then
 begin

  For i := Low(Win10DeliveryDirs) to High(Win10DeliveryDirs) do
  begin
   Dir := StringReplace( Win10DeliveryDirs[i], '<x>', FAllUserProfile, [rfIgnoreCase]);

   {$IFDEF Debug_GenerateDebugLog}
     DebugLog('Process_Delivery_Files: ' + Dir);
   {$ENDIF}

   If DirectoryExists_Cached(Dir) = False then
   begin
    TmpDir := UpOneDir(Dir);
    If DirectoryExists_Cached(TmpDir) = False then FBatFile.Add('@mkdir "'+TmpDir+'" > NUL 2>&1');

    FBatFile.Add('@mkdir "'+Dir+'" > NUL 2>&1');
   End;
  end;
 end;

End;

// Expands Windows environment variable into the full path
// Note: Windows environment variable paths typically do not include a trailing slash!
Function TMainForm.ExpandEnvVariable(const EnvVar : String) : String;
var
 chrResult : array[0 .. 1023] of Char;
 wrdReturn : DWORD;
begin

 if FEnvVars.TryGetValue(EnvVar, Result) then EXIT;

 Result := '';
 wrdReturn := ExpandEnvironmentStrings(PChar(EnvVar), chrResult, 1024);
 If wrdReturn <> 0 then Result := Trim(chrResult);

 FEnvVars.Add(EnvVar, Result);
 {$IFDEF Debug_GenerateDebugLog} DebugLog('ExpandEnvVariable: ' + EnvVar + ' => ' + Result); {$ENDIF}

end;


Function TMainForm.GetAllUserDirs() : TStringList;
var
 Path : String;
begin

 Result := TStringList.Create;

 Try
   for Path in TDirectory.GetDirectories('c:\users\') do
   begin
    If Path <> '' then Result.Add(Path + '\');
   End;
 Except
  ; // Accessing hard drives can always fail, but there is no need to worry about that
 End;

 {$IFDEF Debug_GenerateDebugLog}
   DebugLog('GetAllUserDirs: ' + Result.Text);
 {$ENDIF}


end;

Procedure TMainForm.Process_Temporary_Files();
Var
 i        : Integer;
 Dir      : String;
 Dirs     : TStringList;
 UserDirs : TStringList;
Begin

 // Possible room for improvement: Only delete files within the temporary directories
 // that are created over X days ago and not modified in the last Z days.
 // However, this probably cannot be done via batch file
 // Using batch file for this deletion is easier to implement as it doesn't require us to
 // handle UI progress updates in case of massive amounts of temporary files and the process
 // taking a non-trivial amount of time.

 Dirs := TStringList.Create; Dirs.CaseSensitive := False; Dirs.Sorted := True; Dirs.Duplicates := dupIgnore;
 UserDirs := GetAllUserDirs();

 for i := 0 to UserDirs.Count-1 do
 begin
  Dir := UserDirs[i] + 'temp\';
  Dirs.Add(Dir);

  Dir := UserDirs[i] + 'AppData\Local\temp\';
  Dirs.Add(Dir);

  Dir := UserDirs[i] + 'AppData\LocalLow\temp\';
  Dirs.Add(Dir);

  Dir := UserDirs[i] + 'AppData\Roaming\temp\';
  Dirs.Add(Dir);
 end;

 Dir := ExpandEnvVariable('%TEMP%');
 if Length(Dir) > 3 then Dirs.Add(Dir);

 Dir := ExpandEnvVariable('%TMP%');
 if Length(Dir) > 3 then Dirs.Add(Dir);

 Dirs.Add('c:\windows\temp\');
 Dirs.Add('c:\windows\tmp\');
 Dirs.Add('c:\windows\CbsTemp\');
 Dirs.Add( GetTempDir() );

 Dir := ExpandEnvVariable('%LOCALAPPDATA%');
 if Length(Dir) > 3 then Dirs.Add(Dir + '\temp\');

 for dir in Dirs do
 begin
  if Length(Dir) < 5 then Continue;

  {$IFDEF Debug_GenerateDebugLog}
    DebugLog('Process_Temporary_Files: ' + Dir);
  {$ENDIF}

  FBatFile.Add( _x(GLOB_Crypt_Attrib) + '"'+EnsureTrail(Dir)+'*" /D > NUL 2>&1');
  FBatFile.Add( _x(GLOB_Crypt_Del) + '"'+EnsureTrail(Dir)+'*" > NUL 2>&1');
 end;

 Dirs.Free;
End;


procedure TMainForm.btnRebootClick(Sender: TObject);
begin
 {$IFDEF Debug_GenerateDebugLog} DebugLog('Button Click: Reboot');{$ENDIF}

 // There can be a delay when performing the actual reboot,
 // hence, hide the app window not to make it seem the app is frozen:
 MainForm.AlphaBlend := True;
 Application.ProcessMessages;

 MyExitWindows(2);
end;


Function TMainForm.GetCurrentUserDir() : String;
begin
 Result := 'C:' + ExpandEnvVariable('%HOMEPATH%') + '\';
end;

Function TMainForm.GetDesktopDir() : String;
begin

 if FDesktopDir <> '' then
 begin
  Result := FDesktopDir;
  Exit;
 end;

 Result := GetCurrentUserDir() + 'Desktop\';
 FDesktopDir := Result;

end;

Function TMainForm.GetTempDir() : String;
var
 Len     : Integer;
 Buffer  : Array[0..MAX_PATH+1] of Char;
begin

 if FTempDir <> '' then
 begin
  Result := FTempDir;
  Exit;
 end;

 Result := '';

 Len := GetTempPath(MAX_PATH, Buffer);
 Result := Trim(String(Copy(Buffer, Low(Buffer), Len)));

 // Failsafe:
 if Result = '' then Result := ExpandEnvVariable('%TEMP%');
 if Result = '' then Result := ExpandEnvVariable('%TMP%');

 Result := EnsureTrail(Result);

 FTempDir := Result;

 {$IFDEF Debug_GenerateDebugLog} DebugLog('GetTempDir: ' + FTempDir); {$ENDIF}

end;


Function IsProcessRunningByPID(const PID : Cardinal) : Boolean;
Var
 ProcessHndle: THandle;
Begin
 {$IFDEF EnablePerformanceLog} try PerfLog_SectionBegin('ProcessUtils.IsProcessRunningByPID', nil, TRUE); {$ENDIF}

 Result := False;
 if PID < 1 then EXIT;

 Try
  ProcessHndle := OpenProcess(PROCESS_TERMINATE, False, PID);

  if ProcessHndle > 0 then
  begin
   Result := True;
   CloseHandle(ProcessHndle);
  end;
 Except
  Exit;
 End;

 {$IFDEF EnablePerformanceLog} finally PerfLog_SectionEnd('ProcessUtils.IsProcessRunningByPID'); end; {$ENDIF}
End;


function TMainForm.RunBatchFileAndWait_GetCount() : Integer;
var
  ContinueLoop: BOOL;
  FSnapshotHandle: THandle;
  FProcessEntry32: TProcessEntry32;
  Filename : String;
  CmdExe : String;
  AIL : Integer;
begin

  CmdExe := _x(GLOB_Crypt_CmdExe);
  FSnapshotHandle := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  FProcessEntry32.dwSize := SizeOf(FProcessEntry32);
  ContinueLoop := Process32First(FSnapshotHandle, FProcessEntry32);
  Result := 0;
  AIL := 0;

  while Integer(ContinueLoop) <> 0 do
  begin
    Filename := FastLowerCase_Trim(FProcessEntry32.szExeFile);
    if Filename.EndsWith(CmdExe) then Inc(Result);
    ContinueLoop := Process32Next(FSnapshotHandle, FProcessEntry32);

    Application.ProcessMessages;
    Inc(AIL);
    if AIL > 9999 then Break;
  end;
  CloseHandle(FSnapshotHandle);
end;

// Start a batch file via cmd.exe and waits for it to run
Procedure TMainForm.RunBatchFileAndWait(Const FileName: string);
const
 MAX_WAIT_SEC = 60*5;

var
 sei       : TShellExecuteInfo;
 TmpStr0   : String;
 TmpStr1   : String;
 TmpStr2   : String;
 bRes      : Boolean;
 OrigCount : Integer;
 Waited    : Integer;
 Start     : UInt64;
 LastProg  : UInt64;
 ExitCode  : DWORD;
begin
 {$IFDEF Debug_GenerateDebugLog} DebugLog('RunBatchFileAndWait Start: ' + FileName);{$ENDIF}

 if DEBUG_NO_BATCH = 1 then EXIT;

 Try
  if FileExists(Filename) = False then
  begin
   {$IFDEF Debug_ExceptionMessages} ShowMessage('RunBatchFileAndWait File not found: ' + Filename); {$ENDIF}
   EXIT;
  end;
 Except
  Exit;
 End;

 OrigCount := RunBatchFileAndWait_GetCount(); // Number of CMD.exe instances before
 Start := GetTickCount64();

 // Method one:
 TmpStr0 := _x(GLOB_Crypt_Runas);
 TmpStr1 := _x(GLOB_Crypt_CmdExe);

 //TmpStr2 := ' /q /c "' + Trim(Filename) + '"';
 TmpStr2 := _x('!KiR9LSFsMDM=')  + Trim(Filename) + '"';

 bRes := False;

 Try
    ZeroMemory(@sei, SizeOf(sei));
    sei.cbSize := SizeOf(TShellExecuteInfo);
    sei.Wnd    := MainForm.Handle;
    sei.fMask  := SEE_MASK_FLAG_NO_UI;
    sei.lpVerb := PChar(TmpStr0);
    sei.lpFile := PChar(TmpStr1);
    sei.lpParameters := PChar(TmpStr2);
    sei.nShow := SW_HIDE;
    bRes := ShellExecuteEx(@sei);
    Sleep(500);
 Except
  ;
 End;

 // Sometimes the above just fails.
 // Method two:
 If bRes = False then
 begin
    ShellExecute(MainForm.Handle, PChar(_x(GLOB_Crypt_Runas)), PChar(TmpStr1), PChar(TmpStr2), nil, SW_HIDE);
    sei.hProcess := 0;
 end;

 LastProg := Start;

 // The waiting for the process to run via the sei.hProcess method
 // sometimes fails and I don't really have the time to find out why,
 // hence, as a failsafe method, we simply monitor the amount of
 // cmd.exe instances and ass-u-me that when the number of cmd.exe
 // instances after starting new instance is lower than before starting new instance,
 // the new instance has completed.
 // Naturally, this is not bulleproof if the system happens to be running other
 // cmd.exe instances at the same time user runs this app
 // Todo: Figure out why waiting via the sei.hProcess method sometimes fails.

 while True do
 begin
  Sleep(400); Application.ProcessMessages;
  If GetTickCount64() - LastProg > 4000 then
  begin
   UI_IncProgress();
   LastProg := GetTickCount64();
  end;

  Waited := (GetTickCount64() - Start) div 1000;
  if Waited > MAX_WAIT_SEC then Break; // Timeout
  if RunBatchFileAndWait_GetCount() <= OrigCount then Break; // Process completed


  If (Application = nil) or (Application.Terminated) or (MainForm.Visible = False) then Break;

  If sei.hProcess <> 0 then
  begin
   ExitCode := 0;
   GetExitCodeProcess(sei.hProcess, ExitCode);

   If (ExitCode <> STILL_ACTIVE) then Break;
  End;
 end;

 {$IFDEF Debug_GenerateDebugLog} DebugLog('RunBatchFileAndWait Done after ' + IntToStr((GetTickCount64() - Start) div 1000) + ' seconds');{$ENDIF}

End;



function TMainForm.RunPSFileAndWait_GetCount() : Integer;
var
  ContinueLoop: BOOL;
  FSnapshotHandle: THandle;
  FProcessEntry32: TProcessEntry32;
  Filename  : String;
  Powerhell : String;
  AIL : Integer;
begin

  Powerhell := _x(GLOB_Crypt_Powerhell);
  FSnapshotHandle := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  FProcessEntry32.dwSize := SizeOf(FProcessEntry32);
  ContinueLoop := Process32First(FSnapshotHandle, FProcessEntry32);
  Result := 0;
  AIL := 0;

  while Integer(ContinueLoop) <> 0 do
  begin
    Filename := FastLowerCase_Trim(FProcessEntry32.szExeFile);
    if Filename.EndsWith(Powerhell) then Inc(Result);
    ContinueLoop := Process32Next(FSnapshotHandle, FProcessEntry32);

    Application.ProcessMessages;
    Inc(AIL);
    if AIL > 9999 then Break;
  end;
  CloseHandle(FSnapshotHandle);
end;


// Start a PowerShell script file via powershell.exe and waits for it to run
Procedure TMainForm.RunPSFileAndWait(Const FileName: string);
const
 MAX_WAIT_SEC = 60*5;

var
 sei       : TShellExecuteInfo;
 TmpStr0   : String;
 TmpStr1   : String;
 TmpStr2   : String;
 bRes      : Boolean;
 OrigCount : Integer;
 Waited    : Integer;
 Start     : UInt64;
 LastProg  : UInt64;
 ExitCode  : DWORD;
begin
 {$IFDEF Debug_GenerateDebugLog} DebugLog('RunPSFileAndWait Start: ' + FileName);{$ENDIF}

 if DEBUG_NO_BATCH = 1 then EXIT;

 Try
  if FileExists(Filename) = False then
  begin
   {$IFDEF Debug_ExceptionMessages} ShowMessage('RunPSFileAndWait File not found: ' + Filename); {$ENDIF}
   EXIT;
  end;
 Except
  Exit;
 End;

 // 'powershell.exe -noprofile -executionpolicy bypass -command "'+Filename+'"');

 OrigCount := RunPSFileAndWait_GetCount();
 Start := GetTickCount64();

 // Method one:
 TmpStr0 := _x(GLOB_Crypt_Runas);
 TmpStr1 := _x(GLOB_Crypt_Powerhell); //'powershell.exe';

 //TmpStr2 := ' -noprofile -executionpolicy bypass -command "' + Trim(Filename) + '"';
 TmpStr2 := ' ' + _x('!J2VjfXxgdnh+djQ4c299em9vdXJwb09NS0BdBUReWEhZWAwATUBdXFNdUA==') + ' "' + Trim(Filename) + '"';
 bRes := False;

 Try
    ZeroMemory(@sei, SizeOf(sei));
    sei.cbSize := SizeOf(TShellExecuteInfo);
    sei.Wnd    := MainForm.Handle;
    sei.fMask  := {SEE_MASK_FLAG_DDEWAIT or} SEE_MASK_FLAG_NO_UI;
    sei.lpVerb := PChar(TmpStr0);
    sei.lpFile := PChar(TmpStr1); // PAnsiChar;
    sei.lpParameters := PChar(TmpStr2); // PAnsiChar;
    sei.nShow := SW_HIDE;
    bRes := ShellExecuteEx(@sei);
 Except
  ;
 End;

 // Method two:
 If bRes = False then
 begin
    ShellExecute(MainForm.Handle, PChar(_x(GLOB_Crypt_Runas)), PChar(TmpStr1), PChar(TmpStr2), nil, SW_HIDE);
    sei.hProcess := 0;
 end;

 LastProg := Start;

 while True do
 begin
  Application.ProcessMessages;
  If GetTickCount64() - LastProg > 4000 then
  begin
   UI_IncProgress();
   LastProg := GetTickCount64();
  end;

  Waited := (GetTickCount64() - Start) div 1000;
  if Waited > MAX_WAIT_SEC then Break; // Timeout
  if RunPSFileAndWait_GetCount() <= OrigCount then Break; // Process completed
  If (Application = nil) or (Application.Terminated) or (MainForm.Visible = False) then Break;

  If sei.hProcess <> 0 then
  begin
   ExitCode := 0;
   GetExitCodeProcess(sei.hProcess, ExitCode);

   If (ExitCode <> STILL_ACTIVE) then Break;
  End;
 end;

 {$IFDEF Debug_GenerateDebugLog} DebugLog('RunPSFileAndWait Done after ' + IntToStr((GetTickCount64() - Start) div 1000) + ' seconds');{$ENDIF}

End;



Function TMainForm.GetDriveFreeSpaceGB() : Integer;
var
 free_size  : Int64;
 total_size : Int64;
 Root : Array[0..3] of Char;
begin

 Root[0] := 'C';
 Root[1] := ':';
 Root[2] := '\';
 Root[2] := #0;

 Try
  GetDiskFreeSpaceEx(Root, Free_size, Total_size, nil);
 Except
  Exit(0);
 End;

 Result := Round(free_size / 1024 / 1024 / 1024);

 {$IFDEF Debug_GenerateDebugLog} DebugLog('GetDriveFreeSpaceGB: ' + IntToStr(Result)); {$ENDIF}

End;

Procedure TMainForm.Analyze_DeliveryDirs();
Var
 i : Integer;
begin
 FDeliveryDirsOK := True;

 if (DEBUG_SOME_ISSUES = 1) then
 begin
  FDeliveryDirsOK := False;
  Exit;
 end;

 if FastPosExB('Windows 1', FWinVer) then
 begin

  For i := Low(Win10DeliveryDirs) to High(Win10DeliveryDirs) do
  begin
   If DirectoryExists_Cached(
       StringReplace( Win10DeliveryDirs[i], '<x>', FAllUserProfile, [rfIgnoreCase])) = False then
   begin
    FDeliveryDirsOK := False;
    Break;
   end;
  end;
 end;


 If (FDeliveryDirsOK) and HasAttrib('C:\Windows\SoftwareDistribution\', faReadOnly) then FDeliveryDirsOK := False;
 If (FDeliveryDirsOK) and HasAttrib('C:\Windows\Logs\WindowsUpdate\', faReadOnly) then FDeliveryDirsOK := False;
 If (FDeliveryDirsOK) and HasAttrib(FAllUserProfile + '\Application Data\Microsoft\Network\Downloader\', faReadOnly) then FDeliveryDirsOK := False;
 If (FDeliveryDirsOK) and HasAttrib(FAllUserProfile + '\Microsoft\Network\Downloader\', faReadOnly) then FDeliveryDirsOK := False;
 If (FDeliveryDirsOK) and HasAttrib('C:\Windows\WindowsUpdate.log', faReadOnly) then FDeliveryDirsOK := False;
 If (FDeliveryDirsOK) and HasAttrib('C:\Windows\System32\CatRoot2\', faReadOnly) then FDeliveryDirsOK := False;
 If (FDeliveryDirsOK) and HasAttrib(FAllUserProfile + '\Application Data\Microsoft\Network\', faReadOnly) then FDeliveryDirsOK := False;
 If (FDeliveryDirsOK) and HasAttrib(FAllUserProfile + '\Microsoft\Network\', faReadOnly) then FDeliveryDirsOK := False;
 If (FDeliveryDirsOK) and HasAttrib(FAllUserProfile + '\Application Data\Microsoft\', faReadOnly) then FDeliveryDirsOK := False;
 If (FDeliveryDirsOK) and HasAttrib(FAllUserProfile + '\Microsoft\', faReadOnly) then FDeliveryDirsOK := False;
 If (FDeliveryDirsOK) and HasAttrib('C:\Windows\Temp\', faReadOnly) then FDeliveryDirsOK := False;
 If (FDeliveryDirsOK) and HasAttrib('C:\Windows\CbsTemp\', faReadOnly) then FDeliveryDirsOK := False;

 If (FDeliveryDirsOK) and HasAttrib('C:\Windows\WindowsUpdate.log', faHidden) then FDeliveryDirsOK := False;

 If (FDeliveryDirsOK) and HasAttrib('C:\Windows\SoftwareDistribution\', faHidden) then FDeliveryDirsOK := False;
 If (FDeliveryDirsOK) and HasAttrib('C:\Windows\Logs\WindowsUpdate\', faHidden) then FDeliveryDirsOK := False;
 If (FDeliveryDirsOK) and HasAttrib(FAllUserProfile + '\Application Data\Microsoft\Network\Downloader\', faHidden) then FDeliveryDirsOK := False;
 If (FDeliveryDirsOK) and HasAttrib(FAllUserProfile + '\Microsoft\Network\Downloader\', faHidden) then FDeliveryDirsOK := False;
 If (FDeliveryDirsOK) and HasAttrib('C:\Windows\WindowsUpdate.log', faHidden) then FDeliveryDirsOK := False;
 If (FDeliveryDirsOK) and HasAttrib('C:\Windows\System32\CatRoot2\', faHidden) then FDeliveryDirsOK := False;


 // C:\Windows\System32\Macromed\Flash
 // In our case it was that ... drumroll ... %System32%\Macromed\Flash directory was missing. Created it, re-run updates - et voila - all updates went through.
 // https://www.reddit.com/r/sysadmin/comments/zl7pbg/psa_windows_update_failing_with_0x800f0922_how_to/
 if (FDeliveryDirsOK) and (FastPosExB('Windows 8', FWinVer)) then
 begin
  if DirectoryExists_Cached('C:\Windows\System32\Macromed\Flash', False) = False then FDeliveryDirsOK := False;
 end;




end;

Procedure TMainForm.Analyze_System_Blockers();
Var
 i        : Integer;
 Dirs     : TStringList;
 UserDirs : TStringList;
 SubDirs  : TStringList;
 Dir      : String;
 Filename : String;
begin

 FBlockersFound := False;

 UserDirs := GetAllUserDirs();
 Dirs := TStringList.Create; Dirs.Sorted := True; Dirs.Duplicates := dupIgnore; Dirs.CaseSensitive := False;
 SubDirs := TStringList.Create;

 for i := 0 to UserDirs.Count-1 do
 begin
  Dir := UserDirs[i] + 'Desktop\';
  if DirectoryExists_Cached(Dir) then Dirs.Add(Dir);

  Dir := UserDirs[i] + 'Download\';
  if DirectoryExists_Cached(Dir) then Dirs.Add(Dir);

  Dir := UserDirs[i] + 'Downloads\';
  if DirectoryExists_Cached(Dir) then Dirs.Add(Dir);

  Dir := UserDirs[i] + 'Documents\';
  if DirectoryExists_Cached(Dir) then Dirs.Add(Dir);

  Dir := UserDirs[i] + 'AppData\Local\';
  if DirectoryExists_Cached(Dir) then Dirs.Add(Dir);

  Dir := UserDirs[i] + 'AppData\Locallow\';
  if DirectoryExists_Cached(Dir) then Dirs.Add(Dir);

  Dir := UserDirs[i] + 'AppData\Roaming\';
  if DirectoryExists_Cached(Dir) then Dirs.Add(Dir);
 end;

 Dirs.Add('c:\program files\');
 Dirs.Add('c:\program files (x86)\');
 Dirs.Add('c:\program files (x64)\');

 Dirs.Add( ExtractFilePath(Application.ExeName) );
 Dirs.Add( UpOneDir(ExtractFilePath(Application.ExeName)) );
 Dirs.Add( GetTempDir() );
 Dirs.Add( GetCurrentUserDir() );
 Dirs.Add( GetCurrentUserDir() + 'Desktop\' );
 Dirs.Add( GetCurrentUserDir() );
 Dirs.Add( ExpandEnvVariable('%LOCALAPPDATA%') );
 Dirs.Add( ExpandEnvVariable('%PUBLIC%') );


 for i := 0 to Dirs.Count-1 do
 begin
   if DirectoryExists_Cached(Dirs[i]) = False then Continue;

   Try
     for Dir in TDirectory.GetDirectories(Dirs[i]) do
     begin
      If Dir <> '' then SubDirs.Add(Dir + '\');
     End;
   Except
    ; // Accessing hard drives can always fail, but there is no need to worry about that
   End;

 end;


 // C:\Program Files (x86)\StopUpdates10\uninstall.bat
 // Wub_vXXX

 for i := 0 to SubDirs.Count-1 do
 begin
  Dir := ExtractTopDir(SubDirs[i]);

  if Dir.StartsWith('wub_', True) or
     StringCompare(Dir, 'wub') or
     FastPosExB('blocker', Dir) then
  begin
   if Is64bitWindows() then Filename := EnsureTrail(SubDirs[i]) + 'Wub_x64.exe'
   else Filename := EnsureTrail(SubDirs[i]) + 'Wub.exe';

   {$IFDEF Debug_GenerateDebugLog}
     DebugLog('Analyze_System_Blockers: ' + Filename);
   {$ENDIF}


   if FileExists_Cached(Filename) then
      FBlockerRemoval.Add(Filename + ' /E');


   if Is64bitWindows() then Filename := EnsureTrail(SubDirs[i]) + 'wub\Wub_x64.exe'
   else Filename := EnsureTrail(SubDirs[i]) + 'wub\Wub.exe';

   if FileExists_Cached(Filename) then
      FBlockerRemoval.Add(Filename + ' /E');

  end else

  if Dir.StartsWith('StopUpdates10', True) or
     FastPosExB('StopUpdates', Dir) then
  begin
   Filename := EnsureTrail(SubDirs[i]) + 'uninstall.bat';

   if FileExists_Cached(Filename) then
      FBlockerRemoval.Add('@call ' + Filename);
  end;
 end;

 FBlockersFound := (FBlockerRemoval.Count > 0);
 Dirs.Free;
 UserDirs.Free;
 SubDirs.Free;

end;

// A version of FileExists() that does basic input validation to ensure the input is a
// valid looking local path, as well as caches the results so same paths are not checked many times
// Also supports checking 32b/64b view of the file system
Function TMainForm.FileExists_Cached(Const InputStr : String) : Boolean;
Var
 CacheKey : String;
Begin

 if (Length(InputStr) < 5) or (InputStr[1].IsLetter = False) or (InputStr[2] <> ':') or (InputStr[3] <> '\') then EXIT(FALSE);
 if DirectoryExists_Cached(ExtractFilePath(InputStr)) = False then EXIT(FALSE);

 CacheKey := FastLowerCase(InputStr);

 if (Pos('\temp', CacheKey) = 0) and
    (Pos('\tmp', CacheKey) = 0) and
    (FExistsCache.TryGetValue(CacheKey, Result)) then Exit;

 Try
  Result := FileExists(InputStr);
 Except
  Result := False;
 End;

 if Result = False then
 begin
   Wow64_DisableRedirection();

   Try
     Try
      Result := FileExists(InputStr);
     Except
      Result := False;
     End;
   Finally
    Wow64_RestoreRedirection();
   End;
 end;

 FExistsCache.AddOrSetValue(CacheKey, Result);
End;

// A version of DirectoryExists() that does basic input validation to ensure the input is a
// valid looking local path, as well as caches the results so same paths are not checked many times
// Also supports checking 32b/64b view of the file system
Function TMainForm.DirectoryExists_Cached(Const InputStr : String; const DualModeCheck : Boolean = True) : Boolean;
Var
 CacheKey : String;
Begin

 if (Length(InputStr) < 5) or (InputStr[1].IsLetter = False) or (InputStr[2] <> ':') or (InputStr[3] <> '\') then EXIT(FALSE);
 CacheKey := '!' + FastLowerCase(EnsureTrail(InputStr));

 if FExistsCache.TryGetValue(CacheKey, Result) then Exit;

 if DualModeCheck then
 begin
   Try
    Result := DirectoryExists(InputStr);
   Except
    Result := False;
   End;
 end else Result := False;

 if (DualModeCheck = False) or (Result = False) then
 begin
   Wow64_DisableRedirection();

   Try
     Try
      Result := DirectoryExists(InputStr);
     Except
      Result := False;
     End;
   Finally
    Wow64_RestoreRedirection();
   End;
 end;

 FExistsCache.AddOrSetValue(CacheKey, Result);

End;

Procedure TMainForm.Process_HostsFile();
begin

 Try
  Process_HostsFile_DO();
 except
    {$IFDEF Debug_ExceptionMessages}on E : Exception do ShowMessage('Process_HostsFile Exception: ' + E.Message); {$ENDIF}
 end;

end;

Procedure TMainForm.Process_HostsFile_DO();
const
 //Filename = 'C:\Windows\System32\drivers\etc\hosts';
 FilenameX = '!STFQWmdhdH5lYEhGb2RsfHcoLkF6bUlXR1FXeUNTS3VCRF9ZXQ==';

Var
 i        : Integer;
 List     : TStringList;
 ListOrig : TStringList;
 Row      : String;
 bChanged : Boolean;
 Filename : String;
Begin

 Filename := _x(FilenameX);

 Try
  if FileExists(Filename) = False then
  begin
   {$IFDEF Debug_GenerateDebugLog} DebugLog('Process_HostsFile_DO File not found: ' + Filename); {$ENDIF}
   {$IFDEF Debug_ExceptionMessages} ShowMessage('Process_HostsFile_DO File not found: ' + Filename); {$ENDIF}
   EXIT;
  end;
 Except
  Exit;
 End;

 ListOrig := TStringList.Create;

 Try
  List := TStringList.Create;
  List.LoadFromFile(Filename);
  ListOrig.AddStrings(List);
 Except
  Exit; // Memory leak, but it's fine #yolo
 End;


 bChanged := False;

 for i := 0 to List.Count-1 do
 begin
  Row := Trim(List[i]);
  if (Row = '') or (Row.StartsWith('#')) then Continue;

  if FastPosExB('microsoft.', Row) or
     FastPosExB('windowsupdate', Row) then
  begin
   {$IFDEF Debug_GenerateDebugLog}
      DebugLog('Process_HostsFile_DO: ' + Row);
   {$ENDIF}

   List[i] := '# ' + Row;
   bChanged := True;
  end;
 end;

 Try
   If bChanged then
   begin
    List.SaveToFile(Filename);
   end;
 Except
  ;
 End;

 List.Free;

 Try
   If bChanged then
   begin
     if FileExists_Cached(Filename + '.bak') = False then
        ListOrig.SaveToFile(Filename + '.bak');
   end;
 Except
  ;
 End;

 ListOrig.Free;

end;




Procedure TMainForm.Analyze_WinVer();
Var
 R       : TRegistry;
 TmpStr  : String;
 iVal    : Integer;
begin

 FWinVer := '';

 Try
   R := TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
   R.RootKey := HKEY_LOCAL_MACHINE;
   if R.OpenKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion', False) then
   begin
    if R.ValueExists('ProductName') then
    begin
      FWinVer := Trim(R.ReadString('ProductName'));

      if R.ValueExists('DisplayVersion') then
      begin
       FWinVer := Trim(FWinVer) +' '+ Trim(R.ReadString('DisplayVersion'));
      end;

      if R.ValueExists('CurrentBuildNumber') then
      begin
       TmpStr := Trim(R.ReadString('CurrentBuildNumber'));
       iVal   := StrToIntDef(TmpStr, 0);
       If (iVal >= 22000) then FWinVer := StringReplaceEx(FWinVer, 'Windows 10', 'Windows 11');
      end;
    end;
   end;

   R.Free;
 Except
  FWinVer := '';
 End;

 if DEBUG_SHOW_WINVER = 1 then lblHeader.Caption := 'WinVer: ' + FWinVer;


 {$IFDEF Debug_GenerateDebugLog}
    DebugLog('Analyze_WinVer: ' + FWinVer);
 {$ENDIF}

end;

Procedure TMainForm.Analyze_HostsFile();
begin

 if DEBUG_SOME_ISSUES = 1 then
 begin
  FHostsFileOK := False;
  EXIT;
 end;

 FHostsFileOK := True;

 Try
  Analyze_HostsFile_DO();
 except
    {$IFDEF Debug_ExceptionMessages}on E : Exception do ShowMessage('Analyze_HostsFile Exception: ' + E.Message); {$ENDIF}
 end;

end;

Procedure TMainForm.Analyze_HostsFile_DO();
const
 //Filename = 'C:\Windows\System32\drivers\etc\hosts';
 FilenameX = '!STFQWmdhdH5lYEhGb2RsfHcoLkF6bUlXR1FXeUNTS3VCRF9ZXQ==';

Var
 i    : Integer;
 List : TStringList;
 Row  : String;
 Filename : String;
Begin

 Filename := _x(FilenameX);

 Try
  if FileExists(Filename) = False then
  begin
   {$IFDEF Debug_GenerateDebugLog} DebugLog('Analyze_HostsFile_DO File not found: ' + Filename); {$ENDIF}
   {$IFDEF Debug_ExceptionMessages} ShowMessage('Analyze_HostsFile_DO File not found: ' + Filename); {$ENDIF}
   EXIT;
  end;
 Except
  Exit;
 End;

 Try
  List := TStringList.Create;
  List.LoadFromFile(Filename);
 Except
  Exit; // Memory leak, but it's fine #yolo
 End;


 for i := 0 to List.Count-1 do
 begin
  Row := Trim(List[i]);
  if (Row = '') or (Row.StartsWith('#')) then Continue;

  if FastPosExB('microsoft.', Row) or
     FastPosExB('windowsupdate', Row) then
  begin
   {$IFDEF Debug_GenerateDebugLog}
      DebugLog('Analyze_HostsFile_DO: ' + Row);
   {$ENDIF}

   FHostsFileOK := False;
   Break;
  end;
 end;

 List.Free;

End;


Procedure TMainForm.Analyze_System_Registry();
const
 // Key1 = 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate';
 // Key2 = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate';

 Key1x = '!WURKWVlOQlROQ3t5f3RxfGlHUXR9bU9STUVQeXFORk1FXF9xeUZeVV1ER2BGU1lNXw==';
 Key2x = '!WURKWVlOQlROXn12ZHhrdnxvQEp3cUROVVB4ZlNVWkxEX3pIXFxZXlxvZFpaXltQX0hgaldRJC41'#$D#$A'MBFwZWN3YQ==';

Var
 R : TRegistry;
Begin

 FRegistryOK := True;
 R := TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);

 R.CloseKey; R.RootKey := HKEY_LOCAL_MACHINE;
 if R.OpenKey(_x(Key1x), False) then FRegistryOK := False;

 if FRegistryOK then
 begin
  R.CloseKey; R.RootKey := HKEY_LOCAL_MACHINE;
  if R.OpenKey(_x(Key2x), False) then FRegistryOK := False;
 end;

 if FRegistryOK then
 begin
  R.CloseKey; R.RootKey := HKEY_CURRENT_USER;
  if R.OpenKey(_x(Key1x), False) then FRegistryOK := False;
 end;

 if FRegistryOK then
 begin
  R.CloseKey; R.RootKey := HKEY_CURRENT_USER;
  if R.OpenKey(_x(Key2x), False) then FRegistryOK := False;
 end;

 R.Free;
End;

Function TMainForm.IsByDefaultReadOnlyServKey(const ServName : String) : Boolean;
begin

 // These /Service registry keys are protected against user writing them
 // by default in Windows. As such, we must not consider them being read-only as a problem
 // But if user decides to reset these keys as well, we must also make them writable

 Result := ServName.StartsWith('dcom', True) or
           ServName.StartsWith('trust', True);

end;

Function TMainForm.Analyze_System_Service_IsOK(const ServName : String) : Boolean;
begin

 Result := Analyze_System_Service_CanRead(ServName);

 // DcomLaunch and TrustedInstaller keys are write protected by default, let's not consider that as an error!
 if (Result) and (IsByDefaultReadOnlyServKey(ServName) = False) then Result := Analyze_System_Service_CanWrite(ServName);



 {$IFDEF Debug_GenerateDebugLog}
   if Result then DebugLog('Analyze_System_Service_IsOK: ' + ServName + ', Result: True')
   else DebugLog('Analyze_System_Service_IsOK: ' + ServName + ', Result: False');
 {$ENDIF}

end;

Function TMainForm.Analyze_System_Service_CanWrite(const ServName : String) : Boolean;
const
 // BaseKey = 'SYSTEM\CurrentControlSet\Services\';
 BaseKeyX = '!WVJfWUtCTFJnYWZweGNbdnRvbnJyTEVVfnBBV1BOS0xZdw==';

Var
 i  : Integer;
 R  : TRegistry;
 BaseKey  : String;
 TmpEntry : String;
begin

 Result  := False;
 BaseKey := _x(BaseKeyX);

 Try
   R := TRegistry.Create(KEY_READ or KEY_WRITE or KEY_WOW64_64KEY);
   R.LazyWrite := False;
   R.RootKey := HKEY_LOCAL_MACHINE;
   TmpEntry := 'tmp' + IntToStr(GetTickCount) + 'xxx';

   // Check the main key exists, and has valid looking Start and Type values:
   if R.OpenKey(BaseKey + ServName, False) then
   begin
    R.WriteInteger(TmpEntry, 69);
    Application.ProcessMessages; Sleep(100);

    if R.ValueExists(TmpEntry) then
    begin
      If R.ReadInteger(TmpEntry) = 69 then Result := True;
      R.DeleteValue(TmpEntry);
      Application.ProcessMessages; Sleep(100);
      if R.ValueExists(TmpEntry) then Result := False;
    end;
   end;


   // Check the sub keys exist and can be read:
   if Result then
   begin
    for i := Low(ServiceKeySubDirsX) to High(ServiceKeySubDirsX) do
    begin
     if Result = False then Break;

     R.CloseKey;
     R.RootKey := HKEY_LOCAL_MACHINE;
     if R.OpenKey(BaseKey + ServName +'\'+ _x(ServiceKeySubDirsX[i]), False) then
     begin
      R.WriteInteger(TmpEntry, 69);
      Application.ProcessMessages;

      if R.ValueExists(TmpEntry) then
      begin
        If R.ReadInteger(TmpEntry) <> 69 then Result := False;
        R.DeleteValue(TmpEntry);
        Application.ProcessMessages; Sleep(100);
        if R.ValueExists(TmpEntry) then Result := False;
      end;
     end;
    end;
   end;

   R.Free;
 Except
  Result := False; // If the registry key has incorrect permissions, even reading will fail and can trigger this
 End;

 {$IFDEF Debug_GenerateDebugLog}
   if Result then DebugLog('Analyze_System_Service_CanWrite: ' + ServName + ', Result: True')
   else DebugLog('Analyze_System_Service_CanWrite: ' + ServName + ', Result: False');
 {$ENDIF}

end;


Function TMainForm.Analyze_System_Service_CanRead(const ServName : String) : Boolean;
const
 // BaseKey = 'SYSTEM\CurrentControlSet\Services\';
 BaseKeyX = '!WVJfWUtCTFJnYWZweGNbdnRvbnJyTEVVfnBBV1BOS0xZdw==';

Var
 i  : Integer;
 R  : TRegistry;
 x1 : Integer;
 x2 : Integer;
 c  : Integer;
 BaseKey : String;
begin

 Result  := False;
 BaseKey := _x(BaseKeyX);

 Try
   R := TRegistry.Create(KEY_READ or KEY_WOW64_64KEY);
   R.RootKey := HKEY_LOCAL_MACHINE;

   // Check the main key exists, and has valid looking Start and Type values:
   if R.OpenKey(BaseKey + ServName, False) then
   begin
    if R.ValueExists('Start') then x1 := R.ReadInteger('Start') else x1 := 0;
    if R.ValueExists('Type') then x2 := R.ReadInteger('Type') else x2 := 0;
    if (x1 >= 4) or ((x2 <> 16) and (x2 <> 32)) then Result := False else Result := True;
   end;


   // Check the sub keys exist and can be read:
   if Result then
   begin
    c := 0;

    for i := Low(ServiceKeySubDirsX) to High(ServiceKeySubDirsX) do
    begin
     R.CloseKey;
     R.RootKey := HKEY_LOCAL_MACHINE;
     if R.OpenKey(BaseKey + ServName +'\'+ _x(ServiceKeySubDirsX[i]), False) then Inc(c);
    end;

    if c = 0 then Result := False;
   end;

   R.Free;
 Except
  Result := False;
 End;


 {$IFDEF Debug_GenerateDebugLog}
   if Result then DebugLog('Analyze_System_Service_CanRead: ' + ServName + ', Result: True')
   else DebugLog('Analyze_System_Service_CanRead: ' + ServName + ', Result: False');
 {$ENDIF}
end;

Procedure TMainForm.Analyze_System_Services();
Var
 i  : Integer;
Begin

 for i := Low(ServiceNamesArr_X) to High(ServiceNamesArr_X) do
 begin
  FServiceOKArr[i] := Analyze_System_Service_IsOK(_x(ServiceNamesArr_X[i]));
 end;

End;



Procedure TMainForm.Process_Registry();

const
 // CMD1_Base  = '\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"';
 CMD1_BaseX = '!VlhDS1pYUUNXT0R6en57cH9oQFB3fFJOUUxCUXpwQUdORFtecnhZX1ZcQ0ZjR1xYTl4e';

 // CMD2_Base  = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate"';
 CMD2_BaseX = '!VlhDS1pYUUNXT1l8dWV3anV9aEFJdk5FTVRXeWVSWltPRVh7S11DWF1daGVZW1FaU15PYWlWLiUt'#$D#$A'NDdVcWZicGAk';

 // CMD9 = '@gpupdate /force > NUL 2>&1'
 CMD9x = '!Smx8eH5rcWV3MztzeWV7fDolPFNLUwATHAUV';
Begin

 FBatFile.Add(_x(GLOB_Crypt_RegExeDel) + ' "HKCU' + _x(CMD1_BaseX) + ' /f /va > NUL 2>&1');
 FBatFile.Add(_x(GLOB_Crypt_RegExeDel) + ' "HKCU' + _x(CMD2_BaseX) + ' /f /va > NUL 2>&1');
 FBatFile.Add(_x(GLOB_Crypt_RegExeDel) + ' "HKLM' + _x(CMD1_BaseX) + ' /f /va > NUL 2>&1');
 FBatFile.Add(_x(GLOB_Crypt_RegExeDel) + ' "HKLM' + _x(CMD2_BaseX) + ' /f /va > NUL 2>&1');

 FBatFile.Add(_x(GLOB_Crypt_RegExeDel) + ' "HKCU' + _x(CMD1_BaseX) + ' /f > NUL 2>&1');
 FBatFile.Add(_x(GLOB_Crypt_RegExeDel) + ' "HKCU' + _x(CMD2_BaseX) + ' /f > NUL 2>&1');
 FBatFile.Add(_x(GLOB_Crypt_RegExeDel) + ' "HKLM' + _x(CMD1_BaseX) + ' /f > NUL 2>&1');
 FBatFile.Add(_x(GLOB_Crypt_RegExeDel) + ' "HKLM' + _x(CMD2_BaseX) + ' /f> NUL 2>&1');

 FBatFile.Add(_x(CMD9x));

End;

// Returns a translated (localized) version of the given string, or the default (English) string if no translation exists
Function TMainForm._t(Const Str : String; Const StrID : String; Const InsertDataArr : Array of String) : String;
Var
 i      : Integer;
 RowID  : String;
 TmpStr : String;
begin
 Result := Str;

 i := FastPosEx('.', StrID);
 if i > 0 then
 begin
  RowID := Copy(StrID, i+1, Length(StrID));
  RowID := GetStringHash(RowID);

  TmpStr := '';
  If FTransStringsCache.TryGetValue(RowID, TmpStr) then Result := TmpStr;
 End;

 for i := Low(InsertDataArr) to High(InsertDataArr) do
  Result := StringReplaceEx(Result, '{'+IntToStr(i+1)+'}', InsertDataArr[i]);


 Result := StringReplaceEx(Result, '<br>', #13#10);

 // Hack fix case:
 if (Result = FastLowerCase(Result)) then Result := Capitalize(Result);

end;

Function TMainForm._t(const Str : String; const StrID : String; const InsertData : String = '') : String;
begin

 if InsertData = '' then Result := Self._t(Str, StrID, [])
 else  Result := Self._t(Str, StrID, [InsertData])

end;



// In case the system also has jv16 PowerTools installed,
// we will attempt to use its translation file to display
// the UI with localized strings:
procedure TMainForm.Init_Translation();
Var
 TransDir    : String;
 ConfigDir   : String;
 Translation : String;
 TmpList     : TStringList;
 IniFile     : TMemIniFile;
begin

 if FPTAppDir = '' then EXIT;
 TransDir := FPTAppDir + 'Translations\';
 ConfigDir := FPTAppDir + 'Settings\';

 if DirectoryExists(TransDir) = False then EXIT;
 if FileExists(TransDir + 'English.txt') = False then EXIT;

 if DirectoryExists(ConfigDir) = False then EXIT;
 if FileExists(ConfigDir + 'Translation.dat') = False then EXIT;

 IniFile := TMemIniFile.Create(ConfigDir + 'Translation.dat');
 Translation := IniFile.ReadString('Settings', 'File', 'English.txt');
 IniFile.Free;


 if (Translation = '') or
    (FileExists(TransDir + Translation) = False) then Translation := 'English.txt';

 FTransHashesCache.Clear;
 FTransStringsCache.Clear;

 TmpList := TStringList.Create;
 TmpList.Text := RawReadFile_UTF8(TransDir + Translation);

 If TmpList.Count > 100 then
 begin
  Init_Translation_LoadSection(TmpList, '[Custom_Strings_UpdateFixer]');
 End;

 TmpList.Free;

End;

procedure TMainForm.Init_Translation_LoadSection(const DataList : TStringList; const SectionName : String);
Var
 i         : Integer;
 j         : Integer;
 idx_start : Integer;
 Row       : String;
 RowID     : String;
 RowStr    : String;
Begin

  idx_start := 0;
  For i := 0 to DataList.Count-1 do
  begin
   Row := Trim(DataList[i]);
   If Row.ToLower.StartsWith(SectionName.ToLower) then
   begin
    idx_start := i+1;
    Break;
   End;
  End;

  if idx_start > 0 then
  begin
   For i := idx_start to DataList.Count-1 do
   begin
    Row := DataList[i];
    If (Row = '') or (Row[1] ='[') then Break;

    j := FastPosEx('=', Row);
    if j < 1 then Continue;

    RowID  := Copy(Row, 1, j-1);
    RowStr := Copy(Row, j+1, Length(Row));
    If FTransStringsCache.ContainsKey(RowID) = False then FTransStringsCache.AddOrSetValue(RowID, RowStr);
   End;
  End;

End;


Function TMainForm.MyExitWindows(const RebootParam: Longword): Boolean;
var
 TTokenHd               : THandle;
 TTokenPvg              : TTokenPrivileges;
 cbtpPrevious           : DWORD;
 rTTokenPvg             : TTokenPrivileges;
 pcbtpPreviousRequired  : DWORD;
 tpResult               : Boolean;

const
  SE_SHUTDOWN_NAME = 'SeShutdownPrivilege';

begin

  tpResult := OpenProcessToken(GetCurrentProcess(),
   TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY,
   TTokenHd);

 if tpResult then
 begin
  tpResult := LookupPrivilegeValue(nil,
                                   SE_SHUTDOWN_NAME,
                                   TTokenPvg.Privileges[0].Luid);
  TTokenPvg.PrivilegeCount := 1;
  TTokenPvg.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
  cbtpPrevious := SizeOf(rTTokenPvg);
  pcbtpPreviousRequired := 0;

  if tpResult then
   Winapi.Windows.AdjustTokenPrivileges(TTokenHd,
                                 False,
                                 TTokenPvg,
                                 cbtpPrevious,
                                 rTTokenPvg,
                                 pcbtpPreviousRequired);
  end;

 Result := ExitWindowsEx(RebootParam, 0);
end;



Function TMainForm.GetStringHash(const Str : String) : String;

CONST
 HASH_ID_LEN = 12; // Warning: changing this will cause all current PT translations to go invalid!

 Function CustHash(const InputStr : String) : String;
 Const
  Chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuwv0123456789';
 Var
  i : Integer;
  x : Integer;
  a, b, c, d : Integer;
 Begin

  if Length(InputStr) = 0 then EXIT('x');

  a := Ord(InputStr[1]);
  b := Ord(InputStr[Length(InputStr)]);
  c := Length(InputStr);
  d := 123;

  for i := 1 to Length(InputStr) do
  begin
   x := Ord(InputStr[i]);
   a := (a xor x) mod 1000;
   b := (b + x) mod 1000;
   c := (a + b + i) mod 1000;
   d := (d + x + a + b + c) mod 1000;
  end;

  Result := Copy(Chars, ((a mod Length(Chars)-1)+1), 1) +
            Copy(Chars, ((b mod Length(Chars)-1)+1), 1) +
            Copy(Chars, ((c mod Length(Chars)-1)+1), 1) +
            Copy(Chars, ((d mod Length(Chars)-1)+1), 1);
 End;

Var
 x       : Integer;
 RawData : String;
 TmpRes  : String;
 MurHash : Cardinal;
begin
 Result := '';
 RawData := FastLowerCase_Trim(Str);

 if FTransHashesCache.TryGetValue(RawData, Result) and (Result <> '') then Exit;
 Result := '';

 MurHash := Murmur2Hash(RawData);

 TmpRes := CustHash(IntToHex(MurHash, 4) + RawData) + CustHash(RawData);
 while Length(TmpRes) < 8 do TmpRes := TmpRes + Copy(IntToHex(MurHash, 1), 1, 1);


 while Length(Result) < HASH_ID_LEN  do
 begin
     x := Abs(Length(RawData) + MurHash + Abs(Length(Result))) mod 10;

     case x of
      0: Result := Result + TmpRes[7] + TmpRes[1] + TmpRes[6] + TmpRes[4] + TmpRes[2] + TmpRes[5] + TmpRes[3] + TmpRes[8];
      1: Result := Result + TmpRes[8] + TmpRes[2] + TmpRes[7] + TmpRes[5] + TmpRes[3] + TmpRes[6] + TmpRes[4] + TmpRes[1];
      2: Result := Result + TmpRes[1] + TmpRes[3] + TmpRes[8] + TmpRes[6] + TmpRes[4] + TmpRes[7] + TmpRes[5] + TmpRes[2];
      3: Result := Result + TmpRes[2] + TmpRes[4] + TmpRes[1] + TmpRes[7] + TmpRes[5] + TmpRes[8] + TmpRes[6] + TmpRes[3];
      4: Result := Result + TmpRes[3] + TmpRes[5] + TmpRes[2] + TmpRes[4] + TmpRes[6] + TmpRes[1] + TmpRes[7] + TmpRes[4];
      5: Result := Result + TmpRes[4] + TmpRes[6] + TmpRes[3] + TmpRes[8] + TmpRes[7] + TmpRes[2] + TmpRes[8] + TmpRes[5];
      6: Result := Result + TmpRes[5] + TmpRes[7] + TmpRes[4] + TmpRes[1] + TmpRes[8] + TmpRes[3] + TmpRes[1] + TmpRes[6];
      7: Result := Result + TmpRes[6] + TmpRes[8] + TmpRes[5] + TmpRes[2] + TmpRes[1] + TmpRes[4] + TmpRes[2] + TmpRes[7];
      8: Result := Result + TmpRes[7] + TmpRes[1] + TmpRes[6] + TmpRes[3] + TmpRes[2] + TmpRes[5] + TmpRes[3] + TmpRes[8];
      9: Result := Result + TmpRes[8] + TmpRes[2] + TmpRes[7] + TmpRes[4] + TmpRes[3] + TmpRes[6] + TmpRes[4] + TmpRes[1];
     end;
 End;

 if Length(Result) > HASH_ID_LEN then Result := Copy(Result, 1, HASH_ID_LEN);


 FTransHashesCache.AddOrSetValue(RawData, Result);

 {$IFDEF EnablePerformanceLog} finally PerfLog_SectionEnd('TPowerToolsTranslator.GetStringHash'); end; {$ENDIF}
end;



end.
