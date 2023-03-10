# UpdateFixer

  Update Fixer is a lightweight app to fix Windows Update not working.
  Update Fixer version 1.2
  By Jouni Flemming (Macecraft Software)
  Copyright 2023 Jouni Flemming

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


  ** Change Log **

  Changes since version 1.1

  1) The app window can now be resized in its results show view.
  2) Improved the Debug_GenerateDebugLog directive support and debug log content.
  3) Split Process_Init_Pas() into two functions and fixed many bugs there.
  4) Removed Debug_ExceptionMessages directive. Debug_GenerateDebugLog is better anyway.
  5) Removed DEBUG_WRITE_LOG, because Debug_GenerateDebugLog is better anyway.


  Changes since version 1.0

  1) Removed the use of encrypted strings in order to improve code readability. They were used to
     prevent VirusTotal false positives. I'm going to ass-u-me that since the program is now open source,
     it will no longer be flagged with such false positive detections.
  2) Replaced all of the hard-coded 'c:\windows\' references with %WINDIR%. While this makes very little difference
     for any actual use case, it's still a better way to do it.
  3) Other minor code cleanup and maintenance, and added some more comments to document the code.
