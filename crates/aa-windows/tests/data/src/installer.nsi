; Fixture installer: touches the things the analyzer reports on. Built by make-fixtures.sh
; with -DCOMPRESSOR=... and -DUNICODE_TARGET=true|false.
Unicode ${UNICODE_TARGET}
!if "${SOLID}" == "1"
  SetCompressor /SOLID ${COMPRESSOR}
!else
  SetCompressor ${COMPRESSOR}
!endif
Name "Fixture App"
OutFile "${OUT}"
InstallDir "$PROGRAMFILES64\Fixture App"
RequestExecutionLevel admin

Section "Main"
  SetOutPath "$INSTDIR"
  File "hello.exe"
  File "readme.txt"
  SetOutPath "$INSTDIR\data"
  File "payload.bin"
  File /oname=copy.txt "readme.txt"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "FixtureApp" '"$INSTDIR\hello.exe" --autostart'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\FixtureApp" "DisplayName" "Fixture App"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\FixtureApp" "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegDWORD HKLM "Software\Fixture Works\Fixture App" "Installed" 1
  WriteRegStr HKCR ".fixture" "" "FixtureApp.Document"
  WriteRegStr HKCR "fixtureapp\shell\open\command" "" '"$INSTDIR\hello.exe" "%1"'
  CreateShortcut "$SMPROGRAMS\Fixture App.lnk" "$INSTDIR\hello.exe"
  CreateShortcut "$SMSTARTUP\Fixture App.lnk" "$INSTDIR\hello.exe" "--autostart"
  ExecWait 'sc.exe create FixtureSvc binPath= "$INSTDIR\hello.exe --service" start= auto'
  ExecWait 'netsh advfirewall firewall add rule name="Fixture App" dir=in action=allow program="$INSTDIR\hello.exe"'
  ExecWait 'schtasks /Create /TN "FixtureUpdate" /TR "$INSTDIR\hello.exe --update" /SC DAILY'
  Exec '"$INSTDIR\hello.exe" --first-run'
  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\hello.exe"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\FixtureApp"
  RMDir /r "$INSTDIR"
SectionEnd
