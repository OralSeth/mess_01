Option Explicit
On Error Resume Next

Const CSIDL_COMMON_PROGRAMS = &H17
Const CSIDL_PROGRAMS = &H2
Const CSIDL_STARTMENU = &HB
Const CSIDL_APPDATA = &H1A

Dim objShell, objFSO
Dim objCurrentUserStartFolder
Dim strCurrentUserStartFolderPath
Dim objAllUsersProgramsFolder
Dim strAllUsersProgramsPath
Dim objFolder
Dim objFolderItem
Dim colVerbs
Dim objVerb

Set objShell = CreateObject("Shell.Application")
Set objFSO = CreateObject("Scripting.FileSystemObject")

Set objCurrentUserStartFolder = objShell.Namespace (CSIDL_STARTMENU)
strCurrentUserStartFolderPath = objCurrentUserStartFolder.Self.Path

Set objAllUsersProgramsFolder = objShell.Namespace(CSIDL_COMMON_PROGRAMS)
strAllUsersProgramsPath = objAllUsersProgramsFolder.Self.Path

'- Remove Pinned Items -

'Google Chrome
If objFSO.FileExists(strAllUsersProgramsPath & "\Google Chrome\Google Chrome.lnk") Then
  Set objFolder = objShell.Namespace(strAllUsersProgramsPath & "\Google Chrome")
  Set objFolderItem = objFolder.ParseName("Google Chrome.lnk")
  Set colVerbs = objFolderItem.Verbs
  For Each objVerb in colVerbs
    If Replace(objVerb.name, "&", "") = "Unpin from Taskbar" Then objVerb.DoIt
  Next
End If

'Internet Explorer
If objFSO.FileExists(strCurrentUserStartFolderPath & "\Programs\Internet Explorer.lnk") Then
        Set objFolder = objShell.Namespace(strCurrentUserStartFolderPath & "\Programs")
        Set objFolderItem = objFolder.ParseName("Internet Explorer.lnk")
        Set colVerbs = objFolderItem.Verbs
    For Each objVerb in colVerbs
                If Replace(objVerb.name, "&", "") = "Unpin from Taskbar" Then objVerb.DoIt
    Next
End If
