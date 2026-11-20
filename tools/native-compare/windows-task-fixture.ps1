param([Parameter(Mandatory = $true)][string]$Destination)

# Serialize this project's new definition. It is never registered, run or loaded from input XML.
$ErrorActionPreference = 'Stop'
$fixtureDirectory = (New-Item -ItemType Directory -Force -Path $Destination).FullName
$fixtureService = New-Object -ComObject 'Schedule.Service'
$fixtureService.Connect()
$fixtureTask = $fixtureService.NewTask(0)
$fixtureTask.RegistrationInfo.Author = 'Analyze Anything fixture'
$fixtureTask.RegistrationInfo.Description = 'Unregistered parser comparison fixture'
$fixtureTask.Settings.Compatibility = 2
$fixtureTask.Settings.Enabled = $false
$fixtureTask.Settings.ExecutionTimeLimit = 'PT5M'
$fixtureTask.Principal.Id = 'fixture-principal'
$fixtureTask.Principal.UserId = 'S-1-5-18'
$fixtureTask.Principal.LogonType = 5
$fixtureTask.Principal.RunLevel = 1
$fixtureTask.Actions.Context = 'fixture-principal'
$fixtureAction = $fixtureTask.Actions.Create(0)
$fixtureAction.Id = 'fixture-exec'
$fixtureAction.Path = '%SystemRoot%\System32\cmd.exe'
$fixtureAction.Arguments = '--fixture "two words"'
$fixtureAction.WorkingDirectory = '%SystemRoot%'
$fixtureTime = $fixtureTask.Triggers.Create(1)
$fixtureTime.Id = 'fixture-time'
$fixtureTime.StartBoundary = '2030-01-01T00:00:00'
$fixtureTime.Enabled = $true
$fixtureLogon = $fixtureTask.Triggers.Create(9)
$fixtureLogon.Id = 'fixture-logon'
$fixtureLogon.Enabled = $false
$fixtureReference = [ordered]@{
    producer = 'Windows Task Scheduler new unregistered ITaskDefinition'
    command = $fixtureAction.Path
    arguments = $fixtureAction.Arguments
    working_directory = $fixtureAction.WorkingDirectory
    principal = 'S-1-5-18'
    native_principal_name = $fixtureTask.Principal.UserId
    run_level = 'HighestAvailable'
    native_logon_type = 'ServiceAccount'
    action_context = $fixtureTask.Actions.Context
    time_start = $fixtureTime.StartBoundary
    time_enabled = $fixtureTime.Enabled
    logon_enabled = $fixtureLogon.Enabled
    task_enabled = $fixtureTask.Settings.Enabled
}
[System.IO.File]::WriteAllText((Join-Path $fixtureDirectory 'native-task.xml'), $fixtureTask.XmlText, [System.Text.UnicodeEncoding]::new($false, $true))
[System.IO.File]::WriteAllText((Join-Path $fixtureDirectory 'native-task.xml.ref.json'), (($fixtureReference | ConvertTo-Json) + "`n"), [System.Text.UTF8Encoding]::new($false))
