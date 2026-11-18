param([switch]$ExportOnly, [switch]$Annotate)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskGhidra = Join-Path $taskRoot 'tools\ghidra\ghidra_12.1.3_PUBLIC'
$taskJdk = Join-Path $taskRoot 'tools\jdk\jdk-21.0.13+9'
$env:JAVA_HOME = $taskJdk
$env:PATH = "$taskJdk\bin;$env:PATH"
$taskProject = Join-Path $taskRoot '03_文件结构分析\ghidra\project'
$taskOutput = Join-Path $taskRoot '03_文件结构分析\ghidra\export'
$taskScript = Join-Path $PSScriptRoot 'ghidra_scripts'
New-Item -ItemType Directory -Path $taskProject -Force | Out-Null
$taskArguments = @($taskProject, 'StarrySky_PCSG00510', '-scriptPath', $taskScript)
if ($ExportOnly -or $Annotate) {
    $taskArguments += @('-process', 'PCSG00510.elf', '-noanalysis')
} else {
    $taskArguments += @('-import', (Join-Path $taskRoot '02_解包资源\PCSG00510_decrypted\PCSG00510.elf'), '-overwrite', '-analysisTimeoutPerFile', '600')
}
if ($Annotate) {
    $taskArguments += @('-postScript', 'LabelGame.java', (Join-Path $taskRoot '03_文件结构分析\ghidra\key_functions'))
} else {
    $taskArguments += @('-postScript', 'DumpGame.java', $taskOutput)
}
$taskArguments += @('-log', (Join-Path $taskRoot '03_文件结构分析\ghidra\headless.log'), '-scriptlog', (Join-Path $taskRoot '03_文件结构分析\ghidra\script.log'))
& (Join-Path $taskGhidra 'support\analyzeHeadless.bat') @taskArguments
exit $LASTEXITCODE
