param([string]$Entrada, [string]$Salida, [string]$Pdf)
$w = New-Object -ComObject Word.Application
$w.Visible = $false
$w.DisplayAlerts = 0
try {
  $d = $w.Documents.Open($Entrada, $false, $false, $false)
  $d.Fields.Update() | Out-Null
  foreach ($t in $d.TablesOfContents) { $t.Update() | Out-Null }
  foreach ($t in $d.TablesOfFigures) { $t.Update() | Out-Null }
  $d.Fields.Update() | Out-Null
  $d.SaveAs2($Salida, 16)
  $d.ExportAsFixedFormat($Pdf, 17)
  $d.Close($false)
} finally {
  $w.Quit()
}
"listo"
