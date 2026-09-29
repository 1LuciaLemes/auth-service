# Escanea caracteres no latinos (CJK, cirilico, etc.) en el codigo fuente.
#
# Por que este script existe: varias veces aparecio el mojibake "3 de la ma< CJK >ana"
# en los comentarios. Es facil no verlo a simple vista y queda commiteado.
#
# El bug del escaneo anterior: los rangos de la regex se solapaban
# (por ejemplo 2010-203B y el rango de CJK), y el agrupamiento con
# alternancia hacia que PowerShell no evaluara bien la clase. Aca se
# comprueba el valor de cada caracter de forma explicita, sin regex,
# para que el rango de exclusion sea inequivoco.

$permitidos = @{}
# ASCII imprimible
0..127 | ForEach-Object { $permitidos[$_] = $true }
# Latin-1 supplement
0x00A0..0x00FF | ForEach-Object { $permitidos[$_] = $true }
# Puntuacion tipografica comun (guiones, comillas, elipses)
0x2010..0x203A | ForEach-Object { $permitidos[$_] = $true }
# Euro, flechas, currency
0x20AC, 0x2190, 0x2192, 0x21D2 | ForEach-Object { $permitidos[$_] = $true }
# Cajas de dibujo (tablas ascii)
0x2500..0x257F | ForEach-Object { $permitidos[$_] = $true }

# El script vive en apps/auth-service/scripts, asi que la raiz a escanear es
# un nivel arriba. Un guard verifica que efectivamente se encontro una cantidad
# razonable de archivos: en las primeras versiones la ruta mal calculada hacia
# que el script escaneaba solo la carpeta scripts/ y reportaba "OK" sin haber
# revisado nada. Un escaneo que no falla cuando no hace su trabajo es peor que
# no tenerlo.
$raiz = Split-Path -Parent $PSScriptRoot
if (-not $raiz) { $raiz = (Get-Location).Path }

$extensiones = @('.ts', '.tsx', '.js', '.json', '.md', '.sql')
$archivos = Get-ChildItem -Path $raiz -Recurse -File |
    Where-Object {
        $_.Extension -in $extensiones -and
        $_.FullName -notmatch '\\node_modules\\|\\dist\\|\\\.git\\' -and
        $_.Name -ne 'package-lock.json'
    }

if ($archivos.Count -lt 5) {
    Write-Host "FALLO: solo se encontraron $($archivos.Count) archivos bajo $raiz. El escaneo no es confiable." -ForegroundColor Red
    exit 1
}

$problemas = @()

foreach ($archivo in $archivos) {
    $linea = 0
    foreach ($fila in [System.IO.File]::ReadAllLines($archivo.FullName)) {
        $linea++
        for ($i = 0; $i -lt $fila.Length; $i++) {
            $codigo = [int][char]$fila[$i]
            if ($codigo -gt 127 -and -not $permitidos.ContainsKey($codigo)) {
                $relativo = $archivo.FullName.Replace($raiz, '')
                $problemas += [PSCustomObject]@{
                    Archivo  = $relativo
                    Linea    = $linea
                    Columna  = $i + 1
                    Caracter = $fila[$i]
                    Codigo   = ('U+{0:X4}' -f $codigo)
                    Contexto = $fila.Trim()
                }
            }
        }
    }
}

if ($problemas.Count -eq 0) {
    Write-Host "OK: sin caracteres no latinos en $($archivos.Count) archivos" -ForegroundColor Green
    exit 0
}

Write-Host "Encontrados $($problemas.Count) caracteres no latinos:" -ForegroundColor Red
$problemas | Format-Table Archivo, Linea, Columna, Caracter, Codigo -AutoSize
Write-Host ""
Write-Host "Detalle:" -ForegroundColor Red
foreach ($p in $problemas) {
    Write-Host "  $($p.Archivo):$($p.Linea):$($p.Columna)  $($p.Codigo) $($p.Caracter)"
    Write-Host "    $($p.Contexto)"
    Write-Host ""
}
exit 1
