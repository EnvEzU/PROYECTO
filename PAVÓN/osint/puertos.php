<?php
session_start();
require_once '../config/conexion.php';

set_time_limit(90);

if (!isset($_POST['id_historial'])) {
    die("Error: No se recibió el ID por POST.");
}

$id = (int)$_POST['id_historial'];

function h(string $texto): string
{
    return htmlspecialchars($texto, ENT_QUOTES, 'UTF-8');
}

function normalizarDominio(string $entrada)
{
    $dominio = trim($entrada);

    if ($dominio === '') {
        return false;
    }

    $dominio = preg_replace('~^https?://~i', '', $dominio);
    $dominio = preg_replace('~^www\.~i', '', $dominio);
    $dominio = preg_replace('~[/?#].*$~', '', $dominio);
    $dominio = strtolower(trim($dominio));
    $dominio = rtrim($dominio, '.');

    if ($dominio === '') {
        return false;
    }

    if (!filter_var($dominio, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        return false;
    }

    return $dominio;
}

function obtenerRutaNmap()
{
    $rutas = [
        'C:\\Program Files\\Nmap\\nmap.exe',
        'C:\\Program Files (x86)\\Nmap\\nmap.exe'
    ];

    foreach ($rutas as $ruta) {
        if (file_exists($ruta)) {
            return $ruta;
        }
    }

    return false;
}

function limpiarTextoServicio(string $texto): string
{
    $texto = trim($texto);

    if ($texto === '') {
        return '';
    }

    $texto = preg_replace('/\s+/', ' ', $texto);

    if (strlen($texto) > 80) {
        $texto = substr($texto, 0, 80) . '...';
    }

    return $texto;
}

function parsearSalidaNmap(string $salida): array
{
    $lineas = preg_split("/\r\n|\n|\r/", $salida);
    $puertos = [];

    foreach ($lineas as $linea) {
        $linea = trim($linea);

        if (preg_match('/^(\d+)\/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$/i', $linea, $m)) {
            $extra = isset($m[5]) ? trim($m[5]) : '';

            if (stripos($extra, 'Service detection performed') !== false) {
                $extra = '';
            }

            $puertos[] = [
                'puerto'    => $m[1],
                'protocolo' => strtoupper($m[2]),
                'estado'    => strtolower($m[3]),
                'servicio'  => $m[4],
                'extra'     => limpiarTextoServicio($extra)
            ];
        }
    }

    return $puertos;
}

$q = mysqli_prepare($conn, "SELECT dominio FROM historial_dominios WHERE id = ? LIMIT 1");
mysqli_stmt_bind_param($q, "i", $id);
mysqli_stmt_execute($q);
$resultadoDominio = mysqli_stmt_get_result($q);
$d = mysqli_fetch_assoc($resultadoDominio);
mysqli_stmt_close($q);

if (!$d) {
    die("Dominio no encontrado.");
}

$dominioNormalizado = normalizarDominio($d['dominio']);
if ($dominioNormalizado === false) {
    die("El dominio guardado no es válido.");
}

$ip_objetivo = gethostbyname($dominioNormalizado);
$nmapPath = obtenerRutaNmap();

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="container mt-5 mb-5">
    <div class="card shadow-lg border-0 mx-auto border-danger border-top border-5">
        <div class="card-body p-5">
            <h4 class="text-muted mb-3">Paso 6 de 6</h4>
            <h2 class="text-danger mb-4"><i class="bi bi-door-open"></i> Escáner de Puertos TCP</h2>
            <p class="lead">Auditando servicios expuestos para: <strong><?= h($dominioNormalizado) ?></strong></p>

            <div class="row mb-4">
                <div class="col-md-4">
                    <div class="card border-secondary shadow-sm">
                        <div class="card-body">
                            <div class="small text-muted">Objetivo</div>
                            <div class="fw-bold"><?= h($dominioNormalizado) ?></div>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card border-secondary shadow-sm">
                        <div class="card-body">
                            <div class="small text-muted">IP resuelta</div>
                            <div class="fw-bold"><?= h($ip_objetivo) ?></div>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card border-secondary shadow-sm">
                        <div class="card-body">
                            <div class="small text-muted">Método</div>
                            <div class="fw-bold">Nmap real optimizado</div>
                        </div>
                    </div>
                </div>
            </div>

            <div id="terminal" class="mt-4 mb-4" style="background:#1a0000;color:#ffb3b3;padding:20px;font-family:'Consolas',monospace;border-radius:8px;height:380px;overflow-y:auto;box-shadow:inset 0 0 15px #000;font-size:0.9rem;border:1px solid #dc3545;">
                <?php
                while (ob_get_level() > 0) {
                    ob_end_flush();
                }
                flush();

                echo "<span style='color:#ffffff;'>[SYS] Iniciando escaneo de puertos con Nmap...</span><br>";
                echo "<span style='color:#ffffff;'>[SYS] Objetivo:</span> " . h($dominioNormalizado) . "<br>";
                echo "<span style='color:#ffffff;'>[SYS] IP resuelta:</span> " . h($ip_objetivo) . "<br>";

                $informeFinal = "=== ESCÁNER DE PUERTOS CON NMAP ===\n";
                $informeFinal .= "Objetivo: " . $dominioNormalizado . "\n";
                $informeFinal .= "IP resuelta: " . $ip_objetivo . "\n";
                $informeFinal .= "Fecha: " . date("d/m/Y H:i:s") . "\n\n";

                $puertosDetectados = [];

                if ($nmapPath === false) {
                    echo "<br><span style='color:#ff8080;'>[ERROR] Nmap no está instalado o no se encontró en la ruta esperada.</span><br>";
                    echo "<span style='color:#ff8080;'>[ERROR] Instala Nmap en Windows para usar este módulo real.</span><br>";

                    $informeFinal .= "ERROR: Nmap no está instalado o no se encontró en la ruta esperada.\n";
                    $informeFinal .= "Rutas comprobadas:\n";
                    $informeFinal .= "- C:\\Program Files\\Nmap\\nmap.exe\n";
                    $informeFinal .= "- C:\\Program Files (x86)\\Nmap\\nmap.exe\n";
                } else {
                    $objetivoEscapado = escapeshellarg($dominioNormalizado);
                    $nmapEscapado = escapeshellarg($nmapPath);

                    $comando = $nmapEscapado . " -Pn -T4 --top-ports 30 --host-timeout 20s " . $objetivoEscapado . " 2>&1";

                    echo "<br><span style='color:#ffffff;'>[SYS] Comando:</span> nmap -Pn -T4 --top-ports 30 --host-timeout 20s " . h($dominioNormalizado) . "<br>";
                    echo "<span style='color:#ffffff;'>[SYS] Ejecutando análisis real optimizado...</span><br><br>";
                    flush();

                    $salida = shell_exec($comando);

                    if ($salida === null || trim($salida) === '') {
                        echo "<span style='color:#ff8080;'>[ERROR] No se recibió salida de Nmap. Revisa que shell_exec esté habilitado.</span><br>";
                        $informeFinal .= "ERROR: No se recibió salida de Nmap.\n";
                        $informeFinal .= "Comprueba que shell_exec esté habilitado en PHP.\n";
                    } else {
                        $puertosDetectados = parsearSalidaNmap($salida);

                        if (!empty($puertosDetectados)) {
                            $abiertos = [];
                            $filtrados = 0;
                            $cerrados = 0;
                            $otros = 0;

                            echo "<span style='color:#ffffff;'>[OK] Resultado del escaneo:</span><br>";
                            echo "<div style='margin-top:8px;'>";
                            echo str_pad("PUERTO", 10) . str_pad("PROTO", 10) . str_pad("ESTADO", 14) . str_pad("SERVICIO", 18) . "DETALLE<br>";
                            echo "--------------------------------------------------------------------------<br>";

                            foreach ($puertosDetectados as $p) {
                                $estado = strtolower($p['estado']);
                                $detalle = $p['extra'] !== '' ? $p['extra'] : '-';

                                if ($estado === 'open') {
                                    $abiertos[] = $p;
                                    $color = "#28a745";
                                } elseif ($estado === 'filtered') {
                                    $filtrados++;
                                    $color = "#ffc107";
                                } elseif ($estado === 'closed') {
                                    $cerrados++;
                                    $color = "#6c757d";
                                } else {
                                    $otros++;
                                    $color = "#17a2b8";
                                }

                                echo str_pad(h($p['puerto']), 10);
                                echo str_pad(h($p['protocolo']), 10);
                                echo "<span style='color:$color;font-weight:bold;'>" . str_pad(h($p['estado']), 14) . "</span>";
                                echo str_pad(h($p['servicio']), 18);
                                echo h($detalle) . "<br>";
                                flush();
                            }

                            echo "</div>";

                            if (!empty($abiertos)) {
                                $informeFinal .= "PUERTOS ABIERTOS DETECTADOS\n";
                                $informeFinal .= "----------------------------------------\n";

                                foreach ($abiertos as $p) {
                                    $detalle = $p['extra'] !== '' ? $p['extra'] : '-';
                                    $informeFinal .= $p['puerto'] . "/" . strtolower($p['protocolo']) . " - open - " . $p['servicio'];
                                    if ($detalle !== '-') {
                                        $informeFinal .= " - " . $detalle;
                                    }
                                    $informeFinal .= "\n";
                                }
                            } else {
                                $informeFinal .= "No se detectaron puertos abiertos en el top 30 escaneado.\n";
                            }

                            $informeFinal .= "\n=== RESUMEN DEL ESCANEO ===\n";
                            $informeFinal .= "Puertos abiertos: " . count($abiertos) . "\n";
                            $informeFinal .= "Puertos filtrados: " . $filtrados . "\n";
                            $informeFinal .= "Puertos cerrados: " . $cerrados . "\n";

                            if ($otros > 0) {
                                $informeFinal .= "Otros estados: " . $otros . "\n";
                            }
                        } else {
                            echo "<span style='color:#ffc107;'>[INFO] Nmap no devolvió puertos interpretables.</span><br>";
                            $informeFinal .= "No se detectaron puertos interpretables en el escaneo.\n";
                        }
                    }
                }

                $stmtDelete = mysqli_prepare($conn, "DELETE FROM osint_resultados WHERE id_historial = ? AND herramienta = 'Puertos'");
                mysqli_stmt_bind_param($stmtDelete, "i", $id);
                mysqli_stmt_execute($stmtDelete);
                mysqli_stmt_close($stmtDelete);

                $stmtInsert = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'Puertos', ?)");
                mysqli_stmt_bind_param($stmtInsert, "is", $id, $informeFinal);
                mysqli_stmt_execute($stmtInsert);
                mysqli_stmt_close($stmtInsert);

                echo "<br><span style='color:#ffffff;'>[OK] Escaneo finalizado. Guardando resultados y generando informe...</span>";
                ?>
            </div>

            <div class="progress" style="height: 15px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated bg-danger w-100 fw-bold">
                    ANÁLISIS COMPLETO - REDIRIGIENDO AL INFORME
                </div>
            </div>
        </div>
    </div>
</div>

<form id="finalForm" action="../resultados/ver_resultado.php" method="POST">
    <input type="hidden" name="id" value="<?= (int)$id ?>">
</form>

<script>
    const terminal = document.getElementById('terminal');
    terminal.scrollTop = terminal.scrollHeight;

    setTimeout(function () {
        document.getElementById('finalForm').submit();
    }, 2500);
</script>

<?php require_once '../includes/footer.php'; ?>