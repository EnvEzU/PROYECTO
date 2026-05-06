<?php
session_start();
require_once '../config/conexion.php';

set_time_limit(90);

if (!isset($_POST['id_historial'])) {
    die("Error: No se recibió el ID.");
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

function obtenerRutaPython()
{
    $rutas = [
        'C:\\Users\\Javier\\AppData\\Local\\Microsoft\\WindowsApps\\python.exe',
        'C:\\Python312\\python.exe',
        'C:\\Python311\\python.exe',
        'C:\\Python310\\python.exe'
    ];

    foreach ($rutas as $ruta) {
        if (file_exists($ruta)) {
            return $ruta;
        }
    }

    return 'python';
}

function filtrarVariaciones(array $lineas, string $dominioOriginal, int $limite = 20): array
{
    $resultado = [];
    $vistos = [];
    $dominioOriginal = strtolower(trim($dominioOriginal));

    foreach ($lineas as $linea) {
        $linea = trim($linea);

        if ($linea === '') {
            continue;
        }

        if (stripos($linea, 'dnstwist') !== false) {
            continue;
        }

        if (stripos($linea, 'error') !== false) {
            continue;
        }

        if (stripos($linea, 'fatal') !== false) {
            continue;
        }

        if (stripos($linea, 'Traceback') !== false) {
            continue;
        }

        if ($linea === $dominioOriginal) {
            continue;
        }

        if (isset($vistos[$linea])) {
            continue;
        }

        // Solo dominios con punto y con forma razonable
        if (!preg_match('/^[a-z0-9.-]+\.[a-z]{2,}$/i', $linea)) {
            continue;
        }

        $vistos[$linea] = true;
        $resultado[] = $linea;

        if (count($resultado) >= $limite) {
            break;
        }
    }

    return $resultado;
}

$q = mysqli_prepare($conn, "SELECT dominio FROM historial_dominios WHERE id = ? LIMIT 1");
mysqli_stmt_bind_param($q, "i", $id);
mysqli_stmt_execute($q);
$res = mysqli_stmt_get_result($q);
$d = mysqli_fetch_assoc($res);
mysqli_stmt_close($q);

if (!$d) {
    die("Dominio no encontrado.");
}

$dominio = normalizarDominio($d['dominio']);
if ($dominio === false) {
    die("El dominio guardado no es válido.");
}

$nombre_solo = explode('.', $dominio)[0];
$longitud = strlen($nombre_solo);

if ($longitud >= 10) {
    $fuzzers = "omission,repetition,replacement";
} else {
    $fuzzers = "omission,repetition,replacement,transposition";
}

$python = obtenerRutaPython();
$pythonEsc = escapeshellarg($python);
$domEsc = escapeshellarg($dominio);

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="container mt-5">
    <div class="card shadow-lg border-0 border-warning border-top border-5">
        <div class="card-body p-5">
            <h4 class="text-muted mb-3">Paso 3 de 6</h4>
            <h2 class="text-warning mb-4"><i class="bi bi-cpu"></i> Motor de Typosquatting (Modo filtrado)</h2>
            <p class="lead">Analizando variaciones relevantes para: <strong><?= h($dominio) ?></strong></p>

            <div class="row mb-4">
                <div class="col-md-4">
                    <div class="card border-secondary shadow-sm">
                        <div class="card-body">
                            <div class="small text-muted">Dominio</div>
                            <div class="fw-bold"><?= h($dominio) ?></div>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card border-secondary shadow-sm">
                        <div class="card-body">
                            <div class="small text-muted">Fuzzers usados</div>
                            <div class="fw-bold"><?= h($fuzzers) ?></div>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card border-secondary shadow-sm">
                        <div class="card-body">
                            <div class="small text-muted">Límite</div>
                            <div class="fw-bold">20 resultados</div>
                        </div>
                    </div>
                </div>
            </div>

            <div id="terminal" style="background:#121212;color:#ffc107;padding:20px;font-family:'Consolas',monospace;border-radius:8px;height:400px;overflow-y:auto;font-size:0.9rem;border:1px solid #333;scroll-behavior:smooth;">
                <?php
                while (ob_get_level() > 0) {
                    ob_end_flush();
                }
                ob_implicit_flush(true);

                echo "<span style='color:#ffffff;'>[SYS] Iniciando análisis de typosquatting filtrado...</span><br>";
                echo "<span style='color:#ffffff;'>[SYS] Dominio:</span> " . h($dominio) . "<br>";
                echo "<span style='color:#ffffff;'>[SYS] Fuzzers:</span> " . h($fuzzers) . "<br><br>";
                flush();

                $comando = $pythonEsc . " -m dnstwist --format list --fuzzers " . escapeshellarg($fuzzers) . " " . $domEsc . " 2>&1";
                echo "<span style='color:#ffffff;'>[SYS] Ejecutando dnstwist...</span><br><br>";
                flush();

                $salida = shell_exec($comando);

                $informeFinal = "=== ANÁLISIS DE TYPOSQUATTING CON DNSTWIST ===\n";
                $informeFinal .= "Dominio original: " . $dominio . "\n";
                $informeFinal .= "Fuzzers usados: " . $fuzzers . "\n";
                $informeFinal .= "Fecha: " . date("d/m/Y H:i:s") . "\n\n";

                $contador = 0;

                if ($salida === null || trim($salida) === '') {
                    echo "<span style='color:#ff8080;'>[ERROR] No se recibió salida de dnstwist.</span><br>";
                    $informeFinal .= "ERROR: No se recibió salida de dnstwist.\n";
                } else {
                    $lineas = preg_split("/\r\n|\n|\r/", $salida);
                    $variaciones = filtrarVariaciones($lineas, $dominio, 20);

                    if (!empty($variaciones)) {
                        echo "<span style='color:#ffffff;'>[OK] Variaciones relevantes detectadas:</span><br><br>";
                        $informeFinal .= "VARIACIONES RELEVANTES DETECTADAS\n";
                        $informeFinal .= "----------------------------------------\n";

                        foreach ($variaciones as $variante) {
                            $contador++;
                            echo "<span style='color:#888;'>[+]</span> " . h($variante) . "<br>";
                            $informeFinal .= $contador . ". " . $variante . "\n";

                            if ($contador % 5 === 0) {
                                echo "<script>document.getElementById('terminal').scrollTop = document.getElementById('terminal').scrollHeight;</script>";
                            }

                            flush();
                            usleep(15000);
                        }
                    } else {
                        echo "<span style='color:#ffc107;'>[INFO] No se detectaron variaciones relevantes con el filtro aplicado.</span><br>";
                        $informeFinal .= "No se detectaron variaciones relevantes con el filtro aplicado.\n";
                    }
                }

                $informeFinal .= "\nTotal de variaciones mostradas: " . $contador . "\n";

                $stmtDelete = mysqli_prepare($conn, "DELETE FROM osint_resultados WHERE id_historial = ? AND herramienta = 'Dnstwist'");
                mysqli_stmt_bind_param($stmtDelete, "i", $id);
                mysqli_stmt_execute($stmtDelete);
                mysqli_stmt_close($stmtDelete);

                $stmtInsert = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'Dnstwist', ?)");
                mysqli_stmt_bind_param($stmtInsert, "is", $id, $informeFinal);
                mysqli_stmt_execute($stmtInsert);
                mysqli_stmt_close($stmtInsert);

                echo "<br><span style='color:#00ff00;'>[FINALIZADO] Se han generado " . $contador . " variaciones relevantes.</span>";
                ?>
            </div>

            <div class="progress mt-3" style="height: 10px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated bg-warning w-100"></div>
            </div>
        </div>
    </div>
</div>

<form id="formNext" action="dig.php" method="POST">
    <input type="hidden" name="id_historial" value="<?= (int)$id ?>">
</form>

<script>
    const term = document.getElementById('terminal');
    term.scrollTop = term.scrollHeight;

    setTimeout(function () {
        document.getElementById('formNext').submit();
    }, 2200);
</script>

<?php require_once '../includes/footer.php'; ?>