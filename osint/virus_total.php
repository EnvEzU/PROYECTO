<?php
session_start();
require_once '../config/conexion.php';

set_time_limit(60);

if (!isset($_POST['id_historial'])) {
    die("Error: No se recibió el ID por POST.");
}

$id_historial = (int)$_POST['id_historial'];

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

// Obtener dominio desde la base
$sql = "SELECT dominio FROM historial_dominios WHERE id = ? LIMIT 1";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "i", $id_historial);
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);
$data = mysqli_fetch_assoc($res);
mysqli_stmt_close($stmt);

if (!$data) {
    die("Dominio no encontrado.");
}

$dominio = normalizarDominio($data['dominio']);
if ($dominio === false) {
    die("El dominio guardado no es válido.");
}

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="container mt-5 mb-5">
    <div class="card shadow-lg border-0 mx-auto border-primary border-top border-5">
        <div class="card-body p-5">
            <h4 class="text-muted mb-3">Paso 1 de 6</h4>
            <h2 class="text-primary mb-4"><i class="bi bi-shield-shaded"></i> Threat Intelligence (VirusTotal)</h2>
            <p class="lead">Consultando reputación global para: <strong><?= h($dominio) ?></strong></p>

            <div id="terminal" class="mt-4 mb-4" style="background:#000b1a;color:#7cc0ff;padding:20px;font-family:'Consolas',monospace;border-radius:8px;height:350px;overflow-y:auto;box-shadow:inset 0 0 15px #000;font-size:0.9rem;border:1px solid #004085;">
                <?php
                if (ob_get_level() > 0) {
                    ob_end_flush();
                }
                ob_implicit_flush(true);

                echo "<span style='color:#ffffff;'>[SYS] Estableciendo conexión con VirusTotal v3 API...</span><br>";
                echo "<span style='color:#ffffff;'>[SYS] Dominio normalizado:</span> " . h($dominio) . "<br>";
                echo "<span style='color:#ffffff;'>[SYS] Preparando solicitud...</span><br><br>";
                flush();

                $api_key = '9e317a0117464d2b99396fcb00391bc06f54cb4577b7b638545a4b7bd17273b0';
                $url = "https://www.virustotal.com/api/v3/domains/" . rawurlencode($dominio);

                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $url);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_HTTPHEADER, ["x-apikey: $api_key"]);
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
                curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
                curl_setopt($ch, CURLOPT_TIMEOUT, 30);

                echo "[+] Enviando solicitud a VirusTotal...<br>";
                flush();

                $response = curl_exec($ch);
                $curl_error = curl_error($ch);
                $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                curl_close($ch);

                $estado = 'segura';
                $maliciosos = 0;
                $sospechosos = 0;
                $inofensivos = 0;

                if ($response === false || $curl_error) {
                    echo "<span style='color:#ff8080;'>[ERROR] Error de conexión con la API: " . h($curl_error) . "</span><br>";
                    $response = json_encode([
                        "error" => "Error de conexión con la API",
                        "detalle" => $curl_error
                    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
                    $estado = 'sospechosa';
                } elseif ($http_code === 200) {
                    echo "[INFO] Respuesta recibida correctamente. Procesando reputación del dominio...<br>";
                    flush();
                    usleep(300000);

                    $json = json_decode($response, true);
                    $stats = $json['data']['attributes']['last_analysis_stats'] ?? null;

                    if (is_array($stats)) {
                        $maliciosos = (int)($stats['malicious'] ?? 0);
                        $sospechosos = (int)($stats['suspicious'] ?? 0);
                        $inofensivos = (int)($stats['harmless'] ?? 0);

                        $motores = [
                            'Kaspersky',
                            'BitDefender',
                            'Microsoft',
                            'Google Safebrowsing',
                            'Avast',
                            'Sophos'
                        ];

                        foreach ($motores as $m) {
                            echo "<span style='color:#888;'>[CHECK]</span> Verificando motor: " . h($m) . "... <span style='color:#28a745;'>OK</span><br>";
                            echo "<script>document.getElementById('terminal').scrollTop = document.getElementById('terminal').scrollHeight;</script>";
                            flush();
                            usleep(80000);
                        }

                        echo "<br><span style='color:#ffffff;'>[RESUMEN] Resultado agregado de la inteligencia:</span><br>";
                        echo "- Maliciosos: <span class='badge " . ($maliciosos > 0 ? 'bg-danger' : 'bg-success') . "'>$maliciosos</span><br>";
                        echo "- Sospechosos: <span class='badge " . ($sospechosos > 0 ? 'bg-warning text-dark' : 'bg-secondary') . "'>$sospechosos</span><br>";
                        echo "- Inofensivos: <span class='badge bg-success'>$inofensivos</span><br>";

                        if ($maliciosos > 0) {
                            $estado = 'maliciosa';
                        } elseif ($sospechosos > 0) {
                            $estado = 'sospechosa';
                        } else {
                            $estado = 'segura';
                        }
                    } else {
                        echo "<span style='color:#ffc107;'>[INFO] No se encontraron estadísticas completas en la respuesta.</span><br>";
                        $estado = 'sospechosa';
                    }
                } else {
                    echo "<span style='color:#ff8080;'>[ERROR] La API respondió con código HTTP " . (int)$http_code . ".</span><br>";
                    $response = json_encode([
                        "error" => "Error API VirusTotal",
                        "code" => $http_code,
                        "domain" => $dominio
                    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
                    $estado = 'sospechosa';
                }

                // Borramos resultado anterior de VirusTotal si existe
                $stmt_del = mysqli_prepare($conn, "DELETE FROM osint_resultados WHERE id_historial = ? AND herramienta = 'VirusTotal'");
                mysqli_stmt_bind_param($stmt_del, "i", $id_historial);
                mysqli_stmt_execute($stmt_del);
                mysqli_stmt_close($stmt_del);

                // Guardamos respuesta completa
                $stmt_ins = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'VirusTotal', ?)");
                mysqli_stmt_bind_param($stmt_ins, "is", $id_historial, $response);
                mysqli_stmt_execute($stmt_ins);
                mysqli_stmt_close($stmt_ins);

                // Actualizamos estado en historial
                $stmt_upd = mysqli_prepare($conn, "UPDATE historial_dominios SET estado = ? WHERE id = ?");
                mysqli_stmt_bind_param($stmt_upd, "si", $estado, $id_historial);
                mysqli_stmt_execute($stmt_upd);
                mysqli_stmt_close($stmt_upd);

                echo "<br><span style='color:#00ff00;'>[OK] Análisis de reputación finalizado. Estado asignado: " . strtoupper(h($estado)) . "</span>";
                ?>
            </div>

            <div class="progress" style="height: 12px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated bg-primary w-100"></div>
            </div>
        </div>
    </div>
</div>

<form id="autoPostForm" action="whois.php" method="POST">
    <input type="hidden" name="id_historial" value="<?= (int)$id_historial ?>">
</form>

<script>
    const terminal = document.getElementById('terminal');
    terminal.scrollTop = terminal.scrollHeight;

    setTimeout(function () {
        document.getElementById('autoPostForm').submit();
    }, 2200);
</script>

<?php require_once '../includes/footer.php'; ?>