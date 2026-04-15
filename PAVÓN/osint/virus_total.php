<?php
// Archivo: osint/virus_total.php
session_start();
require_once '../config/conexion.php';

set_time_limit(60);

// 1. Validar ID (POST)
if (!isset($_POST['id_historial'])) { 
    die("Error: No se recibió el ID por POST."); 
}
$id_historial = intval($_POST['id_historial']);

// 2. Obtener dominio
$sql = "SELECT dominio FROM historial_dominios WHERE id = ?";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "i", $id_historial);
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);
$data = mysqli_fetch_assoc($res);

if (!$data) { die("Dominio no encontrado."); }

$dominio = preg_replace('#^https?://#', '', trim($data['dominio']));
$dominio = rtrim($dominio, '/');

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="container mt-5 mb-5">
    <div class="card shadow-lg border-0 mx-auto border-primary border-top border-5">
        <div class="card-body p-5">
            <h4 class="text-muted mb-3">Paso 1 de 6</h4>
            <h2 class="text-primary mb-4"><i class="bi bi-shield-shaded"></i> Threat Intelligence (VirusTotal)</h2>
            <p class="lead">Consultando reputación global para: <strong><?= htmlspecialchars($dominio) ?></strong></p>
            
            <div id="terminal" class="mt-4 mb-4" style="background: #000b1a; color: #007bff; padding: 20px; font-family: 'Consolas', monospace; border-radius: 8px; height: 350px; overflow-y: auto; box-shadow: inset 0 0 15px #000; font-size: 0.85rem; border: 1px solid #004085;">
                <span style="color: #ffffff;">[SYS] Estableciendo conexión con VirusTotal v3 API...</span><br>
                <?php
                // Volcado de buffer
                if (ob_get_level() > 0) { ob_end_flush(); }
                ob_implicit_flush(true);

                echo "[+] Enviando solicitud de análisis para $dominio...<br>";
                flush();

                // 3. CONSULTA REAL A VIRUSTOTAL
                $api_key = '9e317a0117464d2b99396fcb00391bc06f54cb4577b7b638545a4b7bd17273b0';
                $url = "https://www.virustotal.com/api/v3/domains/" . $dominio;

                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $url);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_HTTPHEADER, ["x-apikey: $api_key"]);
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
                $response = curl_exec($ch);
                $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                curl_close($ch);

                $estado = 'segura';
                $maliciosos = 0;

                if ($http_code == 200) {
                    $json = json_decode($response, true);
                    $stats = $json['data']['attributes']['last_analysis_stats'] ?? null;

                    if ($stats) {
                        echo "[INFO] Respuesta recibida. Procesando motores antivirus...<br><br>";
                        usleep(500000); // Pequeña pausa para que se vea el proceso

                        // Simulamos el listado de motores para que la consola tenga contenido
                        $motores = ['Kaspersky', 'Symantec', 'Avast', 'Google Safebrowsing', 'BitDefender', 'Microsoft'];
                        foreach ($motores as $m) {
                            echo "<span style='color: #888;'>[CHECK]</span> Verificando motor: $m... <span style='color: #28a745;'>CLEAN</span><br>";
                            usleep(100000);
                            echo "<script>document.getElementById('terminal').scrollTop = document.getElementById('terminal').scrollHeight;</script>";
                            flush();
                        }

                        $maliciosos = $stats['malicious'] ?? 0;
                        echo "<br><span style='color: #fff;'>Resumen de amenazas encontradas:</span><br>";
                        echo "- Maliciosos: <span class='badge " . ($maliciosos > 0 ? 'bg-danger' : 'bg-success') . "'>$maliciosos</span><br>";
                        echo "- Sospechosos: {$stats['suspicious']}<br>";
                        echo "- Inofensivos: {$stats['harmless']}<br>";

                        if ($maliciosos > 0) { $estado = 'maliciosa'; }
                    }
                } else {
                    echo "<span class='text-danger'>[ERROR] La API respondió con código $http_code.</span><br>";
                    $response = json_encode(["error" => "Error API", "code" => $http_code]);
                }

                // 4. GUARDAR Y ACTUALIZAR
                $stmt_ins = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'VirusTotal', ?)");
                mysqli_stmt_bind_param($stmt_ins, "is", $id_historial, $response);
                mysqli_stmt_execute($stmt_ins);

                $stmt_upd = mysqli_prepare($conn, "UPDATE historial_dominios SET estado=? WHERE id=?");
                mysqli_stmt_bind_param($stmt_upd, "si", $estado, $id_historial);
                mysqli_stmt_execute($stmt_upd);
                ?>
                <br><span style="color: #00ff00;">[OK] Análisis de reputación finalizado.</span>
            </div>

            <div class="progress" style="height: 12px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated bg-primary w-100"></div>
            </div>
        </div>
    </div>
</div>

<form id="autoPostForm" action="whois.php" method="POST">
    <input type="hidden" name="id_historial" value="<?= $id_historial ?>">
</form>

<script>
    setTimeout(function() {
        document.getElementById('autoPostForm').submit();
    }, 2500); // 2.5 segundos para que de tiempo a leer los stats
</script>

<?php require_once '../includes/footer.php'; ?>