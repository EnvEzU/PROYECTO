<?php
session_start();
require_once '../config/conexion.php';

set_time_limit(60);

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

$stmt = mysqli_prepare($conn, "SELECT dominio FROM historial_dominios WHERE id = ? LIMIT 1");
mysqli_stmt_bind_param($stmt, "i", $id);
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);
$d = mysqli_fetch_assoc($res);
mysqli_stmt_close($stmt);

if (!$d) {
    die("Dominio no encontrado.");
}

$dominio = normalizarDominio($d['dominio']);
if ($dominio === false) {
    die("El dominio guardado no es válido.");
}

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="container mt-5 mb-5">
    <div class="card shadow-lg border-0 mx-auto border-success border-top border-5">
        <div class="card-body p-5">
            <h4 class="text-muted mb-3">Paso 5 de 6</h4>
            <h2 class="text-success mb-4"><i class="bi bi-geo-alt"></i> Geolocalización ASN & BGP</h2>
            <p class="lead">Localizando infraestructura física para: <strong><?= h($dominio) ?></strong></p>

            <div id="terminal" class="mt-4 mb-4" style="background:#0d1117;color:#28a745;padding:20px;font-family:'Consolas',monospace;border-radius:8px;height:350px;overflow-y:auto;box-shadow:inset 0 0 15px #000;font-size:0.9rem;border:1px solid #198754;">
                <?php
                while (ob_get_level() > 0) {
                    ob_end_flush();
                }
                flush();

                echo "<span style='color:#ffffff;'>[SYS] Iniciando trazado de infraestructura IP...</span><br>";
                echo "<span style='color:#ffffff;'>[SYS] Dominio:</span> " . h($dominio) . "<br><br>";
                flush();

                $ip = gethostbyname($dominio);
                $out = "=== GEOLOCALIZACIÓN Y ASN DEL SERVIDOR ===\n\n";
                $out .= "Dominio: " . $dominio . "\n";

                if ($ip !== $dominio) {
                    echo "[+] Resolviendo IP: <span style='color:#fff;'>" . h($ip) . "</span><br>";
                    $out .= "IP Objetivo: " . $ip . "\n";
                    flush();
                    usleep(250000);

                    $api_url = "http://ip-api.com/json/" . rawurlencode($ip) . "?fields=status,country,regionName,city,isp,org,as,query,message";

                    $ch = curl_init();
                    curl_setopt($ch, CURLOPT_URL, $api_url);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)');
                    curl_setopt($ch, CURLOPT_TIMEOUT, 15);
                    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

                    $json_res = curl_exec($ch);
                    $curl_error = curl_error($ch);
                    curl_close($ch);

                    if ($json_res) {
                        $geo = json_decode($json_res, true);

                        if (is_array($geo) && isset($geo['status']) && $geo['status'] === 'success') {
                            $lineas = [
                                "País         : " . ($geo['country'] ?? 'N/D'),
                                "Región/City  : " . ($geo['regionName'] ?? 'N/D') . " (" . ($geo['city'] ?? 'N/D') . ")",
                                "Proveedor    : " . ($geo['isp'] ?? 'N/D'),
                                "Organización : " . ($geo['org'] ?? 'N/D'),
                                "ASN / BGP    : " . ($geo['as'] ?? 'N/D')
                            ];

                            foreach ($lineas as $l) {
                                usleep(180000);
                                echo "<span style='color:#888;'>[DATA]</span> " . h($l) . "<br>";
                                $out .= $l . "\n";

                                echo "<script>document.getElementById('terminal').scrollTop = document.getElementById('terminal').scrollHeight;</script>";
                                flush();
                            }
                        } else {
                            $mensajeErrorApi = $geo['message'] ?? 'La API no devolvió datos válidos.';
                            $err = "Error: " . $mensajeErrorApi;
                            echo "<span style='color:#ff8080;'>[ERROR] " . h($err) . "</span><br>";
                            $out .= $err . "\n";
                        }
                    } else {
                        $err = "Error: No se pudo conectar con el servicio GeoIP.";
                        if (!empty($curl_error)) {
                            $err .= " Detalle: " . $curl_error;
                        }

                        echo "<span style='color:#ff8080;'>[ERROR] " . h($err) . "</span><br>";
                        $out .= $err . "\n";
                    }
                } else {
                    $err = "Error: No se pudo resolver la IP DNS del dominio.";
                    echo "<span style='color:#ff8080;'>[ERROR] " . h($err) . "</span><br>";
                    $out .= $err . "\n";
                }

                $stmtDelete = mysqli_prepare($conn, "DELETE FROM osint_resultados WHERE id_historial = ? AND herramienta = 'GeoIP'");
                mysqli_stmt_bind_param($stmtDelete, "i", $id);
                mysqli_stmt_execute($stmtDelete);
                mysqli_stmt_close($stmtDelete);

                $stmtInsert = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'GeoIP', ?)");
                mysqli_stmt_bind_param($stmtInsert, "is", $id, $out);
                mysqli_stmt_execute($stmtInsert);
                mysqli_stmt_close($stmtInsert);
                ?>
                <br><span style="color:#ffffff;">[OK] Consulta GeoIP finalizada.</span>
            </div>

            <div class="progress" style="height: 12px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated bg-success w-100"></div>
            </div>
        </div>
    </div>
</div>

<form id="nextStep" action="puertos.php" method="POST">
    <input type="hidden" name="id_historial" value="<?= (int)$id ?>">
</form>

<script>
    const terminal = document.getElementById('terminal');
    terminal.scrollTop = terminal.scrollHeight;

    setTimeout(function () {
        document.getElementById('nextStep').submit();
    }, 1800);
</script>

<?php require_once '../includes/footer.php'; ?>