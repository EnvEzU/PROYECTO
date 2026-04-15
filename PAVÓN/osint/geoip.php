<?php
// Archivo: osint/geoip.php
session_start();
require_once '../config/conexion.php';

set_time_limit(60);

// 1. Validar ID por POST
if (!isset($_POST['id_historial'])) { 
    die("Error: No se recibió el ID por POST."); 
}
$id = intval($_POST['id_historial']);

// 2. Obtener dominio de la base de datos
$q = mysqli_query($conn, "SELECT dominio FROM historial_dominios WHERE id=$id");
$d = mysqli_fetch_assoc($q);

if (!$d) { die("Dominio no encontrado."); }
$dom_puro = htmlspecialchars($d['dominio']);

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="container mt-5 mb-5">
    <div class="card shadow-lg border-0 mx-auto border-success border-top border-5">
        <div class="card-body p-5">
            <h4 class="text-muted mb-3">Paso 5 de 6</h4>
            <h2 class="text-success mb-4"><i class="bi bi-geo-alt"></i> Geolocalización ASN & BGP</h2>
            <p class="lead">Localizando infraestructura física para: <strong><?= $dom_puro ?></strong></p>
            
            <div id="terminal" class="mt-4 mb-4" style="background: #0d1117; color: #28a745; padding: 20px; font-family: 'Consolas', monospace; border-radius: 8px; height: 350px; overflow-y: auto; box-shadow: inset 0 0 15px #000; font-size: 0.85rem; border: 1px solid #198754;">
                <span style="color: #ffffff;">[SYS] Iniciando trazado de ruta IP...</span><br>
                <span style="color: #ffffff;">[SYS] Consultando bases de datos MaxMind e IP-API...</span><br><br>

                <?php
                // Forzar volcado de buffer
                while (ob_get_level() > 0) { ob_end_flush(); }
                flush();

                // ==========================================
                // MOTOR GEOIP (LÓGICA CON SALIDA EN VIVO)
                // ==========================================
                $ip = gethostbyname($d['dominio']);
                $out = "=== RASTREO FÍSICO DEL SERVIDOR ===\n\n";

                if ($ip !== $d['dominio']) {
                    echo "[+] Resolviendo IP: <span style='color:#fff;'>$ip</span><br>";
                    flush();
                    usleep(500000); // Efecto de carga

                    $api_url = "http://ip-api.com/json/" . $ip . "?fields=status,country,regionName,city,isp,org,as,query";
                    
                    $ch = curl_init();
                    curl_setopt($ch, CURLOPT_URL, $api_url);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)');
                    curl_setopt($ch, CURLOPT_TIMEOUT, 15);
                    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
                    
                    $json_res = curl_exec($ch);
                    curl_close($ch);
                    
                    if ($json_res) {
                        $geo = json_decode($json_res, true);
                        if ($geo && $geo['status'] == 'success') {
                            
                            $lineas = [
                                "IP Objetivo  : " . $geo['query'],
                                "País         : " . $geo['country'],
                                "Región/City  : " . $geo['regionName'] . " (" . $geo['city'] . ")",
                                "Proveedor    : " . $geo['isp'],
                                "Organización : " . $geo['org'],
                                "ASN / BGP    : " . $geo['as']
                            ];

                            foreach ($lineas as $l) {
                                usleep(300000); // Retardo visual por cada dato
                                echo "<span style='color:#888;'>[DATA]</span> " . htmlspecialchars($l) . "<br>";
                                $out .= $l . "\n";
                                
                                // Auto-scroll
                                echo "<script>document.getElementById('terminal').scrollTop = document.getElementById('terminal').scrollHeight;</script>";
                                flush();
                            }
                        } else {
                            $err = "Error: La API no devolvió datos para la IP $ip.";
                            echo "<span class='text-danger'>[!] $err</span>";
                            $out .= $err;
                        }
                    } else {
                        $err = "Error: No se pudo conectar con el servicio de mapas.";
                        echo "<span class='text-danger'>[!] $err</span>";
                        $out .= $err;
                    }
                } else {
                    $err = "Error: No se pudo resolver la IP DNS del dominio.";
                    echo "<span class='text-danger'>[!] $err</span>";
                    $out .= $err;
                }

                // 3. GUARDAR RESULTADO EN LA BD
                $stmt = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'GeoIP', ?)");
                mysqli_stmt_bind_param($stmt, "is", $id, $out);
                mysqli_stmt_execute($stmt);
                ?>
                <br><span style="color: #ffffff;">[OK] Ubicación geográfica identificada.</span>
            </div>

            <div class="progress" style="height: 12px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated bg-success w-100"></div>
            </div>
        </div>
    </div>
</div>

<form id="nextStep" action="puertos.php" method="POST">
    <input type="hidden" name="id_historial" value="<?= $id ?>">
</form>

<script>
    // Delay de 2 segundos para que el usuario verifique la ubicación
    setTimeout(function() {
        document.getElementById('nextStep').submit();
    }, 2000);
</script>

<?php require_once '../includes/footer.php'; ?>