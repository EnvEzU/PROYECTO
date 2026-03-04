<?php
// Archivo: osint/geoip.php
session_start();
require_once '../config/conexion.php';

set_time_limit(60);

if (!isset($_GET['id_historial'])) { die("Error ID."); }
$id = intval($_GET['id_historial']);

$q = mysqli_query($conn, "SELECT dominio FROM historial_dominios WHERE id=$id");
$d = mysqli_fetch_assoc($q);

if (!$d) { die("Dominio no encontrado."); }
$dom_puro = htmlspecialchars($d['dominio']);

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="container text-center mt-5 mb-5">
    <div class="card shadow-lg border-0 mx-auto border-success border-top border-5" style="max-width: 600px;">
        <div class="card-body p-5">
            <h4 class="text-muted mb-3">Paso 5 de 7</h4>
            <h2 class="text-success mb-4"><i class="bi bi-geo-alt"></i> Geolocalización ASN</h2>
            <p class="lead">Ubicando servidor para <span class="fw-bold"><?= $dom_puro ?></span></p>
            <div class="mt-4 mb-4">
                <div class="spinner-border text-success" style="width: 3rem; height: 3rem;" role="status"></div>
            </div>
            <div class="progress" style="height: 25px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated bg-success w-100" role="progressbar">Rastreando coordenadas...</div>
            </div>
        </div>
    </div>
</div>

<?php require_once '../includes/footer.php'; ?>

<?php
while (ob_get_level() > 0) { ob_end_flush(); }
flush();

// MOTOR GEOIP CON CURL
$ip = gethostbyname($d['dominio']);
$out = "=== RASTREO FÍSICO DEL SERVIDOR ===\n\n";

if ($ip !== $d['dominio']) {
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
            $out .= "IP Objetivo : " . $geo['query'] . "\n";
            $out .= "País        : " . $geo['country'] . "\n";
            $out .= "Región/City : " . $geo['regionName'] . " (" . $geo['city'] . ")\n";
            $out .= "Proveedor   : " . $geo['isp'] . "\n";
            $out .= "Organización: " . $geo['org'] . "\n";
            $out .= "ASN / BGP   : " . $geo['as'] . "\n";
        } else {
            $out .= "Error: La API no devolvió datos para la IP $ip.";
        }
    } else {
        $out .= "Error: No se pudo conectar con el servicio de mapas (ip-api).";
    }
} else {
    $out .= "Error: No se pudo resolver la IP DNS del dominio.";
}

$stmt = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'GeoIP', ?)");
mysqli_stmt_bind_param($stmt, "is", $id, $out);
mysqli_stmt_execute($stmt);

echo "<script>window.location.href = 'subdominios.php?id_historial=$id';</script>";
exit;
?>