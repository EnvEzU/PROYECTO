<?php
// Archivo: osint/virus_total.php
session_start();
require_once '../config/conexion.php';

// Validar ID
if (!isset($_GET['id_historial'])) { die("Error: Falta ID."); }
$id_historial = intval($_GET['id_historial']);

// Obtener dominio
$sql = "SELECT dominio FROM historial_dominios WHERE id = ?";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "i", $id_historial);
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);
$data = mysqli_fetch_assoc($res);

if (!$data) { die("Dominio no encontrado."); }
$dominio = $data['dominio'];

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="container text-center mt-5 mb-5">
    <div class="card shadow-lg border-0 mx-auto border-primary border-top border-5" style="max-width: 600px;">
        <div class="card-body p-5">
            <h4 class="text-muted mb-3">Paso 1 de 4</h4>
            <h2 class="text-primary mb-4"><i class="bi bi-virus"></i> Consultando VirusTotal API</h2>
            <p class="lead">Analizando motores antivirus para <span class="fw-bold"><?= htmlspecialchars($dominio) ?></span></p>
            
            <div class="mt-4 mb-4">
                <div class="spinner-border text-primary" style="width: 3rem; height: 3rem;" role="status">
                    <span class="visually-hidden">Cargando...</span>
                </div>
            </div>
            <div class="progress" style="height: 25px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated bg-primary w-100 fw-bold" role="progressbar">
                    Descargando reporte de malware...
                </div>
            </div>
        </div>
    </div>
</div>

<?php require_once '../includes/footer.php'; ?>

<?php
// ENVIAR PANTALLA AL NAVEGADOR
while (ob_get_level() > 0) { ob_end_flush(); }
flush();

// ==========================================
// EJECUTAR CONSULTA DE VIRUSTOTAL
// ==========================================
$api_key = '9e317a0117464d2b99396fcb00391bc06f54cb4577b7b638545a4b7bd17273b0'; 
$url = "https://www.virustotal.com/api/v3/domains/" . $dominio;

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, ["x-apikey: $api_key"]);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

$estado = 'segura';
if ($http_code == 200) {
    $json = json_decode($response, true);
    if (($json['data']['attributes']['last_analysis_stats']['malicious'] ?? 0) > 0) {
        $estado = 'maliciosa';
    }
} else {
    $response = json_encode(["error" => "Error API $http_code"]);
}

$stmt = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'VirusTotal', ?)");
mysqli_stmt_bind_param($stmt, "is", $id_historial, $response);
mysqli_stmt_execute($stmt);

mysqli_query($conn, "UPDATE historial_dominios SET estado='$estado' WHERE id=$id_historial");

// IR AL PASO 2 (WHOIS)
echo "<script>window.location.href = 'whois.php?id_historial=$id_historial';</script>";
exit;
?>