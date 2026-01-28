<?php
// Archivo: osint/virus_total.php
session_start();
require_once '../config/conexion.php';

// Validar ID
if (!isset($_GET['id_historial'])) { die("Error: Falta ID."); }
$id_historial = intval($_GET['id_historial']);

// 1. Obtener dominio (Sin filtrar por usuario para permitir invitados)
$sql = "SELECT dominio FROM historial_dominios WHERE id = ?";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "i", $id_historial);
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);
$data = mysqli_fetch_assoc($res);

if (!$data) { die("Dominio no encontrado."); }
$dominio = $data['dominio'];

// 2. Consulta API
$api_key = 'TU_API_KEY_AQUI'; // <--- ¡PON TU API KEY!
$url = "https://www.virustotal.com/api/v3/domains/" . $dominio;

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, ["x-apikey: $api_key"]);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// 3. Procesar
$estado = 'segura';
if ($http_code == 200) {
    $json = json_decode($response, true);
    if (($json['data']['attributes']['last_analysis_stats']['malicious'] ?? 0) > 0) {
        $estado = 'maliciosa';
    }
} else {
    $response = json_encode(["error" => "Error API $http_code"]);
}

// 4. Guardar
$stmt = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'VirusTotal', ?)");
mysqli_stmt_bind_param($stmt, "is", $id_historial, $response);
mysqli_stmt_execute($stmt);

mysqli_query($conn, "UPDATE historial_dominios SET estado='$estado' WHERE id=$id_historial");

header("Location: whois.php?id_historial=$id_historial");
exit;
?>