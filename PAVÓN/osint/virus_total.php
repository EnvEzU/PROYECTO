<?php
session_start();
require_once '../config/conexion.php';

// Seguridad: Verificar login
if (!isset($_SESSION['id_usuario'])) { header("Location: ../auth/login.php"); exit; }

// Verificar ID de historial
if (!isset($_GET['id_historial'])) { die("Error: Falta ID de análisis."); }
$id_historial = intval($_GET['id_historial']);

// 1. Obtener el dominio de la base de datos
$sql_dom = "SELECT dominio FROM historial_dominios WHERE id = ? AND id_usuario = ?";
$stmt = mysqli_prepare($conn, $sql_dom);
mysqli_stmt_bind_param($stmt, "ii", $id_historial, $_SESSION['id_usuario']);
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);
$data = mysqli_fetch_assoc($res);

if (!$data) { die("Dominio no encontrado o sin permiso."); }

$dominio = $data['dominio'];

// 2. Configurar llamada a API VirusTotal (V3)
// ¡¡IMPORTANTE!!: Poner tu API KEY aquí
$api_key = 'TU_API_KEY_AQUI'; 
$url_api = "https://www.virustotal.com/api/v3/domains/" . $dominio;

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url_api);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "x-apikey: $api_key"
]);
// Desactivar verificación SSL para evitar problemas en XAMPP local
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// 3. Procesar respuesta
$resultado_json = $response;
$estado_final = 'segura'; // Por defecto

if ($http_code == 200) {
    $json = json_decode($response, true);
    // Verificar stats de maliciosos
    $malicious = $json['data']['attributes']['last_analysis_stats']['malicious'] ?? 0;
    
    if ($malicious > 0) {
        $estado_final = 'maliciosa';
    }
} else {
    // Si falla la API, guardamos el error en el JSON
    $resultado_json = json_encode(["error" => "Fallo API o Dominio no registrado en VT", "codigo" => $http_code]);
}

// 4. Guardar en tabla osint_resultados
$sql_insert = "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'VirusTotal', ?)";
$stmt2 = mysqli_prepare($conn, $sql_insert);
mysqli_stmt_bind_param($stmt2, "is", $id_historial, $resultado_json);
mysqli_stmt_execute($stmt2);

// 5. Actualizar estado general en historial_dominios
$sql_update = "UPDATE historial_dominios SET estado = ? WHERE id = ?";
$stmt3 = mysqli_prepare($conn, $sql_update);
mysqli_stmt_bind_param($stmt3, "si", $estado_final, $id_historial);
mysqli_stmt_execute($stmt3);

// 6. Siguiente paso: WHOIS
header("Location: whois.php?id_historial=" . $id_historial);
exit;
?>