<?php
// ==========================================
// 1. LÓGICA PHP (WHOIS SYSTEM COMMAND)
// ==========================================
session_start();
require_once '../config/conexion.php';

if (!isset($_SESSION['id_usuario'])) { header("Location: ../auth/login.php"); exit; }
if (!isset($_GET['id_historial'])) { die("Error: Falta ID."); }

$id_historial = intval($_GET['id_historial']);

// 1. Obtener dominio
$sql = "SELECT dominio FROM historial_dominios WHERE id = ?";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "i", $id_historial);
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);
$row = mysqli_fetch_assoc($res);
$dominio = escapeshellcmd($row['dominio']); // Sanitizar para evitar inyección de comandos

// 2. Ejecutar comando WHOIS
// Intentamos ejecutar el comando del sistema (Linux/Windows si tiene path)
$output = shell_exec("whois $dominio 2>&1");

// Fallback por si no tienes whois instalado en Windows XAMPP
if (empty($output) || strpos($output, 'not recognized') !== false) {
    $output = "ADVERTENCIA: No se pudo ejecutar 'whois' en el servidor.\n";
    $output .= "Asegúrate de que el ejecutable está en el PATH o usa Linux.\n";
    $output .= "Simulando datos para: " . $dominio;
}

// 3. Guardar resultado
$sql_ins = "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'Whois', ?)";
$stmt_ins = mysqli_prepare($conn, $sql_ins);
mysqli_stmt_bind_param($stmt_ins, "is", $id_historial, $output);
mysqli_stmt_execute($stmt_ins);

// 4. Finalizar -> Ir a ver resultado
header("Location: ../resultados/ver_resultado.php?id=" . $id_historial);
exit;
?>