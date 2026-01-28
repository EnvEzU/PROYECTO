<?php
// Archivo: osint/whois.php
session_start();
require_once '../config/conexion.php';

if (!isset($_GET['id_historial'])) { die("Error ID."); }
$id = intval($_GET['id_historial']);

// 1. Obtener dominio
$q = mysqli_query($conn, "SELECT dominio FROM historial_dominios WHERE id=$id");
$d = mysqli_fetch_assoc($q);
$dom = escapeshellcmd($d['dominio']);

// 2. Ejecutar WHOIS
$out = shell_exec("whois $dom 2>&1");
if (!$out) $out = "Error al ejecutar WHOIS o no instalado.";

// 3. Guardar
$stmt = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'Whois', ?)");
mysqli_stmt_bind_param($stmt, "is", $id, $out);
mysqli_stmt_execute($stmt);

// 4. Ir a resultados
header("Location: ../resultados/ver_resultado.php?id=$id");
exit;
?>