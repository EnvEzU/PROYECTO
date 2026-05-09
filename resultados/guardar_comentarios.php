<?php
session_start();
require_once '../config/conexion.php';

// Verificar que el usuario esté logueado
if (!isset($_SESSION['id_usuario'])) {
    header("Location: ../auth/login.php");
    exit;
}

// Si no vienen datos por POST, expulsar
if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    header("Location: ../index.php");
    exit;
}

// Recoger y limpiar variables
$id_usuario      = (int)$_SESSION['id_usuario'];
$autor_nombre    = trim($_SESSION['usuario'] ?? 'Usuario');
$dominio_entrada = $_POST['dominio'] ?? '';
$comentario      = trim($_POST['comentario'] ?? '');
$tipo_comentario = trim($_POST['tipo_comentario'] ?? 'otro');
$id_historial    = isset($_POST['id_historial']) ? (int)$_POST['id_historial'] : 0;

// Normalización correcta (Cambiando el delimitador # por ~)
$dominio = trim($dominio_entrada);
$dominio = preg_replace('~^https?://~i', '', $dominio); 
$dominio = preg_replace('~^www\.~i', '', $dominio);     
$dominio = preg_replace('~[/?#].*$~', '', $dominio);    
$dominio = strtolower(trim($dominio));
$dominio = rtrim($dominio, '.');

$tipos_validos = ['phishing', 'malware', 'spam', 'suplantacion', 'fraude', 'otro'];

// Comprobaciones de seguridad
if (empty($dominio) || $comentario === '' || !in_array($tipo_comentario, $tipos_validos, true)) {
    if ($id_historial > 0) {
        header("Location: ver_resultado.php?id=" . $id_historial . "&comentario=error");
    } else {
        header("Location: ../index.php");
    }
    exit;
}

// Limitar el tamaño del comentario para que no rompa la base de datos
if (mb_strlen($comentario) > 1000) {
    $comentario = mb_substr($comentario, 0, 1000);
}

// Inserción en la base de datos
$sql = "INSERT INTO comentarios_dominios (dominio, id_usuario, autor_nombre, comentario, tipo_comentario, estado)
        VALUES (?, ?, ?, ?, ?, 'aprobado')";

if ($stmt = mysqli_prepare($conn, $sql)) {
    mysqli_stmt_bind_param($stmt, "sisss", $dominio, $id_usuario, $autor_nombre, $comentario, $tipo_comentario);
    
    if (mysqli_stmt_execute($stmt)) {
        // Éxito: redireccionamos con ok
        header("Location: ver_resultado.php?id=" . $id_historial . "&comentario=ok");
    } else {
        // Falla la ejecución de la consulta
        header("Location: ver_resultado.php?id=" . $id_historial . "&comentario=error");
    }
    mysqli_stmt_close($stmt);
} else {
    // Falla la preparación de la consulta
    header("Location: ver_resultado.php?id=" . $id_historial . "&comentario=error");
}
exit;
?>