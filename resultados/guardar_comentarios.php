<?php
session_start();
require_once '../config/conexion.php';
require_once '../includes/seguridad.php';

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

$token_reporte = strtolower(trim((string)($_POST['token_reporte'] ?? '')));
$id_historial = obtenerIdAnalisisPorToken($conn, $token_reporte);

function volverInformeComentario(string $token_reporte, string $estado): void
{
    if (tokenReporteValido($token_reporte)) {
        header("Location: ver_resultado.php?r=" . urlencode($token_reporte) . "&comentario=" . urlencode($estado));
    } else {
        header("Location: ../index.php");
    }
    exit;
}

if (!validarCsrf()) {
    volverInformeComentario($token_reporte, 'error');
}

if ($id_historial <= 0 || !usuarioPuedeAccederAnalisis($conn, $id_historial) || !analisisEstaCompleto($conn, $id_historial)) {
    header("Location: ../index.php");
    exit;
}

$token_reporte = asegurarTokenAnalisis($conn, $id_historial);

// Recoger y limpiar variables
$id_usuario      = (int)$_SESSION['id_usuario'];
$autor_nombre    = trim($_SESSION['usuario'] ?? 'Usuario');
$comentario      = trim($_POST['comentario'] ?? '');
$tipo_comentario = trim($_POST['tipo_comentario'] ?? 'otro');

$stmt_dominio = mysqli_prepare($conn, "SELECT dominio FROM historial_dominios WHERE id = ? LIMIT 1");
mysqli_stmt_bind_param($stmt_dominio, "i", $id_historial);
mysqli_stmt_execute($stmt_dominio);
$fila_dominio = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt_dominio));
mysqli_stmt_close($stmt_dominio);

if (!$fila_dominio) {
    header("Location: ../index.php");
    exit;
}

// El dominio se toma de la BD para evitar manipulación del campo oculto.
$dominio = trim($fila_dominio['dominio']);
$dominio = preg_replace('~^https?://~i', '', $dominio); 
$dominio = preg_replace('~^www\.~i', '', $dominio);     
$dominio = preg_replace('~[/?#].*$~', '', $dominio);    
$dominio = strtolower(trim($dominio));
$dominio = rtrim($dominio, '.');

$tipos_validos = ['phishing', 'malware', 'spam', 'suplantacion', 'fraude', 'otro'];

// Comprobaciones de seguridad
if (empty($dominio) || !filter_var($dominio, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) || $comentario === '' || !in_array($tipo_comentario, $tipos_validos, true)) {
    volverInformeComentario($token_reporte, 'error');
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
        volverInformeComentario($token_reporte, 'ok');
    } else {
        // Falla la ejecución de la consulta
        volverInformeComentario($token_reporte, 'error');
    }
    mysqli_stmt_close($stmt);
} else {
    // Falla la preparación de la consulta
    volverInformeComentario($token_reporte, 'error');
}
exit;
?>
