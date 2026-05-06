<?php
session_start();
require_once '../config/conexion.php';

if (!isset($_SESSION['id_usuario'])) {
    header("Location: ../auth/login.php");
    exit;
}

function normalizarDominio(string $entrada): string|false
{
    $dominio = trim($entrada);

    if ($dominio === '') {
        return false;
    }

    $dominio = preg_replace('#^https?://#i', '', $dominio);
    $dominio = preg_replace('#^www\.#i', '', $dominio);
    $dominio = preg_replace('#[/?#].*$#', '', $dominio);
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

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    header("Location: ../index.php");
    exit;
}

$id_usuario      = (int)$_SESSION['id_usuario'];
$autor_nombre    = trim($_SESSION['usuario'] ?? 'Usuario');
$dominio_entrada = $_POST['dominio'] ?? '';
$comentario      = trim($_POST['comentario'] ?? '');
$tipo_comentario = trim($_POST['tipo_comentario'] ?? 'otro');
$id_historial    = isset($_POST['id_historial']) ? (int)$_POST['id_historial'] : 0;

$dominio = normalizarDominio($dominio_entrada);

$tipos_validos = ['phishing', 'malware', 'spam', 'suplantacion', 'fraude', 'otro'];

if ($dominio === false || $comentario === '' || !in_array($tipo_comentario, $tipos_validos, true)) {
    if ($id_historial > 0) {
        header("Location: ver_resultado.php?id=" . $id_historial . "&comentario=error");
    } else {
        header("Location: ../index.php");
    }
    exit;
}

if (mb_strlen($comentario) > 1000) {
    $comentario = mb_substr($comentario, 0, 1000);
}

$sql = "INSERT INTO comentarios_dominios (dominio, id_usuario, autor_nombre, comentario, tipo_comentario, estado)
        VALUES (?, ?, ?, ?, ?, 'aprobado')";

if ($stmt = mysqli_prepare($conn, $sql)) {
    mysqli_stmt_bind_param($stmt, "sisss", $dominio, $id_usuario, $autor_nombre, $comentario, $tipo_comentario);
    $ok = mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);

    if ($id_historial > 0) {
        if ($ok) {
            header("Location: ver_resultado.php?id=" . $id_historial . "&comentario=ok");
        } else {
            header("Location: ver_resultado.php?id=" . $id_historial . "&comentario=error");
        }
        exit;
    }
}

header("Location: ../index.php");
exit;