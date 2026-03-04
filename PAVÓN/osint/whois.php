<?php
// Archivo: osint/whois.php
session_start();
require_once '../config/conexion.php';

if (!isset($_GET['id_historial'])) { die("Error ID."); }
$id = intval($_GET['id_historial']);

$q = mysqli_query($conn, "SELECT dominio FROM historial_dominios WHERE id=$id");
$d = mysqli_fetch_assoc($q);

if (!$d) { die("Dominio no encontrado en la BD."); }
$dom_puro = htmlspecialchars($d['dominio']);

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="container text-center mt-5 mb-5">
    <div class="card shadow-lg border-0 mx-auto border-dark border-top border-5" style="max-width: 600px;">
        <div class="card-body p-5">
            <h4 class="text-muted mb-3">Paso 2 de 4</h4>
            <h2 class="text-dark mb-4"><i class="bi bi-card-text"></i> Extrayendo datos WHOIS</h2>
            <p class="lead">Buscando información de registro para <span class="fw-bold"><?= $dom_puro ?></span></p>
            
            <div class="mt-4 mb-4">
                <div class="spinner-border text-dark" style="width: 3rem; height: 3rem;" role="status">
                    <span class="visually-hidden">Cargando...</span>
                </div>
            </div>
            <div class="progress" style="height: 25px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated bg-dark w-100 fw-bold" role="progressbar">
                    Ejecutando comandos del sistema...
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
// EJECUTAR WHOIS (CORRECCIÓN PARA SUBDOMINIOS)
// ==========================================

// 1. Extraer el dominio principal (WHOIS falla con subdominios)
$partes_dominio = explode('.', $d['dominio']);
$total_partes = count($partes_dominio);

if ($total_partes > 2) {
    // Si es un subdominio (ej: tesla.iesluisvelez.org), cogemos solo "iesluisvelez.org"
    $dominio_raiz = $partes_dominio[$total_partes - 2] . '.' . $partes_dominio[$total_partes - 1];
} else {
    // Si ya es un dominio principal, lo dejamos igual
    $dominio_raiz = $d['dominio'];
}

$dom = escapeshellarg($dominio_raiz); 

// 2. Ejecutar la herramienta
$out = shell_exec("whois $dom 2>&1");

// 3. Limpiar la salida (Quitar el Copyright feo de Windows Sysinternals para el TFG)
$out = preg_replace('/^Whois v.*?\nCopyright.*?\nSysinternals.*?\n\n/s', '', $out);

if (empty($out) || strpos(strtolower($out), 'error') !== false && strlen($out) < 150) {
    $out = "Error de conexión o datos privados.\nEl servidor WHOIS no respondió adecuadamente para el dominio raíz ($dominio_raiz).\n\n" . $out;
}

$stmt = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'Whois', ?)");
mysqli_stmt_bind_param($stmt, "is", $id, $out);
mysqli_stmt_execute($stmt);

// IR AL PASO 3 (DNSTWIST)
echo "<script>window.location.href = 'dnstwist.php?id_historial=$id';</script>";
exit;
?>