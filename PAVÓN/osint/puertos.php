<?php
// Archivo: osint/puertos.php
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
    <div class="card shadow-lg border-0 mx-auto border-danger border-top border-5" style="max-width: 600px;">
        <div class="card-body p-5">
            <h4 class="text-muted mb-3">Paso 7 de 7</h4>
            <h2 class="text-danger mb-4"><i class="bi bi-door-open"></i> Escáner de Puertos</h2>
            <p class="lead">Comprobando servicios expuestos en <span class="fw-bold"><?= $dom_puro ?></span></p>
            <div class="mt-4 mb-4">
                <div class="spinner-border text-danger" style="width: 3rem; height: 3rem;" role="status"></div>
            </div>
            <div class="progress" style="height: 25px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated bg-danger w-100 fw-bold" role="progressbar">Ejecutando TCP Connect Scan... Generando PDF final...</div>
            </div>
        </div>
    </div>
</div>

<?php require_once '../includes/footer.php'; ?>

<?php
while (ob_get_level() > 0) { ob_end_flush(); }
flush();

// ==========================================
// ESCÁNER DE PUERTOS NATIVO (TCP Connect)
// ==========================================
$ip_objetivo = gethostbyname($d['dominio']);
$puertos_comunes = [
    21 => 'FTP (Transferencia de Archivos)',
    22 => 'SSH (Consola Remota)',
    25 => 'SMTP (Envío de Correo)',
    80 => 'HTTP (Web Insegura)',
    110 => 'POP3 (Recepción de Correo)',
    443 => 'HTTPS (Web Segura)',
    3306 => 'MySQL (Base de Datos)',
    3389 => 'RDP (Escritorio Remoto Windows)'
];

$out = "=== ESCÁNER DE PUERTOS OSINT ===\n";
$out .= "Objetivo: " . $d['dominio'] . " ($ip_objetivo)\n\n";
$out .= str_pad("PUERTO", 10) . str_pad("ESTADO", 15) . "SERVICIO\n";
$out .= str_repeat("-", 55) . "\n";

foreach ($puertos_comunes as $puerto => $servicio) {
    // Usamos @ para suprimir warnings de conexión fallida. Timeout de 1 segundo por puerto.
    $conexion = @fsockopen($ip_objetivo, $puerto, $errno, $errstr, 1);
    
    if (is_resource($conexion)) {
        $out .= str_pad($puerto . "/tcp", 10) . str_pad("ABIERTO", 15) . $servicio . "\n";
        fclose($conexion);
    } else {
        $out .= str_pad($puerto . "/tcp", 10) . str_pad("cerrado/filtro", 15) . $servicio . "\n";
    }
}

$stmt = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'Puertos', ?)");
mysqli_stmt_bind_param($stmt, "is", $id, $out);
mysqli_stmt_execute($stmt);

// REDIRECCIÓN FINAL AL REPORTE
echo "<script>window.location.href = '../resultados/ver_resultado.php?id=$id';</script>";
exit;
?>