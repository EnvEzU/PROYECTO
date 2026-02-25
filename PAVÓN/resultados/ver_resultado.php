<?php
// ==========================================
// 1. LÓGICA DE DATOS (PHP)
// ==========================================
session_start();
require_once '../config/conexion.php';

/**
 * TRUCO PARA OCULTAR EL ID DE LA URL:
 * Si llega por GET (?id=5), lo guardamos en sesión y recargamos la página limpia.
 */
if (isset($_GET['id'])) {
    $_SESSION['ver_id_reporte'] = intval($_GET['id']);
    header("Location: ver_resultado.php"); // Recarga a la misma página sin el ?id=...
    exit;
}

// Si no hay ID en la sesión, el usuario entró directamente: mandamos al inicio
if (!isset($_SESSION['ver_id_reporte'])) { 
    header("Location: ../index.php"); 
    exit; 
}

$id_hist = $_SESSION['ver_id_reporte'];

// 1. Obtener datos del dominio del historial
$sql = "SELECT * FROM historial_dominios WHERE id = ?";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "i", $id_hist);
mysqli_stmt_execute($stmt);
$info = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt));

if (!$info) {
    die("Error: Análisis no encontrado.");
}

// 2. Obtener resultados de las herramientas (VirusTotal, Whois)
$res_tools = mysqli_query($conn, "SELECT * FROM osint_resultados WHERE id_historial=$id_hist");
$data = [];
while($r = mysqli_fetch_assoc($res_tools)) { 
    $data[$r['herramienta']] = $r['resultado_completo']; 
}

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="container mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2>Reporte: <span class="text-primary"><?= htmlspecialchars($info['dominio']) ?></span></h2>
        <a href="../index.php" class="btn btn-outline-secondary shadow-sm">Inicio</a>
    </div>

    <div class="alert <?= ($info['estado'] == 'maliciosa' ? 'alert-danger' : 'alert-success') ?> text-center shadow-sm">
        <h3 class="mb-0">ESTADO: <?= strtoupper($info['estado']) ?></h3>
    </div>

    <div class="row">
        <div class="col-md-6 mb-3">
            <div class="card h-100 shadow-sm">
                <div class="card-header bg-primary text-white font-weight-bold">VirusTotal</div>
                <div class="card-body">
                    <?php 
                    $vt = json_decode($data['VirusTotal'] ?? '{}', true);
                    if(isset($vt['data']['attributes']['last_analysis_stats'])) {
                        $s = $vt['data']['attributes']['last_analysis_stats'];
                        echo "<p class='text-danger mb-1'><strong>Maliciosos:</strong> {$s['malicious']}</p>";
                        echo "<p class='text-success mb-0'><strong>Limpios:</strong> {$s['harmless']}</p>";
                    } else { 
                        echo "<span class='text-muted italic'>Sin datos estructurados.</span>"; 
                    }
                    ?>
                </div>
            </div>
        </div>

        <div class="col-md-6 mb-3">
            <div class="card h-100 shadow-sm">
                <div class="card-header bg-dark text-white font-weight-bold">WHOIS</div>
                <div class="card-body p-0">
                    <pre class="p-3 bg-light m-0" style="max-height: 200px; overflow-y: auto; font-size: 0.85rem; border-radius: 0;"><?= htmlspecialchars($data['Whois'] ?? 'Sin datos disponibles.') ?></pre>
                </div>
            </div>
        </div>
    </div>

    <div class="text-center mt-5 mb-5">
        <?php if(isset($_SESSION['id_usuario'])): ?>
            <button onclick="window.print()" class="btn btn-success btn-lg shadow">
                <i class="bi bi-download"></i> Descargar PDF
            </button>
        <?php else: ?>
            <div class="alert alert-warning d-inline-block shadow-sm">
                <i class="bi bi-lock-fill"></i> Estás en modo invitado. 
                <br>Para <strong>descargar el informe</strong> debes <a href="../auth/login.php" class="alert-link">iniciar sesión</a>.
            </div>
        <?php endif; ?>
    </div>
</div>

<?php require_once '../includes/footer.php'; ?>