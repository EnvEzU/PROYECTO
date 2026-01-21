<?php
// ==========================================
// 1. LÓGICA PHP (RECUPERAR DATOS)
// ==========================================
session_start();
require_once '../config/conexion.php';

// Seguridad
if (!isset($_SESSION['id_usuario'])) { header("Location: ../auth/login.php"); exit; }
if (!isset($_GET['id'])) { header("Location: historial.php"); exit; }

$id_historial = intval($_GET['id']);
$id_usuario = $_SESSION['id_usuario'];

// 1. Obtener info principal del dominio
$sql_info = "SELECT * FROM historial_dominios WHERE id = ? AND id_usuario = ?";
$stmt = mysqli_prepare($conn, $sql_info);
mysqli_stmt_bind_param($stmt, "ii", $id_historial, $id_usuario);
mysqli_stmt_execute($stmt);
$res_info = mysqli_stmt_get_result($stmt);
$info_dominio = mysqli_fetch_assoc($res_info);

if (!$info_dominio) { die("Análisis no encontrado o acceso denegado."); }

// 2. Obtener resultados de las herramientas (VirusTotal, Whois, etc.)
$sql_tools = "SELECT * FROM osint_resultados WHERE id_historial = ?";
$stmt2 = mysqli_prepare($conn, $sql_tools);
mysqli_stmt_bind_param($stmt2, "i", $id_historial);
mysqli_stmt_execute($stmt2);
$res_tools = mysqli_stmt_get_result($stmt2);

$resultados = [];
while ($row = mysqli_fetch_assoc($res_tools)) {
    $resultados[$row['herramienta']] = $row['resultado_completo'];
}

// Configurar ruta base
$ruta_base = "../";
?>

<?php require_once '../includes/header.php'; ?>

<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="bi bi-file-earmark-medical"></i> Reporte de Análisis</h2>
    <a href="historial.php" class="btn btn-outline-secondary"><i class="bi bi-arrow-left"></i> Volver</a>
</div>

<div class="card mb-4 shadow-sm border-start border-5 
    <?= ($info_dominio['estado'] == 'maliciosa') ? 'border-danger' : (($info_dominio['estado'] == 'segura') ? 'border-success' : 'border-warning') ?>">
    <div class="card-body">
        <div class="row align-items-center">
            <div class="col-md-8">
                <h1 class="display-6"><?= htmlspecialchars($info_dominio['dominio']) ?></h1>
                <p class="text-muted mb-0">Escaneado el: <?= $info_dominio['fecha_escaneo'] ?></p>
            </div>
            <div class="col-md-4 text-end">
                <?php if ($info_dominio['estado'] == 'maliciosa'): ?>
                    <span class="badge bg-danger fs-5">MALICIOSO</span>
                <?php elseif ($info_dominio['estado'] == 'segura'): ?>
                    <span class="badge bg-success fs-5">SEGURO</span>
                <?php else: ?>
                    <span class="badge bg-warning text-dark fs-5">SOSPECHOSO</span>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-lg-6">
        <div class="card mb-4 h-100">
            <div class="card-header bg-primary text-white">
                <i class="bi bi-virus"></i> Resultados VirusTotal
            </div>
            <div class="card-body">
                <?php if (isset($resultados['VirusTotal'])): 
                    $vt_data = json_decode($resultados['VirusTotal'], true);
                ?>
                    <?php if (isset($vt_data['data']['attributes']['last_analysis_stats'])): ?>
                        <?php $stats = $vt_data['data']['attributes']['last_analysis_stats']; ?>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item d-flex justify-content-between align-items-center list-group-item-danger">
                                Maliciosos detectados <span class="badge bg-danger rounded-pill"><?= $stats['malicious'] ?></span>
                            </li>
                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                Sospechosos <span class="badge bg-warning text-dark rounded-pill"><?= $stats['suspicious'] ?></span>
                            </li>
                            <li class="list-group-item d-flex justify-content-between align-items-center list-group-item-success">
                                Inofensivos <span class="badge bg-success rounded-pill"><?= $stats['harmless'] ?></span>
                            </li>
                        </ul>
                        <div class="mt-3">
                            <small class="text-muted">ID Análisis: <?= $vt_data['data']['id'] ?? 'N/A' ?></small>
                        </div>
                    <?php else: ?>
                        <pre class="bg-light p-3 border rounded"><?= htmlspecialchars(substr($resultados['VirusTotal'], 0, 500)) ?>...</pre>
                    <?php endif; ?>
                <?php else: ?>
                    <p class="text-muted">No hay datos de VirusTotal.</p>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div class="col-lg-6">
        <div class="card mb-4 h-100">
            <div class="card-header bg-dark text-white">
                <i class="bi bi-card-text"></i> Información WHOIS
            </div>
            <div class="card-body p-0">
                <?php if (isset($resultados['Whois'])): ?>
                    <pre class="m-0 p-3 bg-light text-secondary" style="max-height: 400px; overflow-y: auto; font-size: 0.85rem;"><?= htmlspecialchars($resultados['Whois']) ?></pre>
                <?php else: ?>
                    <p class="p-3 text-muted">No hay datos de WHOIS.</p>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>

<div class="text-center mt-4">
    <button onclick="window.print()" class="btn btn-secondary btn-lg"><i class="bi bi-printer"></i> Descargar Informe PDF</button>
</div>

<?php require_once '../includes/footer.php'; ?>