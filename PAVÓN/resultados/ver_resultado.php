<?php
// Archivo: resultados/ver_resultado.php
session_start();
require_once '../config/conexion.php';

// Manejo de ID por sesión para limpiar la URL
if (isset($_GET['id'])) {
    $_SESSION['ver_id_reporte'] = intval($_GET['id']);
    header("Location: ver_resultado.php");
    exit;
}

if (!isset($_SESSION['ver_id_reporte'])) { 
    header("Location: ../index.php"); 
    exit; 
}

$id_hist = $_SESSION['ver_id_reporte'];

// 1. Obtener datos del dominio
$sql = "SELECT * FROM historial_dominios WHERE id = ?";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "i", $id_hist);
mysqli_stmt_execute($stmt);
$info = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt));

if (!$info) { die("Error: Análisis no encontrado."); }

// 2. Obtener resultados de herramientas
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
        <a href="../index.php" class="btn btn-outline-secondary">Inicio</a>
    </div>

    <div class="alert <?= ($info['estado'] == 'maliciosa' ? 'alert-danger' : 'alert-success') ?> text-center shadow-sm">
        <h3 class="mb-0">ESTADO FINAL: <?= strtoupper($info['estado']) ?></h3>
    </div>

    <div class="row mb-4">
        <div class="col-md-5 mb-3">
            <div class="card h-100 shadow-sm border-primary">
                <div class="card-header bg-primary text-white fw-bold"><i class="bi bi-shield-check"></i> Análisis VirusTotal</div>
                <div class="card-body">
                    <?php 
                    $vt = json_decode($data['VirusTotal'] ?? '{}', true);
                    if (is_array($vt) && isset($vt['data']['attributes']['last_analysis_stats'])) {
                        $s = $vt['data']['attributes']['last_analysis_stats'];
                        echo "<ul class='list-group list-group-flush'>";
                        echo "<li class='list-group-item d-flex justify-content-between'>Maliciosos <span class='badge bg-danger rounded-pill'>{$s['malicious']}</span></li>";
                        echo "<li class='list-group-item d-flex justify-content-between'>Inofensivos <span class='badge bg-success rounded-pill'>{$s['harmless']}</span></li>";
                        echo "<li class='list-group-item d-flex justify-content-between'>Sospechosos <span class='badge bg-warning text-dark rounded-pill'>{$s['suspicious']}</span></li>";
                        echo "</ul>";
                    } else { 
                        echo "<div class='text-muted p-3'>No hay datos de VirusTotal.</div>"; 
                    }
                    ?>
                </div>
            </div>
        </div>

        <div class="col-md-7 mb-3">
            <div class="card h-100 shadow-sm border-success">
                <div class="card-header bg-success text-white fw-bold"><i class="bi bi-geo-alt"></i> Ubicación del Servidor (GeoIP)</div>
                <div class="card-body p-0">
                    <pre class="p-3 bg-light m-0" style="max-height: 250px; overflow-y: auto; font-size: 0.85rem;"><?= htmlspecialchars($data['GeoIP'] ?? 'Sin datos de ubicación.') ?></pre>
                </div>
            </div>
        </div>
    </div>

    <div class="row mb-4">
        <div class="col-md-6 mb-3">
            <div class="card h-100 shadow-sm border-dark">
                <div class="card-header bg-dark text-white fw-bold"><i class="bi bi-person-badge"></i> Registro WHOIS</div>
                <div class="card-body p-0">
                    <pre class="p-3 bg-light m-0" style="max-height: 350px; overflow-y: auto; font-size: 0.8rem;"><?= htmlspecialchars($data['Whois'] ?? 'Sin datos.') ?></pre>
                </div>
            </div>
        </div>

        <div class="col-md-6 mb-3">
            <div class="card h-100 shadow-sm border-danger">
                <div class="card-header bg-danger text-white fw-bold"><i class="bi bi-door-open"></i> Escáner de Puertos TCP</div>
                <div class="card-body p-0">
                    <pre class="p-3 bg-light m-0" style="max-height: 350px; overflow-y: auto; font-size: 0.85rem;"><?= htmlspecialchars($data['Puertos'] ?? 'No se realizó escaneo de puertos.') ?></pre>
                </div>
            </div>
        </div>
    </div>

    <div class="row mb-4">
        <div class="col-12 mb-3">
            <div class="card shadow-sm border-info">
                <div class="card-header bg-info text-dark fw-bold"><i class="bi bi-server"></i> Registros DNS (DIG)</div>
                <div class="card-body p-0">
                    <pre class="p-3 bg-light m-0" style="max-height: 300px; overflow-y: auto; font-size: 0.85rem;"><?= htmlspecialchars($data['Dig'] ?? 'No hay datos DNS.') ?></pre>
                </div>
            </div>
        </div>

        <div class="col-12 mb-3">
            <div class="card shadow-sm border-secondary">
                <div class="card-header bg-secondary text-white fw-bold"><i class="bi bi-diagram-2"></i> Subdominios Detectados (CRT.SH)</div>
                <div class="card-body p-0">
                    <pre class="p-3 bg-light m-0" style="max-height: 300px; overflow-y: auto; font-size: 0.85rem;"><?= htmlspecialchars($data['Subdominios'] ?? 'No se detectaron subdominios.') ?></pre>
                </div>
            </div>
        </div>

        <div class="col-12 mb-3">
            <div class="card shadow-sm border-warning">
                <div class="card-header bg-warning text-dark fw-bold"><i class="bi bi-diagram-3"></i> Posibles Variaciones (Typosquatting)</div>
                <div class="card-body p-0">
                    <pre class="p-3 bg-light m-0" style="max-height: 300px; overflow-y: auto; font-size: 0.8rem;"><?= htmlspecialchars($data['Dnstwist'] ?? 'No hay datos de variaciones.') ?></pre>
                </div>
            </div>
        </div>
    </div>

    <div class="text-center mt-4 mb-5">
        <?php if(isset($_SESSION['id_usuario'])): ?>
            <button onclick="window.print()" class="btn btn-success shadow">
                <i class="bi bi-printer"></i> Imprimir Reporte Completo
            </button>
        <?php else: ?>
            <div class="alert alert-warning d-inline-block">
                Modo invitado: <a href="../auth/login.php" class="alert-link">Inicia sesión</a> para descargar el reporte en PDF.
            </div>
        <?php endif; ?>
    </div>
</div>

<?php require_once '../includes/footer.php'; ?>