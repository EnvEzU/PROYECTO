<?php
// Archivo: resultados/ver_resultado.php
session_start();
require_once '../config/conexion.php';

if (!isset($_GET['id'])) { header("Location: ../index.php"); exit; }
$id_hist = intval($_GET['id']);

// Recuperar datos (Público: No filtramos por usuario)
$sql = "SELECT * FROM historial_dominios WHERE id = ?";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "i", $id_hist);
mysqli_stmt_execute($stmt);
$info = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt));

if (!$info) die("Análisis no encontrado.");

// Herramientas
$res_tools = mysqli_query($conn, "SELECT * FROM osint_resultados WHERE id_historial=$id_hist");
$data = [];
while($r = mysqli_fetch_assoc($res_tools)) { $data[$r['herramienta']] = $r['resultado_completo']; }

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="d-flex justify-content-between align-items-center mb-4">
    <h2>Reporte: <?= htmlspecialchars($info['dominio']) ?></h2>
    <a href="../index.php" class="btn btn-outline-secondary">Inicio</a>
</div>

<div class="alert <?= ($info['estado']=='maliciosa'?'alert-danger':'alert-success') ?> text-center">
    <h3>ESTADO: <?= strtoupper($info['estado']) ?></h3>
</div>

<div class="row">
    <div class="col-md-6">
        <div class="card h-100 mb-3">
            <div class="card-header bg-primary text-white">VirusTotal</div>
            <div class="card-body">
                <?php 
                $vt = json_decode($data['VirusTotal'] ?? '{}', true);
                if(isset($vt['data']['attributes']['last_analysis_stats'])) {
                    $s = $vt['data']['attributes']['last_analysis_stats'];
                    echo "<p class='text-danger'>Maliciosos: {$s['malicious']}</p>";
                    echo "<p class='text-success'>Limpios: {$s['harmless']}</p>";
                } else { echo "Sin datos estructurados."; }
                ?>
            </div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card h-100 mb-3">
            <div class="card-header bg-dark text-white">WHOIS</div>
            <div class="card-body p-0">
                <pre class="p-3 bg-light" style="max-height: 200px; overflow: auto;"><?= htmlspecialchars($data['Whois'] ?? '') ?></pre>
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
            <br>Para <strong>descargar el informe</strong> debes <a href="../auth/login.php">iniciar sesión</a>.
        </div>
    <?php endif; ?>
</div>

<?php require_once '../includes/footer.php'; ?>