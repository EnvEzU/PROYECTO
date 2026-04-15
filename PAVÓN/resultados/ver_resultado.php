<?php
// Archivo: resultados/ver_resultado.php
session_start();
require_once '../config/conexion.php';

// 1. Captura del ID: Aceptamos POST (desde el paso 6) o SESSION (si recarga la página)
if (isset($_POST['id'])) {
    $_SESSION['ver_id_reporte'] = intval($_POST['id']);
}

if (!isset($_SESSION['ver_id_reporte'])) { 
    header("Location: ../index.php"); 
    exit; 
}

$id_hist = $_SESSION['ver_id_reporte'];

// 2. Obtener datos del dominio (Sin la columna 'fecha' para evitar fallos de SQL)
$sql = "SELECT dominio, estado FROM historial_dominios WHERE id = ?";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "i", $id_hist);
mysqli_stmt_execute($stmt);
$info = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt));

if (!$info) { die("Error: No se encontró el análisis en la base de datos."); }

// 3. Cargar todos los resultados de las herramientas en un solo array
$res_tools = mysqli_query($conn, "SELECT herramienta, resultado_completo FROM osint_resultados WHERE id_historial=$id_hist");
$data = [];
while($r = mysqli_fetch_assoc($res_tools)) { 
    $data[$r['herramienta']] = $r['resultado_completo']; 
}

$ruta_base = "../";
require_once '../includes/header.php';
?>

<style>
    /* OPTIMIZACIÓN PROFESIONAL PARA PDF / IMPRESIÓN */
    @media print {
        /* Ocultar elementos web innecesarios */
        .no-print, .btn, .navbar, footer, .breadcrumb { display: none !important; }
        
        /* Expandir contenedor al máximo */
        .container { width: 100% !important; max-width: none !important; margin: 0 !important; padding: 0 !important; }
        
        /* Forzar visualización de colores y fondos en el PDF */
        body { background-color: white !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        
        /* Evitar que las tarjetas se corten entre dos páginas */
        .card { 
            page-break-inside: avoid !important; 
            border: 1px solid #333 !important; 
            margin-bottom: 20px !important; 
            box-shadow: none !important; 
        }

        .card-header { 
            background-color: #eee !important; 
            color: black !important; 
            font-weight: bold !important;
            border-bottom: 2px solid #333 !important;
        }
        
        /* IMPORTANTE: Quitar scrolls y mostrar TODO el texto */
        pre { 
            max-height: none !important; 
            overflow: visible !important; 
            white-space: pre-wrap !important; 
            font-size: 10pt !important; 
            background: #fff !important; 
            color: #000 !important;
            border: none !important;
        }
        
        .alert { border: 2px solid #000 !important; background: #fff !important; color: #000 !important; }
    }

    /* Estilo para la vista web */
    pre { 
        max-height: 400px; 
        overflow-y: auto; 
        background-color: #f8f9fa; 
        font-family: 'Courier New', Courier, monospace; 
        font-size: 0.85rem;
    }
    .card-header { font-size: 1.1rem; }
</style>

<div class="container mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4 no-print">
        <h2 class="mb-0">Auditoría OSINT: <span class="text-primary"><?= htmlspecialchars($info['dominio']) ?></span></h2>
        <a href="../index.php" class="btn btn-outline-secondary"><i class="bi bi-house"></i> Inicio</a>
    </div>

    <div class="alert <?= ($info['estado'] == 'maliciosa' ? 'alert-danger' : 'alert-success') ?> text-center shadow-sm border-2">
        <h3 class="mb-0">DICTAMEN DE SEGURIDAD: <?= strtoupper($info['estado']) ?></h3>
        <p class="mb-0">Generado el: <?= date("d/m/Y H:i") ?></p>
    </div>

    <div class="row">
        <div class="col-md-5 mb-4">
            <div class="card h-100 shadow-sm border-primary">
                <div class="card-header fw-bold"><i class="bi bi-shield-check"></i> 1. Reputación de Malware</div>
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
                    } else { echo "<div class='text-muted'>Sin datos de reputación.</div>"; }
                    ?>
                </div>
            </div>
        </div>

        <div class="col-md-7 mb-4">
            <div class="card h-100 shadow-sm border-success">
                <div class="card-header fw-bold"><i class="bi bi-geo-alt"></i> 2. Ubicación y ASN</div>
                <div class="card-body p-0">
                    <pre class="p-3 m-0"><?= htmlspecialchars($data['GeoIP'] ?? 'Sin datos de ubicación.') ?></pre>
                </div>
            </div>
        </div>
    </div>

    <div class="row">
        <div class="col-md-6 mb-4">
            <div class="card h-100 shadow-sm border-dark">
                <div class="card-header fw-bold"><i class="bi bi-person-badge"></i> 3. Registro WHOIS</div>
                <div class="card-body p-0">
                    <pre class="p-3 m-0"><?= htmlspecialchars($data['Whois'] ?? 'Sin datos de registro.') ?></pre>
                </div>
            </div>
        </div>

        <div class="col-md-6 mb-4">
            <div class="card h-100 shadow-sm border-danger">
                <div class="card-header fw-bold"><i class="bi bi-door-open"></i> 4. Escaneo de Puertos</div>
                <div class="card-body p-0">
                    <pre class="p-3 m-0"><?= htmlspecialchars($data['Puertos'] ?? 'Sin datos de puertos.') ?></pre>
                </div>
            </div>
        </div>
    </div>

    <div class="card mb-4 shadow-sm border-info">
        <div class="card-header fw-bold"><i class="bi bi-server"></i> 5. Registros DNS (DIG)</div>
        <div class="card-body p-0">
            <pre class="p-3 m-0"><?= htmlspecialchars($data['Dig'] ?? 'Sin datos DNS.') ?></pre>
        </div>
    </div>

    <div class="card mb-4 shadow-sm border-warning">
        <div class="card-header fw-bold text-dark"><i class="bi bi-diagram-3"></i> 6. Variaciones de Dominio (Typosquatting)</div>
        <div class="card-body p-0">
            <pre class="p-3 m-0"><?= htmlspecialchars($data['Dnstwist'] ?? 'Sin datos de variaciones.') ?></pre>
        </div>
    </div>

    <div class="text-center mt-4 mb-5 no-print">
        <?php if(isset($_SESSION['id_usuario'])): ?>
            <button onclick="window.print()" class="btn btn-primary btn-lg shadow px-5">
                <i class="bi bi-file-earmark-pdf"></i> Descargar informe en PDF
            </button>
        <?php else: ?>
            <div class="alert alert-warning d-inline-block shadow-sm">
                <i class="bi bi-lock"></i> Inicia sesión para descargar este informe técnico.
            </div>
        <?php endif; ?>
    </div>
</div>

<?php require_once '../includes/footer.php'; ?>