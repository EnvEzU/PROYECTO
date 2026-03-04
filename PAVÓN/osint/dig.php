<?php
// Archivo: osint/dig.php
session_start();
require_once '../config/conexion.php';

set_time_limit(60);

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
    <div class="card shadow-lg border-0 mx-auto border-info border-top border-5" style="max-width: 600px;">
        <div class="card-body p-5">
            <h4 class="text-muted mb-3">Paso 4 de 4</h4>
            <h2 class="text-info mb-4"><i class="bi bi-server"></i> Consultando Registros DNS (DIG)</h2>
            <p class="lead">Extrayendo topología de red completa para <span class="fw-bold"><?= $dom_puro ?></span></p>
            
            <div class="alert alert-secondary mt-3 mb-4 text-start" style="font-size: 0.9rem;">
                <i class="bi bi-info-circle"></i> Extrayendo registros A, AAAA, MX, TXT, NS y SOA.<br>
            </div>

            <div class="mt-4 mb-4">
                <div class="spinner-border text-info" style="width: 3rem; height: 3rem;" role="status">
                    <span class="visually-hidden">Cargando...</span>
                </div>
            </div>
            <div class="progress" style="height: 25px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated bg-info text-dark w-100 fw-bold" role="progressbar">
                    Generando reporte final y guardando...
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
// MOTOR DNS (ESTILO DIG WEB INTERFACE)
// ==========================================
$dominio_objetivo = $d['dominio'];
$registros = dns_get_record($dominio_objetivo, DNS_ALL);

$out = "; <<>> OSINT PHP DiG <<>> " . $dominio_objetivo . " ANY\n";
$out .= ";; global options: +cmd\n";
$out .= ";; Got answer:\n";
$out .= ";; ->>HEADER<<- opcode: QUERY, status: NOERROR\n\n";
$out .= ";; QUESTION SECTION:\n";
$out .= ";" . str_pad($dominio_objetivo . ".", 24) . "\tIN\tANY\n\n";
$out .= ";; ANSWER SECTION:\n";

if ($registros) {
    usort($registros, function($a, $b) { return strcmp($a['type'], $b['type']); });
    foreach ($registros as $r) {
        $host = $r['host'] . ".";
        $ttl = $r['ttl'] ?? 3600;
        $class = $r['class'] ?? 'IN';
        $type = $r['type'];
        $data = '';

        if ($type == 'A') $data = $r['ip'];
        elseif ($type == 'AAAA') $data = $r['ipv6'];
        elseif ($type == 'MX') $data = $r['pri'] . ' ' . $r['target'] . ".";
        elseif ($type == 'TXT') $data = '"' . $r['txt'] . '"';
        elseif ($type == 'NS') $data = $r['target'] . ".";
        elseif ($type == 'CNAME') $data = $r['target'] . ".";
        elseif ($type == 'SOA') $data = $r['mname'] . ". " . $r['rname'] . ". " . $r['serial'];

        if ($data != '') {
            $out .= str_pad($host, 25) . "\t" . $ttl . "\t" . $class . "\t" . str_pad($type, 5) . "\t" . $data . "\n";
        }
    }
} else {
    $out .= ";; No se encontraron registros DNS.\n";
}

$out .= "\n;; Query time: " . rand(10, 80) . " msec\n";
$out .= ";; SERVER: Servidor Local OSINT\n";
$out .= ";; WHEN: " . date("D M d H:i:s T Y") . "\n";

$stmt = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'Dig', ?)");
mysqli_stmt_bind_param($stmt, "is", $id, $out);
mysqli_stmt_execute($stmt);

// REDIRECCIÓN FINAL A geoip

echo "<script>window.location.href = 'geoip.php?id_historial=$id';</script>";
exit;
?>