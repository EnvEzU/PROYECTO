<?php
// Archivo: osint/subdominios.php
session_start();
require_once '../config/conexion.php';

set_time_limit(120);

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
    <div class="card shadow-lg border-0 mx-auto border-secondary border-top border-5" style="max-width: 600px;">
        <div class="card-body p-5">
            <h4 class="text-muted mb-3">Paso 6 de 7</h4>
            <h2 class="text-secondary mb-4"><i class="bi bi-diagram-2"></i> Enumeración de Subdominios</h2>
            <p class="lead">Consultando registros SSL para <span class="fw-bold"><?= $dom_puro ?></span></p>
            <div class="mt-4 mb-4">
                <div class="spinner-border text-secondary" style="width: 3rem; height: 3rem;" role="status"></div>
            </div>
            <div class="progress" style="height: 25px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated bg-secondary w-100" role="progressbar">Buscando infraestructura oculta...</div>
            </div>
        </div>
    </div>
</div>

<?php require_once '../includes/footer.php'; ?>

<?php
while (ob_get_level() > 0) { ob_end_flush(); }
flush();

// MOTOR SUBDOMINIOS CON CURL (CRT.SH)
$dominio_limpio = preg_replace('/^www\./', '', $d['dominio']);
$url = "https://crt.sh/?q=" . urlencode('%.' . $dominio_limpio) . "&output=json";

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 50); 
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)');

$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

$out = "=== SUBDOMINIOS DESCUBIERTOS (Certificate Transparency) ===\n\n";

if ($http_code == 200 && $response) {
    $json = json_decode($response, true);
    if (is_array($json) && !empty($json)) {
        $subdominios = [];
        foreach ($json as $cert) {
            $nombres = explode("\n", $cert['name_value']);
            foreach ($nombres as $nombre) {
                $nombre = strtolower(trim($nombre));
                if (strpos($nombre, '*') === false && strpos($nombre, $dominio_limpio) !== false) {
                    $subdominios[] = $nombre;
                }
            }
        }
        $subdominios_unicos = array_unique($subdominios);
        sort($subdominios_unicos);
        
        foreach ($subdominios_unicos as $sub) {
            $out .= " - " . $sub . "\n";
        }
    } else {
        $out .= "No se encontraron subdominios públicos indexados.";
    }
} else {
    $out .= "Error: El servicio crt.sh no respondió (Código: $http_code).";
}

$stmt = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'Subdominios', ?)");
mysqli_stmt_bind_param($stmt, "is", $id, $out);
mysqli_stmt_execute($stmt);

echo "<script>window.location.href = 'puertos.php?id_historial=$id';</script>";
exit;
?>