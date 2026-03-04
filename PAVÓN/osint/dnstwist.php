<?php
// Archivo: osint/dnstwist.php
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
    <div class="card shadow-lg border-0 mx-auto border-warning border-top border-5" style="max-width: 600px;">
        <div class="card-body p-5">
            <h4 class="text-muted mb-3">Paso 3 de 4</h4>
            <h2 class="text-warning mb-4" style="color: #d39e00 !important;"><i class="bi bi-diagram-3"></i> Typosquatting Engine</h2>
            <p class="lead">Generando vectores de ataque para <span class="fw-bold"><?= $dom_puro ?></span></p>
            
            <div class="alert alert-secondary mt-3 mb-4 text-start" style="font-size: 0.9rem;">
                <i class="bi bi-info-circle"></i> Ejecutando motor Python en modo "Safe Format".<br>
                <i class="bi bi-info-circle"></i> Escribiendo buffer en disco para evitar bloqueos de Windows.<br>
            </div>

            <div class="mt-4 mb-4">
                <div class="spinner-border text-warning" style="width: 3rem; height: 3rem; color: #d39e00 !important;" role="status">
                    <span class="visually-hidden">Cargando...</span>
                </div>
            </div>
            <div class="progress" style="height: 25px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated bg-warning text-dark w-100 fw-bold" role="progressbar">
                    Procesando texto plano de forma segura...
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
// EJECUTAR PYTHON (MODO ANTI-BLOQUEOS WINDOWS)
// ==========================================
$dom = escapeshellarg($d['dominio']); 
$ruta_dnstwist = "C:/Users/Usuario/AppData/Local/Programs/Python/Python314/Scripts/dnstwist.exe";

// 1. Creamos una ruta para un archivo temporal de texto
$archivo_temp = sys_get_temp_dir() . '/dnstwist_out_' . $id . '.txt';

// 2. Usamos '--format list' para quitar colores y redirigimos la salida al .txt ( > archivo )
$comando = "$ruta_dnstwist --format list --fuzzers omission,repetition,homoglyph,insertion $dom > \"$archivo_temp\" 2>&1";

// 3. Ejecutamos (ahora shell_exec terminará inmediatamente al guardar el archivo)
shell_exec($comando);

// 4. Leemos el archivo temporal de forma segura
if (file_exists($archivo_temp)) {
    $out = file_get_contents($archivo_temp);
    unlink($archivo_temp); // Borramos el archivo temporal para no dejar basura en el disco duro
} else {
    $out = "";
}

// 5. Validamos si funcionó
if (empty(trim($out)) || strpos(strtolower($out), 'not recognized') !== false || strpos(strtolower($out), 'no se reconoce') !== false) {
    $out = "ADVERTENCIA: No se pudo ejecutar 'dnstwist'.\nRuta intentada: $ruta_dnstwist\nVerifica que está instalado.";
} else {
    // Añadimos una cabecera para que el resultado en texto plano quede bonito en el PDF
    $out = "=== Vectores de Ataque Generados ===\n\n" . $out;
}

$stmt = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'Dnstwist', ?)");
mysqli_stmt_bind_param($stmt, "is", $id, $out);
mysqli_stmt_execute($stmt);

// IR AL PASO 4 (DIG) INSTANTÁNEAMENTE
echo "<script>window.location.href = 'dig.php?id_historial=$id';</script>";
exit;
?>