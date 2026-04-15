<?php
// Archivo: osint/dnstwist.php
session_start();
require_once '../config/conexion.php';

// Aumentamos el tiempo de ejecución pero optimizamos la tarea
set_time_limit(120);

if (!isset($_POST['id_historial'])) { die("Error ID."); }
$id = intval($_POST['id_historial']);

$q = mysqli_query($conn, "SELECT dominio FROM historial_dominios WHERE id=$id");
$d = mysqli_fetch_assoc($q);
if (!$d) { die("Dominio no encontrado."); }

$dominio = $d['dominio'];
// Medimos la longitud del nombre (sin el .com) para decidir la agresividad
$nombre_solo = explode('.', $dominio)[0];
$longitud = strlen($nombre_solo);

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="container mt-5">
    <div class="card shadow-lg border-0 border-warning border-top border-5">
        <div class="card-body p-5">
            <h4 class="text-muted mb-3">Paso 3 de 6</h4>
            <h2 class="text-warning mb-4"><i class="bi bi-cpu"></i> Motor de Typosquatting (Smart Mode)</h2>
            <p class="lead">Analizando vectores para: <strong><?= htmlspecialchars($dominio) ?></strong></p>
            
            <div id="terminal" style="background: #121212; color: #ffc107; padding: 20px; font-family: 'Consolas', monospace; border-radius: 8px; height: 400px; overflow-y: auto; font-size: 0.85rem; border: 1px solid #333; scroll-behavior: smooth;">
                <?php
                if (ob_get_level() > 0) { ob_end_flush(); }
                ob_implicit_flush(true);

                $ruta_exe = "C:/Users/Usuario/AppData/Local/Programs/Python/Python314/Scripts/dnstwist.exe";
                $dom_esc = escapeshellarg($dominio);
                
                // LÓGICA DE OPTIMIZACIÓN:
                // Si el dominio es largo (>10 caracteres), quitamos 'insertion' y 'homoglyph' que son los que más tardan.
                if ($longitud > 10) {
                    echo "<span style='color: #0dcaf0;'>[INFO] Dominio largo detectado. Aplicando escaneo optimizado para velocidad...</span><br>";
                    $fuzzers = "omission,repetition"; 
                } else {
                    $fuzzers = "omission,repetition,homoglyph,insertion";
                }

                $comando = "\"$ruta_exe\" --format list --fuzzers $fuzzers $dom_esc 2>&1";
                $proceso = popen($comando, 'r');
                
                $out_para_bd = "";
                $contador = 0;
                $limite_seguridad = 250; // No necesitamos más de 250 variantes para un TFG

                if (is_resource($proceso)) {
                    echo "<span style='color: #fff;'>[SYS] Ejecutando fuzzing inteligente...</span><br><br>";
                    
                    while (!feof($proceso) && $contador < $limite_seguridad) {
                        $linea = fgets($proceso);
                        if (!trim($linea)) continue;

                        $out_para_bd .= $linea;
                        $contador++;

                        echo "<span style='color: #888;'>[+]</span> " . htmlspecialchars($linea) . "<br>";
                        
                        // Reducimos el usleep de 5000 a 2000 (2ms) para que vuele
                        usleep(2000); 

                        if ($contador % 5 == 0) {
                            echo "<script>document.getElementById('terminal').scrollTop = document.getElementById('terminal').scrollHeight;</script>";
                        }
                        
                        flush();
                    }
                    
                    if ($contador >= $limite_seguridad) {
                        echo "<br><span style='color: #ffc107;'>[!] Límite de seguridad alcanzado para el reporte técnico.</span><br>";
                        $out_para_bd .= "\n... (Resultado truncado por longitud) ...\n";
                    }
                    
                    pclose($proceso);
                }

                $stmt = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'Dnstwist', ?)");
                mysqli_stmt_bind_param($stmt, "is", $id, $out_para_bd);
                mysqli_stmt_execute($stmt);
                ?>
                <br><span style="color: #00ff00;">[FINALIZADO] Se han generado <?= $contador ?> vectores de ataque.</span>
            </div>

            <div class="progress" style="height: 10px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated bg-warning w-100"></div>
            </div>
        </div>
    </div>
</div>

<form id="formNext" action="dig.php" method="POST">
    <input type="hidden" name="id_historial" value="<?= $id ?>">
</form>

<script>
    const term = document.getElementById('terminal');
    term.scrollTop = term.scrollHeight;
    
    // Si terminó muy rápido, damos 2 segundos. Si fue largo, saltamos casi ya.
    setTimeout(function() {
        document.getElementById('formNext').submit();
    }, <?= ($contador < 50) ? '2500' : '800' ?>);
</script>

<?php require_once '../includes/footer.php'; ?>