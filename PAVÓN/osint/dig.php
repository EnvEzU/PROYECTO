<?php
// Archivo: osint/dig.php
session_start();
require_once '../config/conexion.php';

set_time_limit(60);

// 1. Validar ID por POST
if (!isset($_POST['id_historial'])) { 
    die("Error: No se recibió el ID."); 
}
$id = intval($_POST['id_historial']);

// 2. Obtener dominio con consulta preparada
$stmt_check = mysqli_prepare($conn, "SELECT dominio FROM historial_dominios WHERE id = ?");
mysqli_stmt_bind_param($stmt_check, "i", $id);
mysqli_stmt_execute($stmt_check);
$res_check = mysqli_stmt_get_result($stmt_check);
$d = mysqli_fetch_assoc($res_check);

if (!$d) { die("Dominio no encontrado."); }
$dom_puro = htmlspecialchars($d['dominio']);

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="container mt-5">
    <div class="card shadow-lg border-0 mx-auto border-info border-top border-5">
        <div class="card-body p-5">
            <h4 class="text-muted mb-3">Paso 4 de 6</h4>
            <h2 class="text-info mb-4"><i class="bi bi-server"></i> DNS Resolver (DiG Mode)</h2>
            <p class="lead">Consultando topología de red para: <span class="fw-bold"><?= $dom_puro ?></span></p>
            
            <div id="terminal" style="background: #001b2e; color: #0dcaf0; padding: 20px; font-family: 'Consolas', monospace; border-radius: 8px; height: 380px; overflow-y: auto; box-shadow: inset 0 0 15px #000; font-size: 0.85rem; border: 1px solid #084298; scroll-behavior: smooth;">
                <?php
                // Preparamos el volcado de buffer inmediato
                if (ob_get_level() > 0) { ob_end_flush(); }
                ob_implicit_flush(true);

                $dominio = $d['dominio'];
                $out_header = "; <<>> OSINT PHP DiG Emulator <<>> $dominio ANY\n;; ANSWER SECTION:\n\n";
                echo nl2br(htmlspecialchars($out_header));
                flush();

                // UNA SOLA CONSULTA para todos los registros (Mucho más rápido)
                $registros = dns_get_record($dominio, DNS_ALL);
                $full_output = $out_header;
                $contador = 0;

                if ($registros) {
                    // Ordenamos por tipo para que el reporte quede limpio
                    usort($registros, function($a, $b) { return strcmp($a['type'], $b['type']); });

                    foreach ($registros as $r) {
                        $host = $r['host'] . ".";
                        $ttl = $r['ttl'] ?? 3600;
                        $type = $r['type'];
                        
                        // Lógica de extracción de datos según el tipo
                        $data = $r['ip'] ?? $r['target'] ?? $r['txt'] ?? $r['ipv6'] ?? '';
                        if ($type == 'MX') $data = $r['pri'] . ' ' . $r['target'] . ".";
                        if ($type == 'SOA') $data = $r['mname'] . ". " . $r['rname'] . ". " . $r['serial'];

                        $linea = str_pad($host, 25) . "\t" . $ttl . "\tIN\t" . str_pad($type, 5) . "\t" . $data . "\n";
                        
                        // Efecto visual: imprimimos y esperamos apenas 5ms
                        echo htmlspecialchars($linea) . "<br>";
                        $full_output .= $linea;
                        $contador++;

                        // Scroll cada 2 registros para no saturar el navegador
                        if ($contador % 2 == 0) {
                            echo "<script>document.getElementById('terminal').scrollTop = document.getElementById('terminal').scrollHeight;</script>";
                        }

                        usleep(5000); // 5 milisegundos (Casi instantáneo pero visible)
                        flush();
                    }
                } else {
                    $msg_error = ";; No se encontraron registros públicos.\n";
                    echo $msg_error;
                    $full_output .= $msg_error;
                }

                $footer = "\n;; Query time: " . rand(5, 30) . " msec\n;; WHEN: " . date("D M d H:i:s T Y") . "\n";
                echo nl2br(htmlspecialchars($footer));
                $full_output .= $footer;

                // 3. GUARDAR RESULTADO
                $stmt = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'Dig', ?)");
                mysqli_stmt_bind_param($stmt, "is", $id, $full_output);
                mysqli_stmt_execute($stmt);
                ?>
                <br><span style="color: #00ff00;">[OK] Se han resuelto <?= $contador ?> registros con éxito.</span>
            </div>
        </div>
    </div>
</div>

<form id="autoPost" action="geoip.php" method="POST">
    <input type="hidden" name="id_historial" value="<?= $id ?>">
</form>

<script>
    // Pausa de cortesía de 1 segundo para leer el final antes de saltar
    setTimeout(function() {
        document.getElementById('autoPost').submit();
    }, 1000);
</script>

<?php require_once '../includes/footer.php'; ?>