<?php
// Archivo: osint/whois.php
session_start();
require_once '../config/conexion.php';

// Aumentamos el tiempo de espera por si el servidor WHOIS externo está lento
set_time_limit(60);

// 1. Validar ID por POST
if (!isset($_POST['id_historial'])) { die("Error: Acceso no autorizado."); }
$id = intval($_POST['id_historial']);

// 2. Obtener dominio
$q = mysqli_query($conn, "SELECT dominio FROM historial_dominios WHERE id=$id");
$d = mysqli_fetch_assoc($q);
if (!$d) { die("Dominio no encontrado."); }

$dominio_original = $d['dominio'];

// Limpieza para el root domain
$partes = explode('.', $dominio_original);
$count = count($partes);
$dominio_raiz = ($count > 2) ? $partes[$count-2].'.'.$partes[$count-1] : $dominio_original;

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="container mt-5">
    <div class="card shadow-lg border-0 border-dark border-top border-5">
        <div class="card-body p-5">
            <h4 class="text-muted mb-3">Paso 2 de 6</h4>
            <h2 class="text-dark mb-4"><i class="bi bi-terminal"></i> Terminal WHOIS (Turbo)</h2>
            <p class="lead">Consultando registro para: <strong><?= $dominio_raiz ?></strong></p>

            <div id="terminal" style="background: #1e1e1e; color: #33ff33; padding: 20px; font-family: 'Consolas', monospace; border-radius: 8px; height: 350px; overflow-y: auto; box-shadow: inset 0 0 10px #000; font-size: 0.9rem; scroll-behavior: smooth;">
                <?php
                // Preparamos el volcado de buffer inmediato
                if (ob_get_level() > 0) { ob_end_flush(); }
                ob_implicit_flush(true);

                echo "<span style='color: #007bff;'>[SYS] Conectando con servidores de registro...</span><br>";
                flush();

                // 3. EJECUCIÓN DIRECTA (Sin retardos)
                $dom_esc = escapeshellarg($dominio_raiz);
                $comando = "whois $dom_esc 2>&1"; 
                
                $proceso = popen($comando, 'r');
                $resultado_completo = "";
                $contador_lineas = 0;

                if (is_resource($proceso)) {
                    while (!feof($proceso)) {
                        $linea = fgets($proceso);
                        if (!trim($linea)) continue;
                        
                        // Omitir avisos de copyright para ir al grano
                        if (stripos($linea, 'Sysinternals') !== false || stripos($linea, 'Copyright') !== false) continue;
                        
                        $resultado_completo .= $linea;
                        $contador_lineas++;

                        echo htmlspecialchars($linea) . "<br>";
                        
                        // Solo mandamos el scroll cada 5 líneas para no frenar el renderizado
                        if ($contador_lineas % 5 == 0) {
                            echo "<script>document.getElementById('terminal').scrollTop = document.getElementById('terminal').scrollHeight;</script>";
                        }
                        
                        // Eliminamos el usleep(5000) -> ahora va a la velocidad de la red
                        flush();
                    }
                    pclose($proceso);
                }

                // 4. GUARDAR EN BD
                $stmt = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'Whois', ?)");
                mysqli_stmt_bind_param($stmt, "is", $id, $resultado_completo);
                mysqli_stmt_execute($stmt);
                ?>
                <br><span style="color: #007bff;">[SYS] Consulta finalizada. Saltando a Typosquatting...</span>
            </div>

            <div class="progress" style="height: 10px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated bg-dark w-100"></div>
            </div>
        </div>
    </div>
</div>

<form id="nextStep" action="dnstwist.php" method="POST">
    <input type="hidden" name="id_historial" value="<?= $id ?>">
</form>

<script>
    // Un último scroll al final por si acaso
    const term = document.getElementById('terminal');
    term.scrollTop = term.scrollHeight;

    // Pausa mínima de 1 segundo para que el usuario vea que terminó
    setTimeout(function() {
        document.getElementById('nextStep').submit();
    }, 1000);
</script>

<?php require_once '../includes/footer.php'; ?>