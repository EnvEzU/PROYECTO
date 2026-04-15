<?php
// Archivo: osint/puertos.php
session_start();
require_once '../config/conexion.php';

set_time_limit(60);

// 1. Validar ID por POST
if (!isset($_POST['id_historial'])) { 
    die("Error: No se recibió el ID por POST."); 
}
$id = intval($_POST['id_historial']);

// 2. Obtener dominio de la base de datos
$q = mysqli_query($conn, "SELECT dominio FROM historial_dominios WHERE id=$id");
$d = mysqli_fetch_assoc($q);

if (!$d) { die("Dominio no encontrado."); }
$dom_puro = htmlspecialchars($d['dominio']);

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="container mt-5 mb-5">
    <div class="card shadow-lg border-0 mx-auto border-danger border-top border-5">
        <div class="card-body p-5">
            <h4 class="text-muted mb-3">Paso 6 de 6</h4>
            <h2 class="text-danger mb-4"><i class="bi bi-door-open"></i> Escáner de Puertos TCP</h2>
            <p class="lead">Auditando servicios expuestos para: <strong><?= $dom_puro ?></strong></p>
            
            <div id="terminal" class="mt-4 mb-4" style="background: #1a0000; color: #ff4d4d; padding: 20px; font-family: 'Consolas', monospace; border-radius: 8px; height: 380px; overflow-y: auto; box-shadow: inset 0 0 15px #000; font-size: 0.85rem; border: 1px solid #dc3545;">
                <span style="color: #ffffff;">[SYS] Iniciando TCP Connect Scan...</span><br>
                <span style="color: #ffffff;">[SYS] Aplicando timeout de 1s por socket...</span><br><br>

                <?php
                // Forzar volcado de buffer para que la consola se vea de inmediato
                while (ob_get_level() > 0) { ob_end_flush(); }
                flush();

                // ==========================================
                // MOTOR DE ESCANEO (CON SALIDA EN VIVO)
                // ==========================================
                $ip_objetivo = gethostbyname($d['dominio']);
                $puertos_comunes = [
                    21 => 'FTP (Transferencia de Archivos)',
                    22 => 'SSH (Consola Remota)',
                    25 => 'SMTP (Envío de Correo)',
                    80 => 'HTTP (Web Insegura)',
                    110 => 'POP3 (Recepción de Correo)',
                    443 => 'HTTPS (Web Segura)',
                    3306 => 'MySQL (Base de Datos)',
                    3389 => 'RDP (Escritorio Remoto Windows)'
                ];

                $out = "=== ESCÁNER DE PUERTOS OSINT ===\n";
                $out .= "Objetivo: " . $d['dominio'] . " ($ip_objetivo)\n\n";
                $out .= str_pad("PUERTO", 10) . str_pad("ESTADO", 15) . "SERVICIO\n";
                $out .= str_repeat("-", 55) . "\n";

                echo "[+] Objetivo resuelto: <span style='color:#fff;'>$ip_objetivo</span><br><br>";
                echo str_pad("PUERTO", 12) . str_pad("ESTADO", 18) . "SERVICIO<br>";
                echo "-------------------------------------------------------<br>";
                flush();

                foreach ($puertos_comunes as $puerto => $servicio) {
                    // Usamos fsockopen con timeout de 1 segundo
                    $conexion = @fsockopen($ip_objetivo, $puerto, $errno, $errstr, 1);
                    
                    if (is_resource($conexion)) {
                        $estado_txt = "ABIERTO";
                        $color = "#28a745"; // Verde para abiertos
                        $out_linea = str_pad($puerto . "/tcp", 10) . str_pad("ABIERTO", 15) . $servicio . "\n";
                        fclose($conexion);
                    } else {
                        $estado_txt = "cerrado/filtro";
                        $color = "#888"; // Gris para cerrados
                        $out_linea = str_pad($puerto . "/tcp", 10) . str_pad("cerrado/filtro", 15) . $servicio . "\n";
                    }

                    // Imprimir en consola visual
                    echo str_pad($puerto . "/tcp", 12) . "<span style='color:$color; font-weight:bold;'>" . str_pad($estado_txt, 18) . "</span>" . $servicio . "<br>";
                    
                    $out .= $out_linea;

                    // Auto-scroll
                    echo "<script>document.getElementById('terminal').scrollTop = document.getElementById('terminal').scrollHeight;</script>";
                    
                    flush();
                    usleep(100000); // Pequeña pausa para que se vea el progreso
                }

                // 3. GUARDAR RESULTADO FINAL EN LA BD
                $stmt = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'Puertos', ?)");
                mysqli_stmt_bind_param($stmt, "is", $id, $out);
                mysqli_stmt_execute($stmt);
                ?>
                <br><span style="color: #ffffff;">[OK] Escaneo finalizado. Generando reporte...</span>
            </div>

            <div class="progress" style="height: 15px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated bg-danger w-100 fw-bold">
                    ANÁLISIS COMPLETO - REDIRIGIENDO AL INFORME
                </div>
            </div>
        </div>
    </div>
</div>

<form id="finalForm" action="../resultados/ver_resultado.php" method="POST">
    <input type="hidden" name="id" value="<?= $id ?>">
</form>

<script>
    // Delay de 2.5 segundos para que el usuario sienta el "éxito" del análisis completo
    setTimeout(function() {
        document.getElementById('finalForm').submit();
    }, 2500);
</script>

<?php require_once '../includes/footer.php'; ?>