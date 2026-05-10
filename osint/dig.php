<?php
session_start();
require_once '../config/conexion.php';
require_once '../includes/seguridad.php';

set_time_limit(60);

if (!isset($_POST['id_historial'])) {
    die("Error: No se recibió el ID.");
}

$id = (int)$_POST['id_historial'];

if (!usuarioPuedeAccederAnalisis($conn, $id)) {
    die("Error: Acceso no autorizado.");
}

registrarAnalisisPermitido($id);

function h(string $texto): string
{
    return htmlspecialchars($texto, ENT_QUOTES, 'UTF-8');
}

function normalizarDominio(string $entrada)
{
    $dominio = trim($entrada);

    if ($dominio === '') {
        return false;
    }

    $dominio = preg_replace('~^https?://~i', '', $dominio);
    $dominio = preg_replace('~^www\.~i', '', $dominio);
    $dominio = preg_replace('~[/?#].*$~', '', $dominio);
    $dominio = strtolower(trim($dominio));
    $dominio = rtrim($dominio, '.');

    if ($dominio === '') {
        return false;
    }

    if (!filter_var($dominio, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        return false;
    }

    return $dominio;
}

function limpiarTextoDns(string $texto): string
{
    $texto = str_replace(["\xEF\xBF\xBE", "￾"], '', $texto);
    $texto = preg_replace('/[\x00-\x1F\x7F]/u', ' ', $texto);
    $texto = preg_replace('/\s+/', ' ', trim($texto));
    return $texto;
}

function recortarTextoDns(string $texto, int $max = 100): string
{
    $texto = limpiarTextoDns($texto);

    if (mb_strlen($texto) > $max) {
        return mb_substr($texto, 0, $max) . '...';
    }

    return $texto;
}

function construirDatoRegistro(array $r): string
{
    $type = $r['type'] ?? '';

    if ($type === 'A') {
        return limpiarTextoDns($r['ip'] ?? '');
    }

    if ($type === 'AAAA') {
        return limpiarTextoDns($r['ipv6'] ?? '');
    }

    if ($type === 'MX') {
        $pri = $r['pri'] ?? '';
        $target = $r['target'] ?? '';
        return limpiarTextoDns(trim($pri . ' ' . $target . '.'));
    }

    if ($type === 'NS' || $type === 'CNAME' || $type === 'PTR') {
        $target = $r['target'] ?? '';
        return limpiarTextoDns($target !== '' ? $target . '.' : '');
    }

    if ($type === 'TXT') {
        if (isset($r['entries']) && is_array($r['entries'])) {
            $limpias = [];
            foreach ($r['entries'] as $entrada) {
                $entrada = recortarTextoDns((string)$entrada, 100);
                if ($entrada !== '') {
                    $limpias[] = $entrada;
                }
            }
            return implode(' | ', $limpias);
        }

        return recortarTextoDns((string)($r['txt'] ?? ''), 100);
    }

    if ($type === 'SOA') {
        $mname = limpiarTextoDns((string)($r['mname'] ?? ''));
        $rname = limpiarTextoDns((string)($r['rname'] ?? ''));
        $serial = limpiarTextoDns((string)($r['serial'] ?? ''));
        return trim($mname . '. ' . $rname . '. ' . $serial);
    }

    return limpiarTextoDns($r['ip'] ?? $r['target'] ?? $r['txt'] ?? $r['ipv6'] ?? '');
}

$stmt_check = mysqli_prepare($conn, "SELECT dominio FROM historial_dominios WHERE id = ? LIMIT 1");
mysqli_stmt_bind_param($stmt_check, "i", $id);
mysqli_stmt_execute($stmt_check);
$res_check = mysqli_stmt_get_result($stmt_check);
$d = mysqli_fetch_assoc($res_check);
mysqli_stmt_close($stmt_check);

if (!$d) {
    die("Dominio no encontrado.");
}

$dominio = normalizarDominio($d['dominio']);
if ($dominio === false) {
    die("El dominio guardado no es válido.");
}

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="container mt-5">
    <div class="card shadow-lg border-0 mx-auto border-info border-top border-5">
        <div class="card-body p-5">
            <h4 class="text-muted mb-3">Paso 4 de 7</h4>
            <h2 class="text-info mb-4"><i class="bi bi-server"></i> DNS Resolver (DiG Mode)</h2>
            <p class="lead">Consultando topología DNS para: <span class="fw-bold"><?= h($dominio) ?></span></p>

            <div id="terminal" style="background:#001b2e;color:#0dcaf0;padding:20px;font-family:'Consolas',monospace;border-radius:8px;height:380px;overflow-y:auto;box-shadow:inset 0 0 15px #000;font-size:0.9rem;border:1px solid #084298;scroll-behavior:smooth;">
                <?php
                if (ob_get_level() > 0) {
                    ob_end_flush();
                }
                ob_implicit_flush(true);

                $out_header = "; <<>> OSINT PHP DiG Emulator <<>> " . $dominio . " ANY\n";
                $out_header .= ";; ANSWER SECTION:\n\n";

                echo nl2br(h($out_header));
                flush();

                $registros = dns_get_record($dominio, DNS_A + DNS_AAAA + DNS_CNAME + DNS_MX + DNS_NS + DNS_TXT + DNS_SOA);
                $full_output = $out_header;
                $contador = 0;

                if ($registros && is_array($registros)) {
                    usort($registros, function ($a, $b) {
                        return strcmp(($a['type'] ?? ''), ($b['type'] ?? ''));
                    });

                    foreach ($registros as $r) {
                        $type = $r['type'] ?? '';
                        $host = limpiarTextoDns(($r['host'] ?? $dominio) . '.');
                        $ttl = $r['ttl'] ?? 3600;
                        $data_registro = construirDatoRegistro($r);

                        if ($type === '' || trim($data_registro) === '') {
                            continue;
                        }

                        if ($type !== 'TXT' && mb_strlen($data_registro) > 120) {
                            $data_registro = mb_substr($data_registro, 0, 120) . '...';
                        }

                        $linea = str_pad($host, 30) . "\t" . $ttl . "\tIN\t" . str_pad($type, 6) . "\t" . $data_registro . "\n";

                        echo h($linea) . "<br>";
                        $full_output .= $linea;
                        $contador++;

                        if ($contador % 2 === 0) {
                            echo "<script>document.getElementById('terminal').scrollTop = document.getElementById('terminal').scrollHeight;</script>";
                        }

                        usleep(8000);
                        flush();
                    }
                }

                if ($contador === 0) {
                    $msg_error = ";; No se encontraron registros DNS públicos relevantes.\n";
                    echo nl2br(h($msg_error));
                    $full_output .= $msg_error;
                }

                $footer = "\n;; Total de registros: " . $contador . "\n";
                $footer .= ";; Query time: " . rand(5, 30) . " msec\n";
                $footer .= ";; WHEN: " . date("D M d H:i:s T Y") . "\n";

                echo nl2br(h($footer));
                $full_output .= $footer;

                $stmtDelete = mysqli_prepare($conn, "DELETE FROM osint_resultados WHERE id_historial = ? AND herramienta = 'Dig'");
                mysqli_stmt_bind_param($stmtDelete, "i", $id);
                mysqli_stmt_execute($stmtDelete);
                mysqli_stmt_close($stmtDelete);

                $stmtInsert = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'Dig', ?)");
                mysqli_stmt_bind_param($stmtInsert, "is", $id, $full_output);
                mysqli_stmt_execute($stmtInsert);
                mysqli_stmt_close($stmtInsert);
                ?>
                <br><span style="color:#00ff00;">[OK] Se han resuelto <?= (int)$contador ?> registros con éxito.</span>
            </div>
        </div>
    </div>
</div>

<form id="autoPost" action="geoip.php" method="POST">
    <input type="hidden" name="id_historial" value="<?= (int)$id ?>">
</form>

<script>
    const terminal = document.getElementById('terminal');
    terminal.scrollTop = terminal.scrollHeight;

    setTimeout(function () {
        document.getElementById('autoPost').submit();
    }, 1200);
</script>

<?php require_once '../includes/footer.php'; ?>
