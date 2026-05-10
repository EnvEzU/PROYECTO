<?php
session_start();
require_once '../config/conexion.php';
require_once '../includes/seguridad.php';

set_time_limit(60);

if (!isset($_POST['id_historial'])) {
    die("Error: Acceso no autorizado.");
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

function obtenerDominioRaiz(string $dominio): string
{
    $partes = explode('.', $dominio);
    $count = count($partes);

    if ($count >= 2) {
        return $partes[$count - 2] . '.' . $partes[$count - 1];
    }

    return $dominio;
}

function lineaWhoisInteresante(string $linea): bool
{
    $linea = trim($linea);

    if ($linea === '') {
        return false;
    }

    $permitidos = [
        'Domain Name:',
        'Registry Domain ID:',
        'Registrar:',
        'Registrar URL:',
        'Registrar WHOIS Server:',
        'Registrar IANA ID:',
        'Updated Date:',
        'Creation Date:',
        'Registry Expiry Date:',
        'Registrar Registration Expiration Date:',
        'Registrant Organization:',
        'Registrant Country:',
        'Registrant Name:',
        'Name Server:',
        'DNSSEC:',
        'Domain Status:'
    ];

    foreach ($permitidos as $texto) {
        if (stripos($linea, $texto) === 0) {
            return true;
        }
    }

    return false;
}

function limpiarLineaWhois(string $linea): string
{
    $linea = trim($linea);
    $linea = preg_replace('/\s+/', ' ', $linea);
    return $linea;
}

$stmt = mysqli_prepare($conn, "SELECT dominio FROM historial_dominios WHERE id = ? LIMIT 1");
mysqli_stmt_bind_param($stmt, "i", $id);
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);
$d = mysqli_fetch_assoc($res);
mysqli_stmt_close($stmt);

if (!$d) {
    die("Dominio no encontrado.");
}

$dominio_original = normalizarDominio($d['dominio']);
if ($dominio_original === false) {
    die("El dominio guardado no es válido.");
}

$dominio_raiz = obtenerDominioRaiz($dominio_original);

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="container mt-5">
    <div class="card shadow-lg border-0 border-dark border-top border-5">
        <div class="card-body p-5">
            <h4 class="text-muted mb-3">Paso 2 de 7</h4>
            <h2 class="text-dark mb-4"><i class="bi bi-terminal"></i> Terminal WHOIS</h2>
            <p class="lead">Consultando registro para: <strong><?= h($dominio_raiz) ?></strong></p>

            <div id="terminal" style="background:#1e1e1e;color:#33ff33;padding:20px;font-family:'Consolas',monospace;border-radius:8px;height:350px;overflow-y:auto;box-shadow:inset 0 0 10px #000;font-size:0.9rem;scroll-behavior:smooth;">
                <?php
                if (ob_get_level() > 0) {
                    ob_end_flush();
                }
                ob_implicit_flush(true);

                echo "<span style='color:#4dabf7;'>[SYS] Conectando con servidores de registro...</span><br>";
                echo "<span style='color:#4dabf7;'>[SYS] Dominio raíz:</span> " . h($dominio_raiz) . "<br><br>";
                flush();

                $dom_esc = escapeshellarg($dominio_raiz);
                $comando = "whois " . $dom_esc . " 2>&1";

                $proceso = popen($comando, 'r');
                $lineasFiltradas = [];
                $vistos = [];

                if (is_resource($proceso)) {
                    while (!feof($proceso)) {
                        $linea = fgets($proceso);

                        if (!lineaWhoisInteresante($linea)) {
                            continue;
                        }

                        $linea = limpiarLineaWhois($linea);

                        if ($linea === '') {
                            continue;
                        }

                        if (isset($vistos[$linea])) {
                            continue;
                        }

                        $vistos[$linea] = true;
                        $lineasFiltradas[] = $linea;

                        echo h($linea) . "<br>";

                        if (count($lineasFiltradas) % 5 === 0) {
                            echo "<script>document.getElementById('terminal').scrollTop = document.getElementById('terminal').scrollHeight;</script>";
                        }

                        flush();
                    }

                    pclose($proceso);
                } else {
                    echo "<span style='color:#ff8080;'>[ERROR] No se pudo ejecutar el comando WHOIS.</span><br>";
                    $lineasFiltradas[] = "ERROR: No se pudo ejecutar el comando WHOIS.";
                }

                if (empty($lineasFiltradas)) {
                    $lineasFiltradas[] = "No se obtuvo información WHOIS relevante para este dominio.";
                }

                $resultado_limpio = "=== RESUMEN WHOIS DEL DOMINIO ===\n";
                $resultado_limpio .= "Dominio consultado: " . $dominio_raiz . "\n\n";
                $resultado_limpio .= implode("\n", $lineasFiltradas) . "\n";

                $stmtDelete = mysqli_prepare($conn, "DELETE FROM osint_resultados WHERE id_historial = ? AND herramienta = 'Whois'");
                mysqli_stmt_bind_param($stmtDelete, "i", $id);
                mysqli_stmt_execute($stmtDelete);
                mysqli_stmt_close($stmtDelete);

                $stmtInsert = mysqli_prepare($conn, "INSERT INTO osint_resultados (id_historial, herramienta, resultado_completo) VALUES (?, 'Whois', ?)");
                mysqli_stmt_bind_param($stmtInsert, "is", $id, $resultado_limpio);
                mysqli_stmt_execute($stmtInsert);
                mysqli_stmt_close($stmtInsert);
                ?>
                <br><span style="color:#4dabf7;">[SYS] Consulta finalizada. Saltando a Typosquatting...</span>
            </div>

            <div class="progress mt-3" style="height: 10px;">
                <div class="progress-bar progress-bar-striped progress-bar-animated bg-dark w-100"></div>
            </div>
        </div>
    </div>
</div>

<form id="nextStep" action="dnstwist.php" method="POST">
    <input type="hidden" name="id_historial" value="<?= (int)$id ?>">
</form>

<script>
    const term = document.getElementById('terminal');
    term.scrollTop = term.scrollHeight;

    setTimeout(function () {
        document.getElementById('nextStep').submit();
    }, 1200);
</script>

<?php require_once '../includes/footer.php'; ?>
