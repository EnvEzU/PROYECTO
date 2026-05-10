<?php
session_start();
require_once '../config/conexion.php';
require_once '../includes/seguridad.php';

asegurarColumnaAnalisisCompleto($conn);
limpiarAnalisisIncompletosAntiguos($conn, 60);

$id_hist = 0;
$token_reporte = '';

if (isset($_GET['r'])) {
    $token_reporte = strtolower(trim((string)$_GET['r']));
    $id_hist = obtenerIdAnalisisPorToken($conn, $token_reporte);
} elseif (isset($_POST['token_reporte'])) {
    $token_reporte = strtolower(trim((string)$_POST['token_reporte']));
    $id_hist = obtenerIdAnalisisPorToken($conn, $token_reporte);
} elseif (isset($_POST['id']) || isset($_POST['id_historial'])) {
    // Compatibilidad interna: los módulos del escaneo siguen comunicándose por POST con el ID interno.
    // No se acepta ID por GET para evitar enumeración directa en la URL.
    $id_hist = isset($_POST['id']) ? (int)$_POST['id'] : (int)$_POST['id_historial'];

    if ($id_hist > 0 && usuarioPuedeAccederAnalisis($conn, $id_hist)) {
        $token_reporte = asegurarTokenAnalisis($conn, $id_hist);
        if ($token_reporte !== '') {
            header("Location: ver_resultado.php?r=" . urlencode($token_reporte));
            exit;
        }
    }
}

if ($id_hist <= 0 || !usuarioPuedeAccederAnalisis($conn, $id_hist) || !analisisEstaCompleto($conn, $id_hist)) {
    header("Location: ../index.php");
    exit;
}

registrarAnalisisPermitido($id_hist);
$token_reporte = asegurarTokenAnalisis($conn, $id_hist);
$_SESSION['ver_id_reporte'] = $token_reporte;

$mensajeComentario = '';

// NUEVO: Lógica para que los Administradores puedan borrar comentarios directamente desde aquí
if (isset($_POST['borrar_comentario']) && isset($_SESSION['rol']) && $_SESSION['rol'] === 'admin') {
    if (!validarCsrf()) {
        $mensajeComentario = '<div class="alert alert-danger no-print">Solicitud no válida. Vuelve a intentarlo.</div>';
    } else {
        $id_borrar_com = (int)$_POST['id_comentario'];
        $stmt_del = mysqli_prepare($conn, "DELETE FROM comentarios_dominios WHERE id = ?");
        mysqli_stmt_bind_param($stmt_del, "i", $id_borrar_com);
        mysqli_stmt_execute($stmt_del);
        mysqli_stmt_close($stmt_del);
        
        // Recargamos la página para limpiar el formulario y actualizar la vista
        header("Location: ver_resultado.php?r=" . urlencode($token_reporte));
        exit;
    }
}

if (isset($_GET['comentario'])) {
    if ($_GET['comentario'] === 'ok') {
        $mensajeComentario = '<div class="alert alert-success no-print">Comentario publicado correctamente.</div>';
    } elseif ($_GET['comentario'] === 'error') {
        $mensajeComentario = '<div class="alert alert-danger no-print">No se pudo guardar el comentario. Revisa los datos e inténtalo de nuevo.</div>';
    }
}

$sql_info = "SELECT id, id_usuario, dominio, estado, detalles, fecha_escaneo
             FROM historial_dominios
             WHERE id = ?
             LIMIT 1";

$stmt_info = mysqli_prepare($conn, $sql_info);
mysqli_stmt_bind_param($stmt_info, "i", $id_hist);
mysqli_stmt_execute($stmt_info);
$info = mysqli_fetch_assoc(mysqli_stmt_get_result($stmt_info));
mysqli_stmt_close($stmt_info);

if (!$info) {
    die("Error: No se encontró el análisis en la base de datos.");
}

$dominio_actual = strtolower(trim($info['dominio']));

$data = [];
$sql_tools = "SELECT herramienta, resultado_completo FROM osint_resultados WHERE id_historial = ?";
$stmt_tools = mysqli_prepare($conn, $sql_tools);
mysqli_stmt_bind_param($stmt_tools, "i", $id_hist);
mysqli_stmt_execute($stmt_tools);
$res_tools = mysqli_stmt_get_result($stmt_tools);

while ($r = mysqli_fetch_assoc($res_tools)) {
    $data[$r['herramienta']] = $r['resultado_completo'];
}
mysqli_stmt_close($stmt_tools);

$comentarios = [];
// Añadimos c.id AS id_comentario a la consulta para poder seleccionarlo y borrarlo
$sql_com = "SELECT c.id AS id_comentario, c.autor_nombre, c.comentario, c.tipo_comentario, c.fecha_creacion, u.rol
            FROM comentarios_dominios c
            LEFT JOIN usuarios u ON c.id_usuario = u.id
            WHERE c.dominio = ? AND c.estado = 'aprobado'
            ORDER BY c.fecha_creacion DESC";
$stmt_com = mysqli_prepare($conn, $sql_com);
mysqli_stmt_bind_param($stmt_com, "s", $dominio_actual);
mysqli_stmt_execute($stmt_com);
$res_com = mysqli_stmt_get_result($stmt_com);

while ($fila_com = mysqli_fetch_assoc($res_com)) {
    $comentarios[] = $fila_com;
}
mysqli_stmt_close($stmt_com);

$totalComentarios = count($comentarios);


function valorSsl($valor): string
{
    if ($valor === null || $valor === '') {
        return 'N/D';
    }

    if (is_bool($valor)) {
        return $valor ? 'Sí' : 'No';
    }

    if (is_array($valor)) {
        return implode(', ', array_map('strval', $valor));
    }

    return (string)$valor;
}

function boolSsl($valor): ?bool
{
    if (is_bool($valor)) {
        return $valor;
    }

    if ($valor === null || $valor === '') {
        return null;
    }

    $v = strtolower(trim((string)$valor));
    if (in_array($v, ['1', 'si', 'sí', 'true', 'correcta', 'correcto'], true)) {
        return true;
    }
    if (in_array($v, ['0', 'no', 'false', 'incorrecta', 'incorrecto'], true)) {
        return false;
    }

    return null;
}

function emisorSimpleSsl(string $emisor): string
{
    $emisor = trim($emisor);
    if ($emisor === '' || strtoupper($emisor) === 'N/D') {
        return 'No disponible';
    }

    if (preg_match('/(?:^|,\s*)O=([^,]+)/', $emisor, $m)) {
        return trim($m[1]);
    }

    if (preg_match('/(?:^|,\s*)CN=([^,]+)/', $emisor, $m)) {
        return trim($m[1]);
    }

    return strlen($emisor) > 80 ? substr($emisor, 0, 77) . '...' : $emisor;
}

function protocoloHttpsModernoSsl(string $protocolo): ?bool
{
    $p = strtoupper(trim($protocolo));
    if ($p === '' || $p === 'N/D') {
        return null;
    }

    if (strpos($p, 'TLSV1.3') !== false || strpos($p, 'TLSV1.2') !== false || strpos($p, 'TLS1.3') !== false || strpos($p, 'TLS1.2') !== false) {
        return true;
    }

    if (strpos($p, 'SSL') !== false || strpos($p, 'TLSV1.0') !== false || strpos($p, 'TLSV1.1') !== false || $p === 'TLSV1') {
        return false;
    }

    return null;
}

function estadoVisualCertificadoSsl(string $riesgo): array
{
    $riesgo = strtoupper(trim($riesgo));

    if ($riesgo === 'BAJO') {
        return [
            'clase' => 'success',
            'icono' => 'bi-shield-check',
            'titulo' => 'Candado HTTPS correcto',
            'mensaje' => 'El certificado de esta web no muestra problemas importantes.',
            'consejo' => 'Puedes continuar revisando el resto del informe para tomar una decisión final.'
        ];
    }

    if ($riesgo === 'MEDIO') {
        return [
            'clase' => 'warning',
            'icono' => 'bi-exclamation-triangle',
            'titulo' => 'Candado HTTPS con avisos',
            'mensaje' => 'La web usa HTTPS, pero hay algún detalle que conviene revisar.',
            'consejo' => 'Evita introducir datos sensibles si el resto del informe también muestra señales raras.'
        ];
    }

    if ($riesgo === 'ALTO') {
        return [
            'clase' => 'danger',
            'icono' => 'bi-x-octagon',
            'titulo' => 'Problema importante en el certificado',
            'mensaje' => 'El candado HTTPS presenta un problema relevante.',
            'consejo' => 'No introduzcas contraseñas, tarjetas ni datos personales hasta revisar la web.'
        ];
    }

    return [
        'clase' => 'secondary',
        'icono' => 'bi-question-circle',
        'titulo' => 'No se pudo comprobar bien el candado HTTPS',
        'mensaje' => 'No hay datos suficientes para confirmar si el certificado está bien.',
        'consejo' => 'Prueba de nuevo más tarde o revisa el resto del informe antes de confiar en la web.'
    ];
}

function itemComprobacionSsl(string $titulo, ?bool $estado, string $detalle = ''): string
{
    if ($estado === true) {
        $icono = 'bi-check-circle-fill text-success';
        $texto = 'Correcto';
    } elseif ($estado === false) {
        $icono = 'bi-x-circle-fill text-danger';
        $texto = 'Problema';
    } else {
        $icono = 'bi-question-circle-fill text-secondary';
        $texto = 'No comprobado';
    }

    $html = '<div class="cert-check d-flex gap-2 py-2 border-bottom">';
    $html .= '<div class="pt-1"><i class="bi ' . $icono . '"></i></div>';
    $html .= '<div class="flex-grow-1">';
    $html .= '<div class="d-flex justify-content-between gap-2 flex-wrap"><strong>' . htmlspecialchars($titulo, ENT_QUOTES, 'UTF-8') . '</strong><span class="small fw-semibold">' . htmlspecialchars($texto, ENT_QUOTES, 'UTF-8') . '</span></div>';
    if ($detalle !== '') {
        $html .= '<div class="small text-muted">' . htmlspecialchars($detalle, ENT_QUOTES, 'UTF-8') . '</div>';
    }
    $html .= '</div></div>';
    return $html;
}

function filaDatoBasicoSsl(string $etiqueta, $valor): string
{
    return '<div class="d-flex justify-content-between gap-3 py-2 border-bottom"><span class="text-muted">' . htmlspecialchars($etiqueta, ENT_QUOTES, 'UTF-8') . '</span><strong class="text-end text-break">' . htmlspecialchars(valorSsl($valor), ENT_QUOTES, 'UTF-8') . '</strong></div>';
}

function filaDatoTecnicoSsl(string $etiqueta, $valor): string
{
    return '<tr><th class="text-muted" style="width:35%;">' . htmlspecialchars($etiqueta, ENT_QUOTES, 'UTF-8') . '</th><td class="text-break"><code class="small">' . htmlspecialchars(valorSsl($valor), ENT_QUOTES, 'UTF-8') . '</code></td></tr>';
}

function mensajeSimpleRevisionSsl(string $texto): string
{
    $t = strtolower($texto);

    if (strpos($t, 'no cubre') !== false) {
        return 'El certificado no parece pertenecer exactamente a esta web.';
    }
    if (strpos($t, 'caducado') !== false) {
        return 'El certificado ha caducado.';
    }
    if (strpos($t, 'fecha de inicio') !== false || strpos($t, 'todavía no es válido') !== false) {
        return 'El certificado todavía no ha empezado a ser válido.';
    }
    if (strpos($t, 'autofirmado') !== false) {
        return 'El certificado parece creado por el propio sitio y no por una entidad externa.';
    }
    if (strpos($t, 'algoritmo') !== false || strpos($t, 'firma débil') !== false) {
        return 'Usa un método de seguridad antiguo.';
    }
    if (strpos($t, 'clave rsa') !== false || strpos($t, '2048') !== false) {
        return 'La clave del certificado es demasiado pequeña.';
    }
    if (strpos($t, 'protocolo obsoleto') !== false) {
        return 'La conexión usa un protocolo antiguo.';
    }
    if (strpos($t, 'caduca pronto') !== false) {
        return 'El certificado caduca pronto.';
    }
    if (strpos($t, 'fechas') !== false) {
        return 'No se pudieron leer bien las fechas del certificado.';
    }
    if (strpos($t, 'no se pudo') !== false) {
        return 'No se pudo comprobar correctamente el certificado.';
    }

    return $texto;
}

function pintarCertificadoSsl(?string $resultado): void
{
    $resultado = trim((string)$resultado);

    if ($resultado === '') {
        echo '<div class="alert alert-light border mb-0">No se encontraron datos del certificado HTTPS.</div>';
        return;
    }

    $json = json_decode($resultado, true);
    if (!is_array($json) || (($json['modulo'] ?? '') !== 'certificado_ssl_tls')) {
        echo '<div class="alert alert-warning mb-0">Este resultado se guardó con un formato antiguo. Repite el análisis para verlo resumido de forma sencilla.</div>';
        return;
    }

    $cert = is_array($json['certificado'] ?? null) ? $json['certificado'] : [];
    $conexion = is_array($json['conexion_https'] ?? null) ? $json['conexion_https'] : [];
    $cobertura = is_array($json['cobertura_dominio'] ?? null) ? $json['cobertura_dominio'] : [];
    $revision = is_array($json['revision'] ?? null) ? $json['revision'] : [];

    $riesgo = strtoupper(trim((string)($json['riesgo_tecnico'] ?? 'NO CONCLUYENTE')));
    $visual = estadoVisualCertificadoSsl($riesgo);
    $resultadoSimple = $visual['titulo'];

    $dominioSolicitado = (string)($json['dominio_solicitado'] ?? 'N/D');
    $hostComprobado = (string)($json['host_comprobado'] ?? $dominioSolicitado);
    if ($hostComprobado === '') {
        $hostComprobado = $dominioSolicitado;
    }

    $certEncontrado = boolSsl($json['certificado_encontrado'] ?? null);
    $cubreHost = boolSsl($json['cubre_host'] ?? null);
    $vigente = boolSsl($json['vigente'] ?? null);
    $autofirmado = boolSsl($json['autofirmado'] ?? null);
    $noAutofirmado = $autofirmado === null ? null : !$autofirmado;
    $diasRestantes = $json['dias_restantes'] ?? null;
    $protocolo = (string)($conexion['protocolo_tls_negociado'] ?? 'N/D');
    $conexionModerna = protocoloHttpsModernoSsl($protocolo);

    $detalleCaducidad = 'Fecha no disponible';
    if (is_numeric($diasRestantes)) {
        $dias = (int)$diasRestantes;
        if ($dias < 0) {
            $detalleCaducidad = 'Caducó hace ' . abs($dias) . ' días';
        } elseif ($dias === 0) {
            $detalleCaducidad = 'Caduca hoy';
        } else {
            $detalleCaducidad = 'Caduca en ' . $dias . ' días';
        }
    }

    $detalleHost = $hostComprobado !== $dominioSolicitado
        ? 'Se comprobó ' . $hostComprobado . ' porque algunos sitios usan HTTPS solo con www.'
        : 'Comprobado sobre ' . $hostComprobado;

    $problemas = is_array($revision['problemas'] ?? null) ? $revision['problemas'] : [];
    $avisos = is_array($revision['avisos'] ?? null) ? $revision['avisos'] : [];
    $mensajesRevision = [];
    foreach (array_merge($problemas, $avisos) as $item) {
        $simple = mensajeSimpleRevisionSsl((string)$item);
        if ($simple !== '' && !in_array($simple, $mensajesRevision, true)) {
            $mensajesRevision[] = $simple;
        }
    }

    echo '<div class="ssl-panel ssl-panel-simple">';

    echo '<div class="alert alert-' . htmlspecialchars($visual['clase'], ENT_QUOTES, 'UTF-8') . ' border-' . htmlspecialchars($visual['clase'], ENT_QUOTES, 'UTF-8') . ' d-flex gap-3 align-items-start mb-3">';
    echo '<div class="fs-3 lh-1"><i class="bi ' . htmlspecialchars($visual['icono'], ENT_QUOTES, 'UTF-8') . '"></i></div>';
    echo '<div>';
    echo '<h5 class="alert-heading mb-1">' . htmlspecialchars($visual['titulo'], ENT_QUOTES, 'UTF-8') . '</h5>';
    echo '<p class="mb-1">' . htmlspecialchars($visual['mensaje'], ENT_QUOTES, 'UTF-8') . '</p>';
    echo '<div class="small">' . htmlspecialchars($visual['consejo'], ENT_QUOTES, 'UTF-8') . '</div>';
    echo '</div>';
    echo '</div>';

    echo '<div class="row g-3">';

    echo '<div class="col-lg-7">';
    echo '<div class="border rounded h-100 p-3">';
    echo '<h6 class="fw-bold mb-2"><i class="bi bi-list-check"></i> Comprobaciones principales</h6>';
    echo itemComprobacionSsl('La web tiene certificado HTTPS', $certEncontrado, $certEncontrado === true ? 'Se ha podido leer el certificado.' : 'No se ha podido confirmar el certificado.');
    echo itemComprobacionSsl('El certificado pertenece a esta web', $cubreHost, $detalleHost);
    echo itemComprobacionSsl('El certificado no está caducado', $vigente, $detalleCaducidad);
    echo itemComprobacionSsl('Está emitido por una entidad externa', $noAutofirmado, $noAutofirmado === true ? 'Lo normal es que no lo cree la propia web.' : 'Conviene revisarlo antes de confiar en la web.');
    echo itemComprobacionSsl('La conexión HTTPS es moderna', $conexionModerna, $protocolo !== 'N/D' ? 'Protocolo usado: ' . $protocolo : 'No se pudo leer el protocolo usado.');
    echo '</div>';
    echo '</div>';

    echo '<div class="col-lg-5">';
    echo '<div class="border rounded h-100 p-3 bg-light">';
    echo '<h6 class="fw-bold mb-2"><i class="bi bi-info-circle"></i> Datos básicos</h6>';
    echo filaDatoBasicoSsl('Web comprobada', $hostComprobado);
    echo filaDatoBasicoSsl('Emitido para', $cert['cn'] ?? 'N/D');
    echo filaDatoBasicoSsl('Emitido por', emisorSimpleSsl((string)($cert['emisor'] ?? '')));
    echo filaDatoBasicoSsl('Válido hasta', $cert['valido_hasta'] ?? 'N/D');
    echo filaDatoBasicoSsl('Resultado', $resultadoSimple);
    echo '</div>';
    echo '</div>';

    echo '</div>';

    if (!empty($mensajesRevision)) {
        $claseLista = $riesgo === 'ALTO' ? 'danger' : 'warning';
        echo '<div class="alert alert-' . $claseLista . ' mt-3 mb-0">';
        echo '<strong>Qué debe revisar el usuario:</strong>';
        echo '<ul class="mb-0 mt-2">';
        foreach (array_slice($mensajesRevision, 0, 4) as $mensaje) {
            echo '<li>' . htmlspecialchars($mensaje, ENT_QUOTES, 'UTF-8') . '</li>';
        }
        echo '</ul>';
        echo '</div>';
    }

    if (isset($_SESSION['rol']) && $_SESSION['rol'] === 'admin') {
        $sanCoincidentes = is_array($cobertura['san_dns_coincidentes'] ?? null) ? implode(', ', array_slice($cobertura['san_dns_coincidentes'], 0, 5)) : 'N/D';
        echo '<details class="cert-datos-avanzados mt-3 no-print">';
        echo '<summary class="btn btn-sm btn-outline-secondary">Información avanzada para mantenimiento</summary>';
        echo '<div class="table-responsive mt-2"><table class="table table-sm table-bordered mb-0">';
        echo filaDatoTecnicoSsl('Algoritmo de firma', $cert['algoritmo_firma'] ?? 'N/D');
        echo filaDatoTecnicoSsl('Clave pública', $cert['clave_publica'] ?? 'N/D');
        echo filaDatoTecnicoSsl('Huella SHA-256', $cert['huella_sha256'] ?? 'N/D');
        echo filaDatoTecnicoSsl('Cifrado negociado', $conexion['cifrado_negociado'] ?? 'N/D');
        echo filaDatoTecnicoSsl('SAN coincidente', $sanCoincidentes !== '' ? $sanCoincidentes : 'N/D');
        echo filaDatoTecnicoSsl('Número de serie', $cert['numero_serie'] ?? 'N/D');
        echo '</table></div>';
        echo '</details>';
    }

    echo '</div>';
}

$ruta_base = "../";
require_once '../includes/header.php';
?>

<style>
    @media print {
        .no-print, .btn, .navbar, footer, .breadcrumb, form, textarea, select {
            display: none !important;
        }

        .container {
            width: 100% !important;
            max-width: none !important;
            margin: 0 !important;
            padding: 0 !important;
        }

        body {
            background-color: white !important;
            -webkit-print-color-adjust: exact;
            print-color-adjust: exact;
        }

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

        pre {
            max-height: none !important;
            overflow: visible !important;
            white-space: pre-wrap !important;
            font-size: 10pt !important;
            background: #fff !important;
            color: #000 !important;
            border: none !important;
        }

        .alert {
            border: 2px solid #000 !important;
            background: #fff !important;
            color: #000 !important;
        }
        
        #seccion-analisis, #seccion-comentarios {
            display: block !important; 
        }
    }

    pre {
        max-height: 400px;
        overflow-y: auto;
        background-color: #f8f9fa;
        font-family: 'Courier New', Courier, monospace;
        font-size: 0.85rem;
        white-space: pre-wrap;
        word-break: break-word;
    }

    .card-header {
        font-size: 1.1rem;
    }

    .comentario-card {
        border-left: 4px solid #0d6efd;
    }

    .comentario-meta {
        font-size: 0.9rem;
    }

    .separador-formulario {
        border-top: 1px dashed #ced4da;
        margin-top: 1.5rem;
        padding-top: 1.5rem;
    }
    
    .pestana-btn {
        background: none;
        border: none;
        padding: 10px 20px;
        font-size: 1.1rem;
        font-weight: bold;
        color: #6c757d;
        border-bottom: 3px solid transparent;
        cursor: pointer;
        transition: all 0.2s;
    }
    .pestana-btn:hover {
        color: #0d6efd;
    }
    .pestana-btn.activa {
        color: #0d6efd;
        border-bottom: 3px solid #0d6efd;
    }
    .badge-admin {
        background-color: #ffc107;
        color: #000;
        font-size: 0.75rem;
        margin-left: 5px;
        vertical-align: middle;
    }

    .ssl-panel .table th,
    .ssl-panel .table td {
        padding: 0.55rem 0.75rem;
        vertical-align: middle;
    }

    .ssl-panel-simple .cert-check:last-child {
        border-bottom: 0 !important;
    }

    .ssl-panel details.cert-datos-avanzados summary {
        cursor: pointer;
        list-style: none;
    }

    .ssl-panel details.cert-datos-avanzados summary::-webkit-details-marker {
        display: none;
    }
</style>

<div class="container mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4 no-print flex-wrap gap-2">
        <div>
            <h2 class="mb-1">
                Auditoría OSINT:
                <span class="text-primary"><?= htmlspecialchars($info['dominio']) ?></span>
            </h2>
            <p class="text-muted mb-0">Informe técnico consolidado del análisis realizado</p>
        </div>

        <div class="d-flex gap-2">
            <a href="../index.php" class="btn btn-outline-secondary">
                <i class="bi bi-house"></i> Inicio
            </a>
        </div>
    </div>

    <?= $mensajeComentario ?>

    <?php
    $alertClass = 'alert-success';
    $estadoVisible = strtoupper((string)$info['estado']);
    if ($info['estado'] === 'maliciosa') {
        $alertClass = 'alert-danger';
    } elseif ($info['estado'] === 'sospechosa') {
        $alertClass = 'alert-warning';
    } elseif ($info['estado'] === 'no_concluyente') {
        $alertClass = 'alert-secondary';
        $estadoVisible = 'NO CONCLUYENTE';
    }
    ?>

    <div class="alert <?= $alertClass ?> text-center shadow-sm border-2">
        <h3 class="mb-1">DICTAMEN DE SEGURIDAD: <?= htmlspecialchars($estadoVisible) ?></h3>
        <p class="mb-0">
            Dominio analizado: <strong><?= htmlspecialchars($info['dominio']) ?></strong><br>
            Fecha del escaneo: <strong><?= !empty($info['fecha_escaneo']) ? date("d/m/Y H:i", strtotime($info['fecha_escaneo'])) : date("d/m/Y H:i") ?></strong>
        </p>
    </div>

    <div class="d-flex border-bottom mb-4 no-print">
        <button id="btn-analisis" class="pestana-btn activa" onclick="cambiarPestana('analisis')">
            <i class="bi bi-search"></i> Resultados del Análisis
        </button>
        <button id="btn-comentarios" class="pestana-btn" onclick="cambiarPestana('comentarios')">
            <i class="bi bi-chat-dots"></i> Comunidad (<?= (int)$totalComentarios ?>)
        </button>
    </div>

    <div id="seccion-analisis">
        <div class="row">
            <div class="col-md-5 mb-4">
                <div class="card h-100 shadow-sm border-primary">
                    <div class="card-header fw-bold">
                        <i class="bi bi-shield-check"></i> 1. Reputación de Malware
                    </div>
                    <div class="card-body">
                        <?php
                        $vt = json_decode($data['VirusTotal'] ?? '{}', true);

                        if (is_array($vt) && isset($vt['data']['attributes']['last_analysis_stats'])) {
                            $s = $vt['data']['attributes']['last_analysis_stats'];
                            echo "<ul class='list-group list-group-flush'>";
                            echo "<li class='list-group-item d-flex justify-content-between'>Maliciosos <span class='badge bg-danger rounded-pill'>" . (int)($s['malicious'] ?? 0) . "</span></li>";
                            echo "<li class='list-group-item d-flex justify-content-between'>Inofensivos <span class='badge bg-success rounded-pill'>" . (int)($s['harmless'] ?? 0) . "</span></li>";
                            echo "<li class='list-group-item d-flex justify-content-between'>Sospechosos <span class='badge bg-warning text-dark rounded-pill'>" . (int)($s['suspicious'] ?? 0) . "</span></li>";
                            echo "</ul>";
                        } else {
                            echo "<div class='text-muted'>Sin datos de reputación.</div>";
                        }
                        ?>
                    </div>
                </div>
            </div>

            <div class="col-md-7 mb-4">
                <div class="card h-100 shadow-sm border-success">
                    <div class="card-header fw-bold">
                        <i class="bi bi-geo-alt"></i> 2. Ubicación y ASN
                    </div>
                    <div class="card-body p-0">
                        <pre class="p-3 m-0"><?= htmlspecialchars($data['GeoIP'] ?? 'Sin datos de ubicación.') ?></pre>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-6 mb-4">
                <div class="card h-100 shadow-sm border-dark">
                    <div class="card-header fw-bold">
                        <i class="bi bi-person-badge"></i> 3. Registro WHOIS
                    </div>
                    <div class="card-body p-0">
                        <pre class="p-3 m-0"><?= htmlspecialchars($data['Whois'] ?? 'Sin datos de registro.') ?></pre>
                    </div>
                </div>
            </div>

            <div class="col-md-6 mb-4">
                <div class="card h-100 shadow-sm border-danger">
                    <div class="card-header fw-bold">
                        <i class="bi bi-door-open"></i> 4. Escaneo de Puertos
                    </div>
                    <div class="card-body p-0">
                        <pre class="p-3 m-0"><?= htmlspecialchars($data['Puertos'] ?? 'Sin datos de puertos.') ?></pre>
                    </div>
                </div>
            </div>
        </div>

        <div class="card mb-4 shadow-sm border-info">
            <div class="card-header fw-bold">
                <i class="bi bi-server"></i> 5. Registros DNS (DIG)
            </div>
            <div class="card-body p-0">
                <pre class="p-3 m-0"><?= htmlspecialchars($data['Dig'] ?? 'Sin datos DNS.') ?></pre>
            </div>
        </div>

        <div class="card mb-4 shadow-sm border-info">
            <div class="card-header fw-bold">
                <i class="bi bi-patch-check"></i> 6. Candado HTTPS
            </div>
            <div class="card-body">
                <?php pintarCertificadoSsl($data['Certificado'] ?? ''); ?>
            </div>
        </div>

        <div class="card mb-4 shadow-sm border-warning">
            <div class="card-header fw-bold text-dark">
                <i class="bi bi-diagram-3"></i> 7. Variaciones de Dominio (Typosquatting)
            </div>
            <div class="card-body p-0">
                <pre class="p-3 m-0"><?= htmlspecialchars($data['Dnstwist'] ?? 'Sin datos de variaciones.') ?></pre>
            </div>
        </div>
    </div>
    
    <div id="seccion-comentarios" style="display: none;">
        <div class="card mb-4 shadow-sm border-primary">
            <div class="card-header fw-bold d-flex justify-content-between align-items-center flex-wrap gap-2">
                <span><i class="bi bi-chat-dots"></i> 8. Comentarios de la comunidad</span>
                <span class="badge bg-primary rounded-pill"><?= (int)$totalComentarios ?></span>
            </div>
            <div class="card-body">
                <?php if ($totalComentarios > 0): ?>
                    <div class="mb-3">
                        <p class="text-muted mb-3">Observaciones compartidas por la comunidad sobre este dominio.</p>

                        <?php foreach ($comentarios as $comentario): ?>
                            <?php
                            $badgeClass = 'bg-secondary';
                            switch ($comentario['tipo_comentario']) {
                                case 'phishing': $badgeClass = 'bg-danger'; break;
                                case 'malware': $badgeClass = 'bg-dark'; break;
                                case 'spam': $badgeClass = 'bg-warning text-dark'; break;
                                case 'suplantacion': $badgeClass = 'bg-primary'; break;
                                case 'fraude': $badgeClass = 'bg-danger'; break;
                            }
                            ?>
                            <div class="card comentario-card mb-3 shadow-sm">
                                <div class="card-body">
                                    <div class="d-flex justify-content-between align-items-start flex-wrap gap-2 mb-2 comentario-meta">
                                        <div>
                                            <strong><?= htmlspecialchars($comentario['autor_nombre']) ?></strong>
                                            
                                            <?php if (isset($comentario['rol']) && $comentario['rol'] === 'admin'): ?>
                                                <span class="badge badge-admin rounded-pill" title="Administrador de la plataforma">
                                                    <i class="bi bi-shield-fill-check"></i> Admin
                                                </span>
                                            <?php endif; ?>

                                            <span class="badge <?= $badgeClass ?> ms-2">
                                                <?= htmlspecialchars(ucfirst($comentario['tipo_comentario'])) ?>
                                            </span>
                                        </div>
                                        
                                        <div class="d-flex align-items-center gap-2">
                                            <small class="text-muted">
                                                <?= date("d/m/Y H:i", strtotime($comentario['fecha_creacion'])) ?>
                                            </small>

                                            <?php if (isset($_SESSION['rol']) && $_SESSION['rol'] === 'admin'): ?>
                                                <form method="POST" class="m-0 p-0 no-print">
                                                    <?= campoCsrf() ?>
                                                    <input type="hidden" name="id_comentario" value="<?= (int)$comentario['id_comentario'] ?>">
                                                    <input type="hidden" name="token_reporte" value="<?= htmlspecialchars($token_reporte, ENT_QUOTES, 'UTF-8') ?>">
                                                    <button type="submit" name="borrar_comentario" class="btn btn-sm btn-outline-danger py-0 px-2" title="Borrar comentario" onclick="return confirm('¿Seguro que quieres borrar este comentario permanentemente?');">
                                                        <i class="bi bi-trash"></i>
                                                    </button>
                                                </form>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                    <p class="mb-0"><?= nl2br(htmlspecialchars($comentario['comentario'])) ?></p>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <div class="alert alert-light border mb-0">
                        Todavía no hay comentarios de la comunidad para este dominio.
                    </div>
                <?php endif; ?>

                <?php if (isset($_SESSION['id_usuario'])): ?>
                    <div class="separador-formulario no-print">
                        <h5 class="mb-3">Añadir comentario</h5>
                        <p class="text-muted">Comparte una observación útil sobre este dominio para ayudar a otros usuarios.</p>

                        <form action="guardar_comentarios.php" method="POST">
                            <?= campoCsrf() ?>
                            <input type="hidden" name="dominio" value="<?= htmlspecialchars($dominio_actual) ?>">
                            <input type="hidden" name="token_reporte" value="<?= htmlspecialchars($token_reporte, ENT_QUOTES, 'UTF-8') ?>">

                            <div class="mb-3">
                                <label class="form-label">Tipo de comentario</label>
                                <select name="tipo_comentario" class="form-select" required>
                                    <option value="otro">Otro</option>
                                    <option value="phishing">Phishing</option>
                                    <option value="malware">Malware</option>
                                    <option value="spam">Spam</option>
                                    <option value="suplantacion">Suplantación</option>
                                    <option value="fraude">Fraude</option>
                                </select>
                            </div>

                            <div class="mb-3">
                                <label class="form-label">Comentario</label>
                                <textarea name="comentario" class="form-control" rows="4" maxlength="1000" required placeholder="Describe lo que observaste sobre este dominio..."></textarea>
                            </div>

                            <button type="submit" class="btn btn-primary">
                                <i class="bi bi-send"></i> Publicar comentario
                            </button>
                        </form>
                    </div>
                <?php else: ?>
                    <div class="alert alert-warning no-print mt-3 mb-0">
                        <i class="bi bi-lock"></i> Inicia sesión para publicar un comentario en la comunidad.
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div class="text-center mt-4 mb-5 no-print">
        <?php if (isset($_SESSION['id_usuario'])): ?>
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

<script>
    function cambiarPestana(pestana) {
        const seccionAnalisis = document.getElementById('seccion-analisis');
        const seccionComentarios = document.getElementById('seccion-comentarios');
        const btnAnalisis = document.getElementById('btn-analisis');
        const btnComentarios = document.getElementById('btn-comentarios');

        if (pestana === 'analisis') {
            seccionAnalisis.style.display = 'block';
            seccionComentarios.style.display = 'none';
            btnAnalisis.classList.add('activa');
            btnComentarios.classList.remove('activa');
        } else {
            seccionAnalisis.style.display = 'none';
            seccionComentarios.style.display = 'block';
            btnComentarios.classList.add('activa');
            btnAnalisis.classList.remove('activa');
        }
    }
</script>

<?php require_once '../includes/footer.php'; ?>
