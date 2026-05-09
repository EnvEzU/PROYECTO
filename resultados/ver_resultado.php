<?php
session_start();
require_once '../config/conexion.php';

$id_hist = 0;

if (isset($_POST['id'])) {
    $id_hist = (int)$_POST['id'];
} elseif (isset($_POST['id_historial'])) {
    $id_hist = (int)$_POST['id_historial'];
} elseif (isset($_GET['id'])) {
    $id_hist = (int)$_GET['id'];
} elseif (isset($_SESSION['ver_id_reporte'])) {
    $id_hist = (int)$_SESSION['ver_id_reporte'];
}

if ($id_hist <= 0) {
    header("Location: ../index.php");
    exit;
}

$_SESSION['ver_id_reporte'] = $id_hist;

// NUEVO: Lógica para que los Administradores puedan borrar comentarios directamente desde aquí
if (isset($_POST['borrar_comentario']) && isset($_SESSION['rol']) && $_SESSION['rol'] === 'admin') {
    $id_borrar_com = (int)$_POST['id_comentario'];
    $stmt_del = mysqli_prepare($conn, "DELETE FROM comentarios_dominios WHERE id = ?");
    mysqli_stmt_bind_param($stmt_del, "i", $id_borrar_com);
    mysqli_stmt_execute($stmt_del);
    mysqli_stmt_close($stmt_del);
    
    // Recargamos la página para limpiar el formulario y actualizar la vista
    header("Location: ver_resultado.php?id=" . $id_hist);
    exit;
}

$mensajeComentario = '';
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
    if ($info['estado'] === 'maliciosa') {
        $alertClass = 'alert-danger';
    } elseif ($info['estado'] === 'sospechosa') {
        $alertClass = 'alert-warning';
    }
    ?>

    <div class="alert <?= $alertClass ?> text-center shadow-sm border-2">
        <h3 class="mb-1">DICTAMEN DE SEGURIDAD: <?= strtoupper(htmlspecialchars($info['estado'])) ?></h3>
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

        <div class="card mb-4 shadow-sm border-warning">
            <div class="card-header fw-bold text-dark">
                <i class="bi bi-diagram-3"></i> 6. Variaciones de Dominio (Typosquatting)
            </div>
            <div class="card-body p-0">
                <pre class="p-3 m-0"><?= htmlspecialchars($data['Dnstwist'] ?? 'Sin datos de variaciones.') ?></pre>
            </div>
        </div>
    </div>
    
    <div id="seccion-comentarios" style="display: none;">
        <div class="card mb-4 shadow-sm border-primary">
            <div class="card-header fw-bold d-flex justify-content-between align-items-center flex-wrap gap-2">
                <span><i class="bi bi-chat-dots"></i> 7. Comentarios de la comunidad</span>
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
                                                    <input type="hidden" name="id_comentario" value="<?= (int)$comentario['id_comentario'] ?>">
                                                    <input type="hidden" name="id" value="<?= (int)$id_hist ?>">
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
                            <input type="hidden" name="dominio" value="<?= htmlspecialchars($dominio_actual) ?>">
                            <input type="hidden" name="id_historial" value="<?= (int)$id_hist ?>">

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