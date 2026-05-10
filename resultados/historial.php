<?php
session_start();
require_once '../config/conexion.php';
require_once '../includes/seguridad.php';

asegurarColumnaAnalisisCompleto($conn);
limpiarAnalisisIncompletosAntiguos($conn, 60);

if (!isset($_SESSION['id_usuario'])) {
    header("Location: ../auth/login.php");
    exit;
}

$id_usuario = (int)$_SESSION['id_usuario'];

$sql = "SELECT id, token_publico, dominio, estado, fecha_escaneo, detalles 
        FROM historial_dominios 
        WHERE id_usuario = ?
          AND analisis_completo = 1
        ORDER BY fecha_escaneo DESC, id DESC";

$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "i", $id_usuario);
mysqli_stmt_execute($stmt);
$resultado = mysqli_stmt_get_result($stmt);

$totalAnalisis = 0;
$filas = [];

while ($fila = mysqli_fetch_assoc($resultado)) {
    $filas[] = $fila;
}

$totalAnalisis = count($filas);

mysqli_stmt_close($stmt);

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="container mt-4 mb-5">
    <div class="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-2">
        <div>
            <h2 class="mb-1"><i class="bi bi-clock-history"></i> Mi Historial de Análisis</h2>
            <p class="text-muted mb-0">Consulta los dominios que has analizado y accede a sus informes técnicos.</p>
        </div>

        <a href="../osint/analizar_url.php" class="btn btn-primary">
            <i class="bi bi-plus-circle"></i> Nuevo análisis
        </a>
    </div>

    <div class="row g-3 mb-4">
        <div class="col-md-4">
            <div class="card text-bg-primary shadow-sm h-100">
                <div class="card-body">
                    <div class="small text-white-50">Total de análisis</div>
                    <h3 class="mb-0"><?= (int)$totalAnalisis ?></h3>
                </div>
            </div>
        </div>
    </div>

    <div class="card shadow-sm border-0">
        <div class="card-header bg-dark text-white fw-bold">
            <i class="bi bi-list-ul"></i> Resultados guardados
        </div>
        <div class="card-body p-0">
            <div class="table-responsive">
                <table class="table table-hover table-striped mb-0 align-middle">
                    <thead class="table-light">
                        <tr>
                            <th>Dominio</th>
                            <th>Estado</th>
                            <th>Fecha</th>
                            <th>Detalle</th>
                            <th class="text-end">Acciones</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ($totalAnalisis > 0): ?>
                            <?php foreach ($filas as $fila): ?>
                                <?php
                                $badgeClass = 'bg-warning text-dark';
                                $estadoTexto = 'Sospechosa';

                                if ($fila['estado'] === 'maliciosa') {
                                    $badgeClass = 'bg-danger';
                                    $estadoTexto = 'Maliciosa';
                                } elseif ($fila['estado'] === 'segura') {
                                    $badgeClass = 'bg-success';
                                    $estadoTexto = 'Segura';
                                } elseif ($fila['estado'] === 'no_concluyente') {
                                    $badgeClass = 'bg-secondary';
                                    $estadoTexto = 'No concluyente';
                                }
                                ?>
                                <tr>
                                    <td class="fw-bold"><?= htmlspecialchars($fila['dominio']) ?></td>
                                    <td>
                                        <span class="badge <?= $badgeClass ?>">
                                            <?= htmlspecialchars($estadoTexto) ?>
                                        </span>
                                    </td>
                                    <td>
                                        <?= !empty($fila['fecha_escaneo']) ? date("d/m/Y H:i", strtotime($fila['fecha_escaneo'])) : '-' ?>
                                    </td>
                                    <td>
                                        <?= htmlspecialchars(mb_strimwidth((string)($fila['detalles'] ?? ''), 0, 60, '...')) ?>
                                    </td>
                                    <td class="text-end">
                                        <a href="<?= htmlspecialchars(urlInformeAnalisis($conn, (int)$fila['id']), ENT_QUOTES, 'UTF-8') ?>" class="btn btn-sm btn-outline-primary">
                                            <i class="bi bi-eye"></i> Ver informe
                                        </a>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="5" class="text-center py-5 text-muted">
                                    <div class="mb-2">
                                        <i class="bi bi-search fs-2"></i>
                                    </div>
                                    No has realizado ningún análisis todavía.
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<?php require_once '../includes/footer.php'; ?>