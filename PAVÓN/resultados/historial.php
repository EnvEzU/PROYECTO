<?php
// Archivo: resultados/historial.php
session_start();
require_once '../config/conexion.php';

// Seguridad: Solo usuarios registrados
if (!isset($_SESSION['id_usuario'])) {
    header("Location: ../auth/login.php");
    exit;
}

$id_usuario = $_SESSION['id_usuario'];

// Consulta: Obtener análisis de ESTE usuario ordenados por fecha
$sql = "SELECT * FROM historial_dominios WHERE id_usuario = ? ORDER BY fecha_escaneo DESC";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "i", $id_usuario);
mysqli_stmt_execute($stmt);
$resultado = mysqli_stmt_get_result($stmt);

// Configuración ruta
$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="bi bi-clock-history"></i> Mi Historial de Análisis</h2>
    <a href="../osint/analizar_url.php" class="btn btn-primary">
        <i class="bi bi-plus-circle"></i> Nuevo Análisis
    </a>
</div>

<div class="card shadow-sm">
    <div class="card-body p-0">
        <div class="table-responsive">
            <table class="table table-hover table-striped mb-0 align-middle">
                <thead class="table-dark">
                    <tr>
                        <th>Dominio</th>
                        <th>Estado</th>
                        <th>Fecha</th>
                        <th class="text-end">Acciones</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (mysqli_num_rows($resultado) > 0): ?>
                        <?php while ($fila = mysqli_fetch_assoc($resultado)): ?>
                            <tr>
                                <td class="fw-bold"><?= htmlspecialchars($fila['dominio']) ?></td>
                                <td>
                                    <?php if ($fila['estado'] == 'maliciosa'): ?>
                                        <span class="badge bg-danger">Maliciosa</span>
                                    <?php elseif ($fila['estado'] == 'segura'): ?>
                                        <span class="badge bg-success">Segura</span>
                                    <?php else: ?>
                                        <span class="badge bg-warning text-dark">Sospechosa</span>
                                    <?php endif; ?>
                                </td>
                                <td><?= date("d/m/Y H:i", strtotime($fila['fecha_escaneo'])) ?></td>
                                <td class="text-end">
                                    <a href="ver_resultado.php?id=<?= $fila['id'] ?>" class="btn btn-sm btn-outline-primary">
                                        <i class="bi bi-eye"></i> Ver Informe
                                    </a>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="4" class="text-center py-5 text-muted">
                                No has realizado ningún análisis todavía.
                            </td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<?php require_once '../includes/footer.php'; ?>