<?php
session_start();
require_once '../config/conexion.php';

if (!isset($_SESSION['rol']) || $_SESSION['rol'] !== 'admin') {
    header("Location: ../index.php");
    exit;
}

$mensaje = "";

// Borrar usuario
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['borrar_user'])) {
    $id_borrar = (int)($_POST['id_borrar'] ?? 0);

    if ($id_borrar > 0 && $id_borrar !== (int)$_SESSION['id_usuario']) {
        $stmt = mysqli_prepare($conn, "DELETE FROM usuarios WHERE id = ?");
        mysqli_stmt_bind_param($stmt, "i", $id_borrar);

        if (mysqli_stmt_execute($stmt)) {
            $mensaje = '<div class="alert alert-success">Usuario eliminado correctamente.</div>';
        } else {
            $mensaje = '<div class="alert alert-danger">No se pudo eliminar el usuario.</div>';
        }

        mysqli_stmt_close($stmt);
    } else {
        $mensaje = '<div class="alert alert-warning">No puedes eliminar tu propio usuario.</div>';
    }
}

// Editar usuario
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['editar_user'])) {
    $id_editar = (int)$_POST['id_editar'];
    $nuevo_nombre = trim($_POST['nuevo_nombre']);
    $nuevo_email = trim($_POST['nuevo_email']);
    $nuevo_rol = trim($_POST['nuevo_rol']);

    if ($id_editar > 0 && !empty($nuevo_nombre) && !empty($nuevo_email)) {
        $stmt_update = mysqli_prepare($conn, "UPDATE usuarios SET usuario = ?, email = ?, rol = ? WHERE id = ?");
        mysqli_stmt_bind_param($stmt_update, "sssi", $nuevo_nombre, $nuevo_email, $nuevo_rol, $id_editar);
        
        if (mysqli_stmt_execute($stmt_update)) {
            $mensaje = '<div class="alert alert-success">Usuario actualizado correctamente.</div>';
        } else {
            $mensaje = '<div class="alert alert-danger">Error al actualizar la información del usuario.</div>';
        }
        mysqli_stmt_close($stmt_update);
    }
}

// Estadísticas
$u_count = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) AS c FROM usuarios"))['c'] ?? 0;
$d_count = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) AS c FROM historial_dominios"))['c'] ?? 0;
$mal_count = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) AS c FROM historial_dominios WHERE estado = 'maliciosa'"))['c'] ?? 0;
$sos_count = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) AS c FROM historial_dominios WHERE estado = 'sospechosa'"))['c'] ?? 0;
$com_count = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) AS c FROM comentarios_dominios"))['c'] ?? 0;

// Usuarios
$usuarios = mysqli_query($conn, "SELECT id, usuario, email, rol FROM usuarios ORDER BY id DESC");

// Últimos análisis
$analisis = mysqli_query($conn, "
    SELECT h.id, h.dominio, h.estado, h.fecha_escaneo, u.usuario
    FROM historial_dominios h
    LEFT JOIN usuarios u ON h.id_usuario = u.id
    ORDER BY h.id DESC
    LIMIT 10
");

$ruta_base = "../";
require_once '../includes/header.php';
?>

<div class="container mt-4 mb-5">
    <div class="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-2">
        <div>
            <h2 class="mb-1">Panel de Administración</h2>
            <p class="text-muted mb-0">Gestión general de usuarios, análisis y comentarios de comunidad</p>
        </div>
        <a href="../index.php" class="btn btn-outline-secondary">
            <i class="bi bi-house"></i> Volver al inicio
        </a>
    </div>

    <?= $mensaje ?>

    <div class="row g-3 mb-4">
        <div class="col-md-6 col-xl-2">
            <div class="card text-bg-primary shadow-sm h-100">
                <div class="card-body">
                    <div class="small text-white-50">Usuarios</div>
                    <h3 class="mb-0"><?= (int)$u_count ?></h3>
                </div>
            </div>
        </div>

        <div class="col-md-6 col-xl-2">
            <div class="card text-bg-success shadow-sm h-100">
                <div class="card-body">
                    <div class="small text-white-50">Análisis</div>
                    <h3 class="mb-0"><?= (int)$d_count ?></h3>
                </div>
            </div>
        </div>

        <div class="col-md-6 col-xl-2">
            <div class="card text-bg-danger shadow-sm h-100">
                <div class="card-body">
                    <div class="small text-white-50">Maliciosos</div>
                    <h3 class="mb-0"><?= (int)$mal_count ?></h3>
                </div>
            </div>
        </div>

        <div class="col-md-6 col-xl-2">
            <div class="card text-bg-warning shadow-sm h-100">
                <div class="card-body">
                    <div class="small text-dark">Sospechosos</div>
                    <h3 class="mb-0 text-dark"><?= (int)$sos_count ?></h3>
                </div>
            </div>
        </div>

        <div class="col-md-6 col-xl-2">
            <div class="card text-bg-dark shadow-sm h-100">
                <div class="card-body">
                    <div class="small text-white-50">Comentarios</div>
                    <h3 class="mb-0"><?= (int)$com_count ?></h3>
                </div>
            </div>
        </div>
    </div>

    <div class="card mb-4 shadow-sm">
        <div class="card-header bg-dark text-white fw-bold">
            <i class="bi bi-people"></i> Gestión de Usuarios
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-hover align-middle">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Usuario</th>
                            <th>Email</th>
                            <th>Rol</th>
                            <th class="text-end">Acción</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ($usuarios && mysqli_num_rows($usuarios) > 0): ?>
                            <?php while ($row = mysqli_fetch_assoc($usuarios)): ?>
                                <tr>
                                    <td><?= (int)$row['id'] ?></td>
                                    <td><?= htmlspecialchars($row['usuario']) ?></td>
                                    <td><?= htmlspecialchars($row['email']) ?></td>
                                    <td>
                                        <span class="badge <?= $row['rol'] === 'admin' ? 'bg-danger' : 'bg-secondary' ?>">
                                            <?= htmlspecialchars($row['rol']) ?>
                                        </span>
                                    </td>
                                    <td class="text-end">
                                        <div class="d-inline-flex gap-2 justify-content-end align-items-center">
                                            
                                            <button type="button" class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#editModal<?= $row['id'] ?>">
                                                <i class="bi bi-pencil-square"></i> Editar
                                            </button>

                                            <?php if ((int)$row['id'] !== (int)$_SESSION['id_usuario']): ?>
                                                <form method="POST" class="m-0">
                                                    <input type="hidden" name="id_borrar" value="<?= (int)$row['id'] ?>">
                                                    <button type="submit" name="borrar_user" class="btn btn-danger btn-sm" onclick="return confirm('¿Seguro que quieres eliminar este usuario?');">
                                                        <i class="bi bi-trash"></i> Borrar
                                                    </button>
                                                </form>
                                            <?php else: ?>
                                                <span class="text-muted small">Sesión actual</span>
                                            <?php endif; ?>
                                        </div>
                                    </td>
                                </tr>

                                <div class="modal fade" id="editModal<?= $row['id'] ?>" tabindex="-1" aria-hidden="true">
                                    <div class="modal-dialog">
                                        <div class="modal-content text-start">
                                            <div class="modal-header">
                                                <h5 class="modal-title">Editar Usuario</h5>
                                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                            </div>
                                            <form method="POST">
                                                <div class="modal-body">
                                                    <input type="hidden" name="id_editar" value="<?= (int)$row['id'] ?>">
                                                    
                                                    <div class="mb-3">
                                                        <label class="form-label">Nombre de Usuario</label>
                                                        <input type="text" name="nuevo_nombre" class="form-control" value="<?= htmlspecialchars($row['usuario']) ?>" required>
                                                    </div>
                                                    
                                                    <div class="mb-3">
                                                        <label class="form-label">Correo Electrónico</label>
                                                        <input type="email" name="nuevo_email" class="form-control" value="<?= htmlspecialchars($row['email']) ?>" required>
                                                    </div>
                                                    
                                                    <div class="mb-3">
                                                        <label class="form-label">Rol del Usuario</label>
                                                        <select name="nuevo_rol" class="form-select" <?= ($row['id'] == $_SESSION['id_usuario']) ? 'disabled' : '' ?>>
                                                            <option value="usuario" <?= ($row['rol'] === 'usuario') ? 'selected' : '' ?>>Usuario</option>
                                                            <option value="admin" <?= ($row['rol'] === 'admin') ? 'selected' : '' ?>>Admin</option>
                                                        </select>
                                                        <?php if ($row['id'] == $_SESSION['id_usuario']): ?>
                                                            <small class="text-muted d-block mt-1">No puedes cambiar tu propio rol.</small>
                                                            <input type="hidden" name="nuevo_rol" value="<?= htmlspecialchars($row['rol']) ?>">
                                                        <?php endif; ?>
                                                    </div>
                                                </div>
                                                <div class="modal-footer">
                                                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                                                    <button type="submit" name="editar_user" class="btn btn-primary">Guardar Cambios</button>
                                                </div>
                                            </form>
                                        </div>
                                    </div>
                                </div>
                                <?php endwhile; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="5" class="text-center text-muted">No hay usuarios registrados.</td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="card mb-4 shadow-sm">
        <div class="card-header bg-primary text-white fw-bold">
            <i class="bi bi-bar-chart"></i> Últimos análisis realizados
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-hover align-middle">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Dominio</th>
                            <th>Estado</th>
                            <th>Usuario</th>
                            <th>Fecha</th>
                            <th class="text-end">Ver</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ($analisis && mysqli_num_rows($analisis) > 0): ?>
                            <?php while ($row = mysqli_fetch_assoc($analisis)): ?>
                                <?php
                                $badgeEstado = 'bg-success';
                                if ($row['estado'] === 'maliciosa') {
                                    $badgeEstado = 'bg-danger';
                                } elseif ($row['estado'] === 'sospechosa') {
                                    $badgeEstado = 'bg-warning text-dark';
                                }
                                ?>
                                <tr>
                                    <td><?= (int)$row['id'] ?></td>
                                    <td><?= htmlspecialchars($row['dominio']) ?></td>
                                    <td><span class="badge <?= $badgeEstado ?>"><?= htmlspecialchars($row['estado']) ?></span></td>
                                    <td><?= htmlspecialchars($row['usuario'] ?? 'Anónimo') ?></td>
                                    <td><?= !empty($row['fecha_escaneo']) ? date("d/m/Y H:i", strtotime($row['fecha_escaneo'])) : '-' ?></td>
                                    <td class="text-end">
                                        <a href="../resultados/ver_resultado.php?id=<?= (int)$row['id'] ?>" class="btn btn-outline-primary btn-sm">
                                            <i class="bi bi-eye"></i> Ver
                                        </a>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="6" class="text-center text-muted">No hay análisis registrados.</td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<?php require_once '../includes/footer.php'; ?>