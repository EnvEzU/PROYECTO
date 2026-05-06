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

// Ocultar comentario
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ocultar_comentario'])) {
    $id_comentario = (int)($_POST['id_comentario'] ?? 0);

    if ($id_comentario > 0) {
        $stmt = mysqli_prepare($conn, "UPDATE comentarios_dominios SET estado = 'oculto' WHERE id = ?");
        mysqli_stmt_bind_param($stmt, "i", $id_comentario);

        if (mysqli_stmt_execute($stmt)) {
            $mensaje = '<div class="alert alert-success">Comentario ocultado correctamente.</div>';
        } else {
            $mensaje = '<div class="alert alert-danger">No se pudo ocultar el comentario.</div>';
        }

        mysqli_stmt_close($stmt);
    }
}

// Aprobar comentario
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['aprobar_comentario'])) {
    $id_comentario = (int)($_POST['id_comentario'] ?? 0);

    if ($id_comentario > 0) {
        $stmt = mysqli_prepare($conn, "UPDATE comentarios_dominios SET estado = 'aprobado' WHERE id = ?");
        mysqli_stmt_bind_param($stmt, "i", $id_comentario);

        if (mysqli_stmt_execute($stmt)) {
            $mensaje = '<div class="alert alert-success">Comentario aprobado correctamente.</div>';
        } else {
            $mensaje = '<div class="alert alert-danger">No se pudo aprobar el comentario.</div>';
        }

        mysqli_stmt_close($stmt);
    }
}

// Borrar comentario
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['borrar_comentario'])) {
    $id_comentario = (int)($_POST['id_comentario'] ?? 0);

    if ($id_comentario > 0) {
        $stmt = mysqli_prepare($conn, "DELETE FROM comentarios_dominios WHERE id = ?");
        mysqli_stmt_bind_param($stmt, "i", $id_comentario);

        if (mysqli_stmt_execute($stmt)) {
            $mensaje = '<div class="alert alert-success">Comentario eliminado correctamente.</div>';
        } else {
            $mensaje = '<div class="alert alert-danger">No se pudo eliminar el comentario.</div>';
        }

        mysqli_stmt_close($stmt);
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

// Comentarios recientes
$comentarios = mysqli_query($conn, "
    SELECT id, dominio, autor_nombre, tipo_comentario, estado, fecha_creacion, comentario
    FROM comentarios_dominios
    ORDER BY id DESC
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
                                        <?php if ((int)$row['id'] !== (int)$_SESSION['id_usuario']): ?>
                                            <form method="POST" class="d-inline">
                                                <input type="hidden" name="id_borrar" value="<?= (int)$row['id'] ?>">
                                                <button type="submit" name="borrar_user" class="btn btn-danger btn-sm" onclick="return confirm('¿Seguro que quieres eliminar este usuario?');">
                                                    <i class="bi bi-trash"></i> Borrar
                                                </button>
                                            </form>
                                        <?php else: ?>
                                            <span class="text-muted small">Sesión actual</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
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

    <div class="card mb-4 shadow-sm">
        <div class="card-header bg-warning text-dark fw-bold">
            <i class="bi bi-chat-dots"></i> Moderación de comentarios
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-hover align-middle">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Dominio</th>
                            <th>Autor</th>
                            <th>Tipo</th>
                            <th>Estado</th>
                            <th>Fecha</th>
                            <th>Comentario</th>
                            <th class="text-end">Acciones</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ($comentarios && mysqli_num_rows($comentarios) > 0): ?>
                            <?php while ($row = mysqli_fetch_assoc($comentarios)): ?>
                                <tr>
                                    <td><?= (int)$row['id'] ?></td>
                                    <td><?= htmlspecialchars($row['dominio']) ?></td>
                                    <td><?= htmlspecialchars($row['autor_nombre']) ?></td>
                                    <td>
                                        <span class="badge bg-secondary"><?= htmlspecialchars($row['tipo_comentario']) ?></span>
                                    </td>
                                    <td>
                                        <?php
                                        $badgeComentario = 'bg-secondary';
                                        if ($row['estado'] === 'aprobado') {
                                            $badgeComentario = 'bg-success';
                                        } elseif ($row['estado'] === 'oculto') {
                                            $badgeComentario = 'bg-danger';
                                        } elseif ($row['estado'] === 'pendiente') {
                                            $badgeComentario = 'bg-warning text-dark';
                                        }
                                        ?>
                                        <span class="badge <?= $badgeComentario ?>"><?= htmlspecialchars($row['estado']) ?></span>
                                    </td>
                                    <td><?= !empty($row['fecha_creacion']) ? date("d/m/Y H:i", strtotime($row['fecha_creacion'])) : '-' ?></td>
                                    <td style="min-width: 260px; max-width: 360px;">
                                        <?= nl2br(htmlspecialchars(mb_strimwidth($row['comentario'], 0, 180, '...'))) ?>
                                    </td>
                                    <td class="text-end">
                                        <div class="d-flex flex-wrap justify-content-end gap-2">
                                            <form method="POST" class="d-inline">
                                                <input type="hidden" name="id_comentario" value="<?= (int)$row['id'] ?>">
                                                <button type="submit" name="aprobar_comentario" class="btn btn-success btn-sm">
                                                    <i class="bi bi-check-circle"></i>
                                                </button>
                                            </form>

                                            <form method="POST" class="d-inline">
                                                <input type="hidden" name="id_comentario" value="<?= (int)$row['id'] ?>">
                                                <button type="submit" name="ocultar_comentario" class="btn btn-warning btn-sm">
                                                    <i class="bi bi-eye-slash"></i>
                                                </button>
                                            </form>

                                            <form method="POST" class="d-inline">
                                                <input type="hidden" name="id_comentario" value="<?= (int)$row['id'] ?>">
                                                <button type="submit" name="borrar_comentario" class="btn btn-danger btn-sm" onclick="return confirm('¿Seguro que quieres eliminar este comentario?');">
                                                    <i class="bi bi-trash"></i>
                                                </button>
                                            </form>
                                        </div>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="8" class="text-center text-muted">No hay comentarios registrados.</td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="card border-danger shadow-sm">
        <div class="card-header bg-danger text-white fw-bold">
            <i class="bi bi-exclamation-triangle"></i> Log de Errores
        </div>
        <div class="card-body">
            <p class="text-muted mb-0">
                Si más adelante registráis errores en la tabla <code>errores_sistema</code>, podéis mostrarlos aquí.
            </p>
        </div>
    </div>
</div>

<?php require_once '../includes/footer.php'; ?>