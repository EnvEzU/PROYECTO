<?php
// Archivo: admin/panel_admin.php
session_start();
require_once '../config/conexion.php'; 

if (!isset($_SESSION['rol']) || $_SESSION['rol'] != 'admin') {
    header("Location: ../index.php"); exit;
}

// Lógica para borrar usuario (RF6)
if(isset($_POST['borrar_user'])) {
    $id_borrar = intval($_POST['id_borrar']);
    if($id_borrar != $_SESSION['id_usuario']) {
        mysqli_query($conn, "DELETE FROM usuarios WHERE id=$id_borrar");
    }
}

$ruta_base = "../"; 
require_once '../includes/header.php';

// Estadísticas
$u_count = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) c FROM usuarios"))['c'];
$d_count = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) c FROM historial_dominios"))['c'];
?>

<h2 class="mb-4">Panel de Administración</h2>

<div class="row mb-4">
    <div class="col-md-6">
        <div class="card text-bg-primary mb-3">
            <div class="card-body">
                <h3><?= $u_count ?></h3> <p>Usuarios</p>
            </div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card text-bg-success mb-3">
            <div class="card-body">
                <h3><?= $d_count ?></h3> <p>Análisis</p>
            </div>
        </div>
    </div>
</div>

<div class="card mb-4">
    <div class="card-header bg-dark text-white">Gestión de Usuarios</div>
    <div class="card-body">
        <table class="table table-sm">
            <thead><tr><th>ID</th><th>Usuario</th><th>Rol</th><th>Acción</th></tr></thead>
            <tbody>
                <?php
                $res = mysqli_query($conn, "SELECT * FROM usuarios");
                while($row = mysqli_fetch_assoc($res)): ?>
                <tr>
                    <td><?= $row['id'] ?></td>
                    <td><?= $row['usuario'] ?></td>
                    <td><span class="badge bg-secondary"><?= $row['rol'] ?></span></td>
                    <td>
                        <?php if($row['id'] != $_SESSION['id_usuario']): ?>
                        <form method="POST" style="display:inline;">
                            <input type="hidden" name="id_borrar" value="<?= $row['id'] ?>">
                            <button type="submit" name="borrar_user" class="btn btn-danger btn-sm" onclick="return confirm('¿Eliminar?');">Borrar</button>
                        </form>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
    </div>
</div>

<div class="card border-danger">
    <div class="card-header bg-danger text-white">Log de Errores</div>
    <div class="card-body">
        <p class="text-muted">Si hubiera errores registrados en la tabla 'errores_sistema', aparecerían aquí.</p>
    </div>
</div>

<?php require_once '../includes/footer.php'; ?>