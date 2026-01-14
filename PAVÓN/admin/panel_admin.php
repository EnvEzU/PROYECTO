<?php
// Archivo: admin/panel_admin.php
session_start();
// Ruta para conexión desde carpeta 'admin'
require_once '../config/conexion.php'; 

// Seguridad: Solo admin
if (!isset($_SESSION['rol']) || $_SESSION['rol'] != 'admin') {
    header("Location: ../index.php");
    exit;
}

// Rutas para el header desde carpeta 'admin'
$ruta_base = "../"; 
require_once '../includes/header.php';

// Estadísticas rápidas
$total_users = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as c FROM usuarios"))['c'];
$total_scans = mysqli_fetch_assoc(mysqli_query($conn, "SELECT COUNT(*) as c FROM historial_dominios"))['c'];
?>

<h2 class="mb-4">Panel de Administración</h2>

<div class="row mb-4">
    <div class="col-md-4">
        <div class="card text-bg-primary mb-3">
            <div class="card-body">
                <h5 class="card-title">Usuarios Registrados</h5>
                <p class="card-text display-4"><?= $total_users ?></p>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card text-bg-success mb-3">
            <div class="card-body">
                <h5 class="card-title">Análisis Totales</h5>
                <p class="card-text display-4"><?= $total_scans ?></p>
            </div>
        </div>
    </div>
</div>

<h3>Últimos accesos al sistema</h3>
<table class="table table-striped">
    <thead>
        <tr><th>Usuario</th><th>IP</th><th>Fecha</th></tr>
    </thead>
    <tbody>
        <?php
        $sql = "SELECT u.usuario, h.ip_acceso, h.fecha_acceso 
                FROM historial_accesos h 
                JOIN usuarios u ON h.id_usuario = u.id 
                ORDER BY h.fecha_acceso DESC LIMIT 5";
        $res = mysqli_query($conn, $sql);
        while($row = mysqli_fetch_assoc($res)): ?>
        <tr>
            <td><?= $row['usuario'] ?></td>
            <td><?= $row['ip_acceso'] ?></td>
            <td><?= $row['fecha_acceso'] ?></td>
        </tr>
        <?php endwhile; ?>
    </tbody>
</table>

<?php require_once '../includes/footer.php'; ?>