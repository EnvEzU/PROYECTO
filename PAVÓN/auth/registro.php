<?php
session_start();
// RUTA CORREGIDA: Apuntando a config
require_once '../config/conexion.php';

$mensaje = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $user  = trim($_POST['usuario']);
    $email = trim($_POST['email']);
    $pass  = md5($_POST['pass']); 

    // Comprobar duplicados
    $sql_check = "SELECT id FROM usuarios WHERE email = ? OR usuario = ?";
    $stmt_check = mysqli_prepare($conn, $sql_check);
    mysqli_stmt_bind_param($stmt_check, "ss", $email, $user);
    mysqli_stmt_execute($stmt_check);
    mysqli_stmt_store_result($stmt_check);

    if (mysqli_stmt_num_rows($stmt_check) > 0) {
        $mensaje = '<div class="alert alert-danger">El usuario o email ya existen.</div>';
    } else {
        $sql_insert = "INSERT INTO usuarios (usuario, email, password, rol) VALUES (?, ?, ?, 'usuario')";
        if ($stmt = mysqli_prepare($conn, $sql_insert)) {
            mysqli_stmt_bind_param($stmt, "sss", $user, $email, $pass);
            if (mysqli_stmt_execute($stmt)) {
                header("Location: login.php?registro=exito");
                exit;
            } else {
                $mensaje = '<div class="alert alert-danger">Error al registrar.</div>';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <title>Registro - OSINT</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark d-flex align-items-center min-vh-100">
    <div class="container" style="max-width: 400px;">
        <div class="card shadow">
            <div class="card-body">
                <h3 class="text-center mb-4">Registro</h3>
                <?= $mensaje ?>
                <form method="POST">
                    <div class="mb-3">
                        <label>Usuario</label>
                        <input type="text" name="usuario" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label>Email</label>
                        <input type="email" name="email" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label>Contraseña</label>
                        <input type="password" name="pass" class="form-control" required>
                    </div>
                    <button type="submit" class="btn btn-success w-100">Registrarse</button>
                    <div class="mt-3 text-center">
                        <a href="login.php">Ya tengo cuenta</a>
                    </div>
                </form>
            </div>
        </div>
    </div>
</body>
</html>