<?php
session_start();
require_once '../config/conexion.php';

$mensaje = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $user  = trim($_POST['usuario'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $pass  = $_POST['pass'] ?? '';

    if ($user === '' || $email === '' || $pass === '') {
        $mensaje = '<div class="alert alert-danger">Debes completar todos los campos.</div>';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $mensaje = '<div class="alert alert-danger">Introduce un email válido.</div>';
    } elseif (strlen($user) < 3) {
        $mensaje = '<div class="alert alert-danger">El usuario debe tener al menos 3 caracteres.</div>';
    } elseif (strlen($pass) < 4) {
        $mensaje = '<div class="alert alert-danger">La contraseña debe tener al menos 4 caracteres.</div>';
    } else {
        $sql_check = "SELECT id FROM usuarios WHERE email = ? OR usuario = ?";
        if ($stmt_check = mysqli_prepare($conn, $sql_check)) {
            mysqli_stmt_bind_param($stmt_check, "ss", $email, $user);
            mysqli_stmt_execute($stmt_check);
            mysqli_stmt_store_result($stmt_check);

            if (mysqli_stmt_num_rows($stmt_check) > 0) {
                $mensaje = '<div class="alert alert-danger">El usuario o email ya existen.</div>';
            } else {
                $hash = password_hash($pass, PASSWORD_DEFAULT);

                $sql_insert = "INSERT INTO usuarios (usuario, email, password, rol) VALUES (?, ?, ?, 'usuario')";
                if ($stmt = mysqli_prepare($conn, $sql_insert)) {
                    mysqli_stmt_bind_param($stmt, "sss", $user, $email, $hash);

                    if (mysqli_stmt_execute($stmt)) {
                        mysqli_stmt_close($stmt);
                        mysqli_stmt_close($stmt_check);
                        header("Location: login.php?registro=exito");
                        exit;
                    } else {
                        $mensaje = '<div class="alert alert-danger">Error al registrar el usuario.</div>';
                        mysqli_stmt_close($stmt);
                    }
                } else {
                    $mensaje = '<div class="alert alert-danger">Error interno al preparar el registro.</div>';
                }
            }

            mysqli_stmt_close($stmt_check);
        } else {
            $mensaje = '<div class="alert alert-danger">Error interno al comprobar duplicados.</div>';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Registro - OSINT</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark d-flex align-items-center min-vh-100">
    <div class="container" style="max-width: 400px;">
        <div class="card shadow border-0">
            <div class="card-body p-4">
                <h3 class="text-center mb-4">Registro</h3>

                <?= $mensaje ?>

                <form method="POST" autocomplete="off">
                    <div class="mb-3">
                        <label class="form-label">Usuario</label>
                        <input type="text" name="usuario" class="form-control" required>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Email</label>
                        <input type="email" name="email" class="form-control" required>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Contraseña</label>
                        <input type="password" name="pass" class="form-control" placeholder="1234" required>
                        <div class="form-text">Mínimo 4 caracteres.</div>
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