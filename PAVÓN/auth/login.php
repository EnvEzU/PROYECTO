<?php
session_start();
require_once '../config/conexion.php';

$mensaje = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $email = trim($_POST['email'] ?? '');
    $pass  = $_POST['pass'] ?? '';

    if ($email === '' || $pass === '') {
        $mensaje = '<div class="alert alert-danger">Debes completar todos los campos.</div>';
    } else {
        $sql = "SELECT id, usuario, rol, password FROM usuarios WHERE email = ? LIMIT 1";

        if ($stmt = mysqli_prepare($conn, $sql)) {
            mysqli_stmt_bind_param($stmt, "s", $email);
            mysqli_stmt_execute($stmt);
            $resultado = mysqli_stmt_get_result($stmt);

            if ($fila = mysqli_fetch_assoc($resultado)) {
                $login_ok = false;

                // Caso nuevo: contraseña con password_hash()
                if (password_verify($pass, $fila['password'])) {
                    $login_ok = true;
                }
                // Compatibilidad con contraseñas antiguas en MD5
                elseif (md5($pass) === $fila['password']) {
                    $login_ok = true;

                    // Migrar automáticamente a password_hash()
                    $nuevo_hash = password_hash($pass, PASSWORD_DEFAULT);
                    if ($stmt_update = mysqli_prepare($conn, "UPDATE usuarios SET password = ? WHERE id = ?")) {
                        mysqli_stmt_bind_param($stmt_update, "si", $nuevo_hash, $fila['id']);
                        mysqli_stmt_execute($stmt_update);
                        mysqli_stmt_close($stmt_update);
                    }
                }

                if ($login_ok) {
                    session_regenerate_id(true);

                    $_SESSION['id_usuario'] = (int)$fila['id'];
                    $_SESSION['usuario']    = $fila['usuario'];
                    $_SESSION['rol']        = $fila['rol'];

                    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
                    if ($stmt_aud = mysqli_prepare($conn, "INSERT INTO historial_accesos (id_usuario, ip_acceso) VALUES (?, ?)")) {
                        mysqli_stmt_bind_param($stmt_aud, "is", $fila['id'], $ip);
                        mysqli_stmt_execute($stmt_aud);
                        mysqli_stmt_close($stmt_aud);
                    }

                    if ($fila['rol'] === 'admin') {
                        header("Location: ../admin/panel_admin.php");
                    } else {
                        header("Location: ../index.php");
                    }
                    exit;
                } else {
                    $mensaje = '<div class="alert alert-danger">Usuario o contraseña incorrectos.</div>';
                }
            } else {
                $mensaje = '<div class="alert alert-danger">Usuario o contraseña incorrectos.</div>';
            }

            mysqli_stmt_close($stmt);
        } else {
            $mensaje = '<div class="alert alert-danger">Error interno al preparar la consulta.</div>';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login - VirusTotal OSINT</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark d-flex align-items-center min-vh-100">
    <div class="container" style="max-width: 400px;">
        <div class="card shadow border-0">
            <div class="card-body p-4">
                <h3 class="text-center mb-4">Iniciar sesión</h3>

                <?= $mensaje ?>

                <form method="POST" autocomplete="off">
                    <div class="mb-3">
                        <label class="form-label">Email</label>
                        <input type="email" name="email" class="form-control" placeholder="admin@test.com" required>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Contraseña</label>
                        <input type="password" name="pass" class="form-control" placeholder="1234" required>
                    </div>

                    <button type="submit" class="btn btn-primary w-100">Entrar</button>

                    <div class="mt-3 text-center">
                        <a href="registro.php">Crear cuenta</a>
                    </div>
                </form>
            </div>
        </div>
    </div>
</body>
</html>