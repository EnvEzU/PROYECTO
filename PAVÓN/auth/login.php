<?php
session_start();
// RUTA CORREGIDA: Salir de 'auth', entrar en 'config', buscar 'conexion.php'
require_once '../config/conexion.php'; 

$mensaje = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = trim($_POST['email']);
    $pass  = $_POST['pass']; 
    $pass_md5 = md5($pass);

    $sql = "SELECT id, usuario, rol FROM usuarios WHERE email = ? AND password = ?";
    
    if ($stmt = mysqli_prepare($conn, $sql)) {
        mysqli_stmt_bind_param($stmt, "ss", $email, $pass_md5);
        mysqli_stmt_execute($stmt);
        $resultado = mysqli_stmt_get_result($stmt);

        if ($fila = mysqli_fetch_assoc($resultado)) {
            $_SESSION['id_usuario'] = $fila['id'];
            $_SESSION['usuario']    = $fila['usuario'];
            $_SESSION['rol']        = $fila['rol'];

            // Auditoría
            $ip = $_SERVER['REMOTE_ADDR'];
            mysqli_query($conn, "INSERT INTO historial_accesos (id_usuario, ip_acceso) VALUES ({$fila['id']}, '$ip')");

            if ($fila['rol'] == 'admin') {
                header("Location: ../admin/panel_admin.php"); 
            } else {
                header("Location: ../index.php");
            }
            exit;
        } else {
            $mensaje = '<div class="alert alert-danger">Usuario o contraseña incorrectos</div>';
        }
        mysqli_stmt_close($stmt);
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <title>Login - VirusTotal OSINT</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-dark d-flex align-items-center min-vh-100">
    <div class="container" style="max-width: 400px;">
        <div class="card shadow">
            <div class="card-body">
                <h3 class="text-center mb-4">Iniciar sesión</h3>
                <?= $mensaje ?>
                <form method="POST">
                    <div class="mb-3">
                        <label>Email</label>
                        <input type="email" name="email" class="form-control" placeholder="admin@test.com" required>
                    </div>
                    <div class="mb-3">
                        <label>Contraseña</label>
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