<?php
// Archivo: auth/logout.php
session_start();

// Destruir todas las variables de sesión
$_SESSION = array();

// Borrar la cookie de sesión si existe (limpieza profunda)
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// Destruir la sesión completamente
session_destroy();

// CAMBIO: Redirigir al inicio (index.php) en lugar del login
header("Location: ../index.php");
exit;
?>