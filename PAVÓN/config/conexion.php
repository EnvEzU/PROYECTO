<?php
// Archivo: config/conexion.php

$servidor   = "localhost";
$usuario    = "root";         // Usuario de XAMPP por defecto
$password   = "";             // Contraseña vacía por defecto
$base_datos = "virustotal_osint";

$conn = mysqli_connect($servidor, $usuario, $password, $base_datos);

// Verificar conexión
if (!$conn) {
    // En producción no se debe mostrar el error exacto, pero para desarrollo (TFG) está bien.
    die("Error crítico de conexión: " . mysqli_connect_error());
}

// Forzar UTF-8 para evitar problemas con tildes y ñ
mysqli_set_charset($conn, "utf8mb4");
?>