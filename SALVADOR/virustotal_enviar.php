<?php

$apiKey = "9e317a0117464d2b99396fcb00391bc06f54cb4577b7b638545a4b7bd17273b0";
$urlAnalizar = "http://malware.wicar.org/";

$endpoint = "https://www.virustotal.com/api/v3/urls";

// VirusTotal requiere la URL codificada en base64
$url_id = rtrim(strtr(base64_encode($urlAnalizar), '+/', '-_'), '=');

$resultados = curl_init();
curl_setopt_array($resultados, [
    CURLOPT_URL => $endpoint,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST => true,
    CURLOPT_HTTPHEADER => [
        "x-apikey: $apiKey",
        "Content-Type: application/x-www-form-urlencoded"
    ],
    CURLOPT_POSTFIELDS => "url=" . urlencode($urlAnalizar)
]);

$respuesta = curl_exec($resultados);
curl_close($resultados);

$datos = json_decode($respuesta, true);

// ID del análisis
$analisis = $datos['data']['id'] ?? null;

echo "ID de análisis: " . $analisis;
