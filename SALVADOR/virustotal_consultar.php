<?php

$apiKey = "9e317a0117464d2b99396fcb00391bc06f54cb4577b7b638545a4b7bd17273b0";
$urlAnalizar = "http://malware.wicar.org/";

// ID de la URL (base64, si no virustotal no puede analizarla)"
$url_id = rtrim(strtr(base64_encode($urlAnalizar), '+/', '-_'), '='); 

/*Base64 usa caracteres + y / que pueden dar problemas en URLs.
Esta parte los reemplaza por: 
+ -> -  
/ -> _ 
*/ 

$endpoint = "https://www.virustotal.com/api/v3/urls/$url_id";

$resultados = curl_init();
curl_setopt_array($resultados, [
    CURLOPT_URL => $endpoint,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER => [
        "x-apikey: $apiKey"
    ]
]);         

$respuesta = curl_exec($resultados);
curl_close($resultados);

$datos = json_decode($respuesta, true);
/*Virus total devuelve la información en una cadena json por lo que hay que decodificarla para convertirla en un valor php*/

// Resultados importantes
$estadisticas = $datos['data']['attributes']['last_analysis_stats'];

echo "<pre>";
print_r($estadisticas);
echo "</pre>";
