<?php

    /* Connexion à une base MySQL avec l'invocation de pilote */
    $dsn = 'mysql:dbname=mexico_authentication;host=127.0.0.1;port=3306';
    $user = 'root';
    $password = '';

    // Essaye
    try 
    {
        // D'établir une connexion à la base de données.
        // Si ça fonctionne, tant mieux!
        $db = new PDO($dsn, $user, $password);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    } 
    catch (\PDOException $e)  // Dans le cas contraire, capturons l'erreur sous forme d'exception
    {
        // Affichons le message d'erreur puis arrêtons l'exécution du script.
        die("Erreur de connexion à la base de données: " . $e->getMessage());
    }
?>