<?php
session_start();

    unset($_SESSION['user']);

    session_destroy();

    return header("Location: connexion.php");