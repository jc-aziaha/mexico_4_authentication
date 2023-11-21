<?php

    function verifyIfEmailAlreadyExists(string $email): bool
    {
        require __DIR__ . "/../db/connexion.php";

        $req = $db->prepare("SELECT * FROM user WHERE email=:email");
        $req->bindValue(":email", $email);
        $req->execute();

        if ( $req->rowCount() == 1 ) 
        {
            return true;
        }

        return false;
    }