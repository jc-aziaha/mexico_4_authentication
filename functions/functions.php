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


    /**
     * Cette fonction permet de vérifier si la personne qui essaie 
     * de se connecter existe dans la base de données ou non.
     *
     * @param string $email
     * @param string $plainPassword
     * 
     * @return array|null
     */
    function loginAuthenticator(string $email, string $plainPassword): ?array
    {
        require __DIR__ . "/../db/connexion.php";

        $req = $db->prepare("SELECT * FROM user WHERE email=:email");
        $req->bindValue(":email", $email);
        $req->execute();

        if ( $req->rowCount() != 1 ) 
        {
            return null;
        }

        $user = $req->fetch();
 
        if ( ! password_verify($plainPassword, $user['password']) ) 
        {
            return null;
        }

        return $user;

    }