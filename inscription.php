<?php
session_start();

require __DIR__ . "/functions/functions.php";

    /*
     * ------------------------------------------------------
     * Partie Controller 
     * Traitement des données par le serveur
     * ------------------------------------------------------
    */

    // 1- Si la méthode d'envoi des données est "POST",
    if ( $_SERVER['REQUEST_METHOD'] === "POST" ) 
    {

        $postClean = [];
        $errors    = [];

        // 2- Protéger le serveur contre les failles de type XSS
        foreach ($_POST as $key => $value) 
        {
            $postClean[$key] = htmlspecialchars($value);
        }


        // 3- Protéger le serveur contre les failles de type CSRF
        if ( !isset($_SESSION['csrf_token'])  || !isset($postClean['csrf_token']) 
            || empty($_SESSION['csrf_token']) || empty($postClean['csrf_token'])
            || $_SESSION['csrf_token'] !== $postClean['csrf_token']
        ) 
        {
            // Effectuer une redirection vers la page de laquelle proviennent les données puis arrêter l'exécution du script
            unset($_SESSION['csrf_token']);
            return header("Location: " . $_SERVER['HTTP_REFERER']);
        }
        unset($_SESSION['csrf_token']);

        // var_dump($errors); die();



        // 4- Protéger le serveur contre les robots spameurs
        if ( !isset($postClean['honeypot']) || !empty($postClean['honeypot']) ) 
        {
            // Effectuer une redirection vers la page de laquelle proviennent les données puis arrêter l'exécution du script
            return header("Location: " . $_SERVER['HTTP_REFERER']);
        }

        // 5- Définir les contraintes de validation pour chaque input

        // 5-a) Le prénom
        if ( isset($postClean['firstName']) ) 
        {
            if ( empty($postClean['firstName']) ) 
            {
                $errors['firstName'] = "Le prénom est obligatoire.";
            }
            else if ( ! preg_match("/^[a-zA-Z-_' áàâäãåçéèêëíìîïñóòôöõúùûüýÿæœÁÀÂÄÃÅÇÉÈÊËÍÌÎÏÑÓÒÔÖÕÚÙÛÜÝŸÆŒ]+$/i",$postClean['firstName']) )
            {
                $errors['firstName'] = "Le prénom est invalide.";
            }
        }

        // 5-b) Le nom 
        if ( isset($postClean['lastName']) ) 
        {
            if ( empty($postClean['lastName']) ) 
            {
                $errors['lastName'] = "Le nom est obligatoire.";
            }
            else if ( ! preg_match("/^[a-zA-Z-_' áàâäãåçéèêëíìîïñóòôöõúùûüýÿæœÁÀÂÄÃÅÇÉÈÊËÍÌÎÏÑÓÒÔÖÕÚÙÛÜÝŸÆŒ]+$/i",$postClean['lastName']) )
            {
                $errors['lastName'] = "Le nom est invalide.";
            }
        }


        // 5-c) L'email
        if ( isset($postClean['email']) ) 
        {
            if ( empty($postClean['email']) )
            {
                $errors['email'] = "L'email est obligatoire.";
            }
            else if ( ! filter_var($postClean['email'], FILTER_VALIDATE_EMAIL) )
            {
                $errors['email'] = "Votre email est invalide.";
            }
            else if ( verifyIfEmailAlreadyExists($postClean['email']) )
            {
                $errors['email'] = "Impossible de créer un compte avec cet email.";
            }
        }

        // 5-d) Le mot de passe
        if ( isset($postClean['password']) ) 
        {
            if ( empty($postClean['password']) )
            {
                $errors['password'] = "Le mot de passe est obligatoire.";
            }
            else if( mb_strlen($postClean['password']) < 12 )
            {
                $errors['password'] = "Le mot de passe ne doit pas être inférieur à 12 caractères.";
            }
            else if( mb_strlen($postClean['password']) > 255 )
            {
                $errors['password'] = "Le mot de passe ne doit pas être supérieur à 255 caractères.";
            }
            else if( ! preg_match("/^(?=.*[a-zà-ÿ])(?=.*[A-ZÀ-Ỳ])(?=.*[0-9])(?=.*[^a-zà-ÿA-ZÀ-Ỳ0-9]).{11,255}$/", $postClean['password']) )
            {
                $errors['password'] = "Le mot de passe doit contenir au moins un chiffre, une lettre minuscule, majuscule et un caractère spécial.";
            }
        }

        // 5-e) La confirmation du mot de passe
        if ( isset($postClean['confirmPassword']) ) 
        {
            if ( empty($postClean['confirmPassword']) )
            {
                $errors['confirmPassword'] = "La confirmation du mot de passe est obligatoire.";
            }
            else if( mb_strlen($postClean['confirmPassword']) < 12 )
            {
                $errors['confirmPassword'] = "La confirmation du mot de passe ne doit pas être inférieur à 12 caractères.";
            }
            else if( mb_strlen($postClean['confirmPassword']) > 255 )
            {
                $errors['confirmPassword'] = "La confirmation du mot de passe ne doit pas être supérieur à 255 caractères.";
            }
            else if( ! preg_match("/^(?=.*[a-zà-ÿ])(?=.*[A-ZÀ-Ỳ])(?=.*[0-9])(?=.*[^a-zà-ÿA-ZÀ-Ỳ0-9]).{11,255}$/", $postClean['confirmPassword']) )
            {
                $errors['confirmPassword'] = "La confirmation du mot de passe doit contenir au moins un chiffre, une lettre minuscule, majuscule et un caractère spécial.";
            }
            else if( $postClean['password'] !== $postClean['confirmPassword'] )
            {
                $errors['confirmPassword'] = "Le mot de pase doit être identique à sa confirmation.";
            }
        }

        // 6- Si le tableau d'erreurs contient au moins une erreur,
        if ( count($errors) > 0 ) 
        {
            // Sauvegarder ces messages d'erreur en session
            $_SESSION['form_errors'] = $errors;
            
            // Sauvegarder les anciennes données provenant du formulaire en session
            $_SESSION['old'] = $postClean;

            // Effectuer une redirection vers la page de la laquelle proviennent les informations puis arrêter l'exécution du script
            return header("Location: " . $_SERVER['HTTP_REFERER']);
        }

        // 7- Dans le cas contraire,

        // 9- Etablir une connexion avec la base de données
        require __DIR__ . "/db/connexion.php";

        // Encodons le mot de passe
        $passwordHashed = password_hash($postClean['password'], PASSWORD_BCRYPT);

        // 10- Effectuer la requête d'insertion du nouveau film dans la table des films de la base de données.

            // 10-a) On prepare la requête
        $req = $db->prepare("INSERT INTO user (first_name, last_name, email, password, created_at, updated_at) VALUES (:first_name, :last_name, :email, :password, now(), now() ) ");

            // 10-b) On initialise les valeurs
        $req->bindValue(":first_name", $postClean['firstName']);
        $req->bindValue(":last_name", $postClean['lastName']);
        $req->bindValue(":email", $postClean['email']);
        $req->bindValue(":password", $passwordHashed);

            // 10-c) On execute la requête
        $req->execute();

            // 10-d) On ferme le curseur (Non obligatoire.)
        $req->closeCursor();


        // 11- Générer un message flash de succès
        $_SESSION['success'] = "Bienvenue.";

        // 12- Effectuer une redirection vers la page d'accueil puis arrêter l'exécution du script.
        return header("Location: connexion.php");
    }

    $_SESSION['csrf_token'] = bin2hex(random_bytes(30));
?>

<?php require __DIR__ . "/partials/head.php"; ?>

    <?php require __DIR__ . "/partials/nav.php"; ?>

        <main>
            <h1>Inscription</h1>

            <?php if( isset($_SESSION['form_errors']) && !empty($_SESSION['form_errors']) ) : ?>
                <div class="alert alert-danger" role="alert">
                    <ul>
                        <?php foreach($_SESSION['form_errors'] as $error) : ?>
                            <li><?= $error; ?></li>
                        <?php endforeach ?>
                    </ul>
                </div>
                <?php unset($_SESSION['form_errors']); ?>
            <?php endif ?>

            <form method="POST">
                <div>
                    <label for="firstName">Prénom</label>
                    <input type="text" name="firstName" id="firstName" autofocus value="<?= isset($_SESSION['old']['firstName']) ? $_SESSION['old']['firstName'] : ''; unset($_SESSION['old']['firstName']); ?>">
                </div>
                <div>
                    <label for="lastName">Nom</label>
                    <input type="text" name="lastName" id="lastName" value="<?= isset($_SESSION['old']['lastName']) ? $_SESSION['old']['lastName'] : ''; unset($_SESSION['old']['lastName']); ?>">
                </div>
                <div>
                    <label for="email">Email</label>
                    <input type="email" name="email" id="email" value="<?= isset($_SESSION['old']['email']) ? $_SESSION['old']['email'] : ''; unset($_SESSION['old']['email']); ?>">
                </div>
                <div>
                    <label for="password">Mot de passe</label>
                    <input type="password" name="password" id="password">
                </div>
                <div>
                    <label for="confirmPassword">Confirmation du mot de passe</label>
                    <input type="password" name="confirmPassword" id="confirmPassword">
                </div>
                <div>
                    <input formnovalidate type="submit" value="Je m'inscris">
                </div>
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token']; ?>">
                <input type="hidden" name="honeypot" value="">
            </form>
        </main>
        
    <?php require __DIR__ . "/partials/footer.php"; ?>

<?php require __DIR__ . "/partials/foot.php"; ?>
    