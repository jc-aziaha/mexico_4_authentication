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


        // 4- Protéger le serveur contre les robots spameurs
        if ( !isset($postClean['honeypot']) || !empty($postClean['honeypot']) ) 
        {
            // Effectuer une redirection vers la page de laquelle proviennent les données puis arrêter l'exécution du script
            return header("Location: " . $_SERVER['HTTP_REFERER']);
        }

        // 5- Définir les contraintes de validation pour chaque input


        // 5-a) L'email
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
        }

        // 5-b) Le mot de passe
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

        // Dans le cas contraire,
        // 7- Etablir une connexion avec la base de données
        require __DIR__ . "/db/connexion.php";

        /*
         * 8- Charger la fonction qui permet de vérfifier: 
         *      -- Si l'email envoyé par la personne qui essaie de se connecter existe dans la base de données ou non.
         *      -- Si l'email existe, vérifier si le mot de passe envoyé par la personne qui essaie de se connecter correspond également
         *      -- Par conséquent, il faut que le couple email-password corresponde afin d'authentifier l'utilisateur
         */
        // $loginResponse = loginAuthenticator($postClean['email'], $postClean['password']);
        // Pause
    }

    $_SESSION['csrf_token'] = bin2hex(random_bytes(30));
?>
<?php require __DIR__ . "/partials/head.php"; ?>

    <?php require __DIR__ . "/partials/nav.php"; ?>

        <main>
            <h1>Connexion</h1>

            <?php if( isset($_SESSION['form_errors']) && !empty($_SESSION['form_errors']) ) : ?>
                <div style="color:red;" role="alert">
                    <ul>
                        <?php foreach($_SESSION['form_errors'] as $error) : ?>
                            <li><?= $error; ?></li>
                        <?php endforeach ?>
                    </ul>
                </div>
                <?php unset($_SESSION['form_errors']); ?>
            <?php endif ?>

            <?php if(isset($_SESSION['success']) && !empty($_SESSION['success']) ) : ?>
                <div role="alert">
                    <?= $_SESSION['success']; ?>
                </div>
                <?php unset($_SESSION['success']); ?>
            <?php endif ?>

            <form method="POST">
                <div>
                    <label for="email">Email</label>
                    <input type="email" name="email" id="email" autofocus value="<?= isset($_SESSION['old']['email']) ? $_SESSION['old']['email'] : ''; unset($_SESSION['old']['email']); ?>">
                </div>
                <div>
                    <label for="password">Mot de passe</label>
                    <input type="text" name="password" id="password">
                </div>
                <div>
                    <input formnovalidate type="submit" value="Je me connecte">
                </div>
                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token']; ?>">
                <input type="hidden" name="honeypot" value="">
            </form>
        </main>
        
    <?php require __DIR__ . "/partials/footer.php"; ?>

<?php require __DIR__ . "/partials/foot.php"; ?>
    