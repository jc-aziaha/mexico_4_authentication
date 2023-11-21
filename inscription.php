<?php
    // Traitement des données

    // 1- Si les données arrivent au serveur via la méthod "POST"

        // 2- Protéger le serveur contre les failles de type XSS

        // 3- Protéger le serveur contre les failles de type CSRF

        // 4- Protéger le serveur contre les robots spameurs

        // 5- Définir les contraintes de validation pour chaque input

        // 5-a) Le prénom 

        // 5-b) Le nom 

        // 5-c) L'email
        if ( isset($postClean['email']) ) 
        {
            if ( empty($postClean['email']) )
            {
                $errors['email'] = "L'email est obligatoire.";
            }
            else if ( !filter_var($postClean['email'], FILTER_VALIDATE_EMAIL) )
            {
                $errors['email'] = "Votre email est invalide.";
            }
            else if ( verifyIfEmailAlreadyExists($postClean['email']) )
            {
                $errors['email'] = "Impossible de créer un compte avec cet email.";
            }
        }

        // 5-d) Le mot de passe

        // 5-e) La confirmation du mot de passe

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

        // 10- Effectuer la requête d'insertion du nouveau film dans la table des films de la base de données.

            // 10-a) On prepare la requête
        $req = $db->prepare("INSERT INTO user (first_name, last_name, email, password, created_at, updated_at) VALUES (:first_name, :last_name, :email, :password, now(), now() ) ");

            // 10-b) On initialise les valeurs
        $req->bindValue(":first_name", $postClean['first_name']);
        $req->bindValue(":last_name", $postClean['last_name']);
        $req->bindValue(":email", $postClean['email']);
        $req->bindValue(":password", $postClean['password']);

            // 10-c) On execute la requête
        $req->execute();

            // 10-d) On ferme le curseur (Non obligatoire.)
        $req->closeCursor();


        // 11- Générer un message flash de succès
        $_SESSION['success'] = "Bienvenue.";

        // 12- Effectuer une redirection vers la page d'accueil puis arrêter l'exécution du script.
        return header("Location: index.php");


        



?>

<?php require __DIR__ . "/partials/head.php"; ?>

    <?php require __DIR__ . "/partials/nav.php"; ?>

        <main>
            <h1>Inscription</h1>

            <form method="POST">
                <div>
                    <label for="firstName">Prénom</label>
                    <input type="text" name="firstName" id="firstName" autofocus>
                </div>
                <div>
                    <label for="lastName">Nom</label>
                    <input type="text" name="lastName" id="lastName">
                </div>
                <div>
                    <label for="email">Email</label>
                    <input type="email" name="email" id="email">
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
                    <input type="submit">
                </div>
            </form>
        </main>
        
    <?php require __DIR__ . "/partials/footer.php"; ?>

<?php require __DIR__ . "/partials/foot.php"; ?>
    