<nav>
    <a href="index.php">Accueil</a>
    
    <?php if(isset($_SESSION['user']) && !empty($_SESSION['user']) ) : ?>
        <a href="deconnexion.php">Déconnexion</a>
    <?php else : ?>
        <a href="connexion.php">Connexion</a>
        <a href="inscription.php">Inscription</a>
    <?php endif ?>
</nav>