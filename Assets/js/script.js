document.addEventListener('DOMContentLoaded', function () {
    const isConnected = false;  // Remplacer par la logique de connexion réelle
    const profileLink = document.getElementById('profile-link');
    const signInLink = document.getElementById('signin');
    const loginLink = document.getElementById('login');
    
    if (isConnected) {
        // Cacher les liens "S'inscrire" et "Se connecter" et afficher "Profil"
        signInLink.style.display = 'none';
        loginLink.style.display = 'none';
        profileLink.style.display = 'block';
    } else {
        // Sinon, afficher "S'inscrire" et "Se connecter" et cacher "Profil"
        signInLink.style.display = 'block';
        loginLink.style.display = 'block';
        profileLink.style.display = 'none';
    }
});
