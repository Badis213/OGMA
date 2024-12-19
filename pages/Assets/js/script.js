const hamburger = document.getElementById('hamburger');
const navLinks = document.getElementById('nav-links');

// Écouteur pour afficher/masquer le menu
hamburger.addEventListener('click', () => {
    navLinks.classList.toggle('active');
});
