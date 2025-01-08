from flask import Flask, render_template, request, redirect, url_for, flash, make_response, session, g
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash
from flask_cors import CORS
from dotenv import load_dotenv
import re
from datetime import datetime, timedelta
import os

# Initialisation de l'application Flask
app = Flask(__name__)
CORS(app)

load_dotenv()

# Now you can access the environment variables
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = f"{os.getenv('DB_URL')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # To disable a feature that uses memory for tracking

# Initialisation des extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Flask-Session configuration (stores sessions in database)
app.config['SESSION_TYPE'] = 'sqlalchemy'  # You can change this to 'filesystem' if you want to store it in files
app.config['SESSION_SQLALCHEMY'] = db  # Using the same SQLAlchemy instance for session storage
app.config['SESSION_PERMANENT'] = True  # Keep sessions persistent
app.config['SESSION_USE_SIGNER'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Sessions will last for 7 days

Session(app)  # Initialize Flask-Session to use server-side sessions

# Modèle utilisateur et inscription évenement
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(100), nullable=False)
    prenom = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default="membre")
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.id} - {self.nom} {self.prenom} ({self.email})>"

class EventRegistration(db.Model):
    __tablename__ = 'event_registration'
    id = db.Column(db.Integer, primary_key=True)
    prenom = db.Column(db.String(100))
    nom = db.Column(db.String(100))
    email = db.Column(db.String(100))
    classe = db.Column(db.String(100))
    mode = db.Column(db.String(100))
    confirmation = db.Column(db.Boolean)  # Add this line
    status = db.Column(db.String(100))

class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Message {self.id} from {self.name}>"


with app.app_context():  # Ensuring app context is available
    db.create_all()  # Create all tables defined in your models


# Permission lists
admin_panel_permissions = ["président", "vice-président", "secrétaire", "admin", "développeur"]
change_verification_permissions = ["président", "vice-président", "secrétaire", "admin", "développeur"]
change_status_permissions = ["président", "vice-président", "secrétaire", "admin", "développeur"]
change_role_permissions = ["président", "vice-président", "développeur", "admin"]
delete_user_permissions = ["président", "vice-président", "développeur", "admin"]
clear_registrations_permissions = ["président", "vice-président", "secrétaire", "admin", "développeur"]


def is_logged_in():
    return 'user_id' in session

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/evenements')
def evenements():
    return render_template('evenements.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        content = request.form.get('message')

        if not name or not email or not content:
            flash("Veuillez remplir tous les champs.", 'danger')
            return redirect(url_for('contact'))

        new_message = ContactMessage(name=name, email=email, content=content)
        db.session.add(new_message)
        db.session.commit()
        flash("Votre message a été envoyé avec succès.", 'success')
        return redirect(url_for('contact'))

    return render_template('contact.html')


@app.route('/bureau-provisoire')
def bureau_provisoire():
    return render_template('bureau-provisoire.html')

@app.route('/event-signin', methods=['GET', 'POST'])
def event_signin():
    if not is_logged_in():
        flash("Vous devez être connecté pour vous inscrire à un événement.", 'danger')
        return redirect(url_for('login'))  # Redirect to login page if not logged in
    
    user = User.query.get(session['user_id'])  # Get the logged-in user
    
    # Check if the user is verified
    if not user.is_verified:
        flash("Votre compte n'est pas encore vérifié. Veuillez attendre qu'un membre du bureau vérifie votre compte, ou contactez un membre du bureau.", 'danger')
        return redirect(url_for('profil'))  # Redirect to homepage or any other page
    
    # Dummy event data, you would later fetch it from the database
    event_date = "18/01/2025"  # Example date (d/m/y)
    event_time = "(heure pas encore connue)"       # Example time (xhy)
    event_place = "Pont Du Casse (addresse exacte pas encore connue)"    # Example location

    if request.method == 'POST':
        # Retrieve form data
        classe = request.form['classe']
        mode = request.form['mode']
        confirmation = 'confirmation' in request.form  # Check if the checkbox is ticked (True/False)

        # Only proceed with registration if confirmed (True)
        if confirmation:
            # Save the data in the database with confirmation as True
            event_registration = EventRegistration(
                prenom=user.prenom,
                nom=user.nom,
                email=user.email,
                classe=classe,
                mode=mode,
                confirmation=True,  # Store as True if the checkbox is checked
                status="attente"  # Default status
            )

            db.session.add(event_registration)
            db.session.commit()
            flash("Inscription à l'événement réussie !", 'success')
            return redirect(url_for('profil'))  # Redirect to the homepage (or any page you like)
        else:
            flash("Vous devez certifier votre présence avant de vous inscrire.", 'danger')
            return redirect(url_for('event_signin'))  # Redirect to the same page with an error

    # For GET request, render the page with the current event details
    return render_template('event-signin.html', user=user, event_date=event_date, event_time=event_time, event_place=event_place)

    
@app.route('/signin', methods=['POST', 'GET'])
def signin():
    if request.method == 'POST':
        try:
            nom = request.form['nom']
            prenom = request.form['prenom']
            email = request.form['email']
            password = request.form['password']
            confirm_password = request.form['confirm-password']

            # Check if the passwords match
            if password != confirm_password:
                flash('Les mots de passe ne correspondent pas.', 'danger')
                return redirect(url_for('signin'))

            # Check if email already exists
            if User.query.filter_by(email=email).first():
                flash('Cet email est déjà utilisé. Veuillez en choisir un autre.', 'danger')
                return redirect(url_for('signin'))

            # Validate the email format
            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_regex, email):
                flash('Veuillez entrer une adresse email valide.', 'danger')
                return redirect(url_for('signin'))

            # Validate the password strength (e.g., minimum length)
            if len(password) < 8:
                flash('Le mot de passe doit contenir au moins 8 caractères.', 'danger')
                return redirect(url_for('signin'))

            # Hash the password using Flask-Bcrypt
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Create a new user instance
            new_user = User(nom=nom, prenom=prenom, email=email, password=hashed_password)

            # Add the user to the database
            db.session.add(new_user)
            db.session.commit()

            # Flash success message and redirect to login
            flash('Inscription réussie ! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            flash(f"Erreur inattendue: {str(e)}", 'danger')
            return redirect(url_for('signin'))

    return render_template('signin.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        try:
            email = request.form['email']
            password = request.form['password']

            user = User.query.filter_by(email=email).first()

            if user and bcrypt.check_password_hash(user.password, password):
                # Store user ID in session to keep track of login state
                session['user_id'] = user.id

                flash('Connexion réussie !', 'success')
                # Redirect to dashboard or homepage
                return redirect(url_for('profil'))
            else:
                flash('Email ou mot de passe incorrect.', 'danger')
                return redirect(url_for('login'))

        except Exception as e:
            flash(f"Erreur inattendue: {str(e)}", 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Removes the user_id from the session
    flash('Vous êtes déconnecté.', 'success')
    return redirect(url_for('login'))


@app.route('/profil')
def profil():
    if not is_logged_in():
        flash('Vous devez être connecté pour accéder à cette page.', 'danger')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user = User.query.get(user_id)  # Fetch the user from the database by their ID
    
    if not user:
        flash('Utilisateur introuvable.', 'danger')
        return redirect(url_for('login'))

    # Pass user data to the template
    return render_template('profil.html', user=user)

@app.before_request
def load_logged_in_user():
    """This function runs before every request to load the logged-in user into the global context."""
    user_id = session.get('user_id')
    if user_id:
        g.logged_in_user = User.query.get(user_id)  # Get the logged-in user from the database
    else:
        g.logged_in_user = None

@app.context_processor
def inject_logged_in_user():
    """This context processor will make the logged-in user available in all templates."""
    return {'logged_in_user': g.get('logged_in_user')}

@app.route('/admin-panel')
def admin_panel():
    if not is_logged_in():
        flash("Vous devez être connecté pour accéder à cette page.", 'danger')
        return redirect(url_for('login'))  # Redirect to login page if not logged in

    user = g.logged_in_user  # Use the global logged-in user

    # Ensure user has the necessary role (only president and admin can access the admin panel)
    if user.role not in admin_panel_permissions:
        flash("Vous n'avez pas les autorisations nécessaires pour accéder à cette page.", 'danger')
        return redirect(url_for('profil'))  # Redirect to profile page if no access

    # Get all users, event registrations, and messages to display in the panel
    users = User.query.all()
    event_registrations = EventRegistration.query.all()
    messages = ContactMessage.query.order_by(ContactMessage.created_at.desc()).all()


    # Calculate statistics
    total_members = len(users)
    verified_members = len([user for user in users if user.is_verified])
    non_verified_members = total_members - verified_members
    event_signed_up = len([registration for registration in event_registrations if registration.status == "Validé"])
    presencial_count = len([registration for registration in event_registrations if registration.mode == "présentiel"])
    distanciel_count = len([registration for registration in event_registrations if registration.mode == "distanciel"])
    attente_count = len([registration for registration in event_registrations if registration.status == "attente"])

    return render_template('admin-panel.html', users=users, event_registrations=event_registrations,
                           total_members=total_members, verified_members=verified_members,
                           non_verified_members=non_verified_members, event_signed_up=event_signed_up,
                           presencial_count=presencial_count, distanciel_count=distanciel_count,
                           attente_count=attente_count, messages=messages,)


@app.route('/change-role/<int:user_id>', methods=['POST'])
def change_role(user_id):
    user = g.logged_in_user  # Use the global logged-in user
    if not user:
        return "Unauthorized", 401

    user_to_change = User.query.get(user_id)
    if not user_to_change:
        return "User not found", 404

    if user.role not in change_role_permissions or user_to_change.role in ["président", "vice-président"]:
        return "Forbidden", 403

    new_role = request.form.get('role')
    if not new_role:
        return "Bad Request: Missing role parameter", 400

    user_to_change.role = new_role
    db.session.commit()

    return redirect(url_for('admin_panel'))


@app.route('/delete-account/<int:user_id>', methods=['POST'])
def delete_account(user_id):
    if not is_logged_in():
        flash("Vous devez être connecté pour effectuer cette action.", 'danger')
        return redirect(url_for('login'))

    user = g.logged_in_user  # Use the global logged-in user
    if user.role not in delete_user_permissions:
        flash("Vous n'avez pas l'autorisation de supprimer des comptes.", 'danger')
        return redirect(url_for('admin_panel'))

    user_to_delete = User.query.get(user_id)
    if not user_to_delete:
        flash("Utilisateur non trouvé.", 'danger')
        return redirect(url_for('admin_panel'))

    if user_to_delete.role in ["président", "vice-président"] and user.role not in ["président", "vice-président"]:
        flash("Vous ne pouvez pas supprimer le compte du président ou du vice-président.", 'danger')
        return redirect(url_for('admin_panel'))

    # Delete event registrations related to this user
    event_registrations = EventRegistration.query.filter_by(id=user_to_delete.id).all()
    if event_registrations:
        for registration in event_registrations:
            db.session.delete(registration)
        db.session.commit()
        flash(f"Toutes les inscriptions à l'événement de {user_to_delete.nom} ont été supprimées.", 'success')

    # Now delete the user
    db.session.delete(user_to_delete)
    db.session.commit()

    flash(f"Compte de {user_to_delete.nom} supprimé avec succès.", 'success')
    return redirect(url_for('admin_panel'))


@app.route('/update-status/<int:registration_id>', methods=['POST'])
def update_status(registration_id):
    if not is_logged_in():
        flash("Vous devez être connecté pour effectuer cette action.", 'danger')
        return redirect(url_for('login'))

    user = g.logged_in_user  # Use the global logged-in user
    if user.role not in change_status_permissions:
        flash("Vous n'avez pas l'autorisation de modifier le statut de l'inscription.", 'danger')
        return redirect(url_for('admin_panel'))

    registration = EventRegistration.query.get(registration_id)
    if not registration:
        flash("Inscription à l'événement non trouvée.", 'danger')
        return redirect(url_for('admin-panel'))

    new_status = request.form['status']  # Get new status from form
    registration.status = new_status
    db.session.commit()
    flash(f"Statut de l'inscription mis à jour en {new_status}.", 'success')
    return redirect(url_for('admin_panel'))


@app.route('/toggle-verification/<int:user_id>', methods=['POST'])
def toggle_verification(user_id):
    if not is_logged_in():
        flash("Vous devez être connecté pour effectuer cette action.", 'danger')
        return redirect(url_for('login'))

    user = g.logged_in_user  # Use the global logged-in user
    if user.role not in change_verification_permissions:
        flash("Vous n'avez pas l'autorisation de modifier la vérification des utilisateurs.", 'danger')
        return redirect(url_for('admin_panel'))

    user_to_toggle = User.query.get(user_id)
    if not user_to_toggle:
        flash("Utilisateur non trouvé.", 'danger')
        return redirect(url_for('admin_panel'))

    # Toggle the verification status
    user_to_toggle.is_verified = not user_to_toggle.is_verified
    db.session.commit()
    flash(f"Vérification de {user_to_toggle.nom} mise à jour.", 'success')
    return redirect(url_for('admin_panel'))


@app.route('/clear-event-registrations', methods=['POST'])
def clear_event_registrations():
    if not is_logged_in():
        flash("Vous devez être connecté pour effectuer cette action.", 'danger')
        return redirect(url_for('login'))

    user = g.logged_in_user  # Get the logged-in user from the global context
    if user.role not in clear_registrations_permissions:  # Only the 'président' can clear registrations
        flash("Vous n'avez pas l'autorisation de supprimer les inscriptions.", 'danger')
        return redirect(url_for('admin_panel'))

    # Delete all event registrations from the database
    EventRegistration.query.delete()
    db.session.commit()

    flash("Les inscriptions passées ont été effacées avec succès.", 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/messages/delete/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    if not is_logged_in() or g.logged_in_user.role not in clear_registrations_permissions:
        flash("Vous n'êtes pas autorisé à supprimer des messages.", 'danger')
        return redirect(url_for('admin_panel'))

    message = ContactMessage.query.get(message_id)
    if not message:
        flash("Message introuvable.", 'danger')
        return redirect(url_for('admin_panel'))

    db.session.delete(message)
    db.session.commit()
    flash("Message supprimé avec succès.", 'success')
    return redirect(url_for('admin_panel'))

@app.route('/delete-event-registration/<int:registration_id>', methods=['POST'])
def delete_event_registration(registration_id):
    if not is_logged_in():
        flash('Vous devez être connecté pour effectuer cette action.', 'danger')
        return redirect(url_for('login'))

    # Ensure only authorized users can delete (president, admin, etc.)
    user = User.query.get(session['user_id'])
    if user.role not in ["président", "vice-président", "secrétaire", "admin", "développeur"]:
        flash('Accès non autorisé.', 'danger')
        return redirect(url_for('profil'))

    # Get the registration to delete
    registration = EventRegistration.query.get(registration_id)
    if not registration:
        flash('Inscription non trouvée.', 'danger')
        return redirect(url_for('admin_panel'))

    # Delete the registration
    db.session.delete(registration)
    db.session.commit()

    flash(f"Inscription de {registration.nom} {registration.prenom} supprimée avec succès.", 'success')
    return redirect(url_for('admin_panel'))


@app.route('/db-panel')
def db_panel():
    if not is_logged_in():  # Use is_logged_in() to check if the user is logged in
        flash('Vous devez être connecté pour accéder à cette page.', 'danger')
        return redirect(url_for('login'))

    # Get the user from the session
    user = User.query.get(session['user_id'])
    if user.email != 'bazizbadis13@gmail.com':  # Ensure the email is the one you specified
        flash('Accès non autorisé.', 'danger')
        return redirect(url_for('index'))

    # Query all users for the database panel
    users = User.query.all()
    return render_template('db_panel.html', users=users)


# Route to delete a user from the database (for the db-panel)
@app.route('/db-panel/delete-user/<int:user_id>', methods=['POST'])
def delete_user_from_db(user_id):
    if not is_logged_in():  # Use is_logged_in() to check if the user is logged in
        flash('Vous devez être connecté pour effectuer cette action.', 'danger')
        return redirect(url_for('login'))

    # Get the user from the session
    user = User.query.get(session['user_id'])
    if user.email != 'bazizbadis13@gmail.com':  # Ensure the email is the one you specified
        flash('Accès non autorisé.', 'danger')
        return redirect(url_for('index'))

    # Find the user to delete
    user_to_delete = User.query.get(user_id)
    if not user_to_delete:
        flash('Utilisateur non trouvé.', 'danger')
        return redirect(url_for('db_panel'))

    # Delete the user from the database
    db.session.delete(user_to_delete)
    db.session.commit()

    flash(f"Utilisateur {user_to_delete.nom} supprimé avec succès.", 'success')
    return redirect(url_for('db_panel'))


# Route to modify a user (for the db-panel)
@app.route('/db-panel/modify-user/<int:user_id>', methods=['GET', 'POST'])
def modify_user_in_db(user_id):
    if not is_logged_in():  # Use is_logged_in() to check if the user is logged in
        flash('Vous devez être connecté pour effectuer cette action.', 'danger')
        return redirect(url_for('login'))

    # Get the user from the session
    user = User.query.get(session['user_id'])
    if user.email != 'bazizbadis13@gmail.com':  # Ensure the email is the one you specified
        flash('Accès non autorisé.', 'danger')
        return redirect(url_for('index'))

    # Get the user to modify from the database
    user_to_modify = User.query.get(user_id)
    if not user_to_modify:
        flash('Utilisateur non trouvé.', 'danger')
        return redirect(url_for('db_panel'))

    # If the method is POST, update the user data
    if request.method == 'POST':
        user_to_modify.nom = request.form.get('nom')
        user_to_modify.prenom = request.form.get('prenom')
        user_to_modify.email = request.form.get('email')
        user_to_modify.role = request.form.get('role')
        user_to_modify.is_verified = request.form.get('is_verified') == 'True'

        db.session.commit()

        flash(f"Utilisateur {user_to_modify.nom} modifié avec succès.", 'success')
        return redirect(url_for('db_panel'))

    # Render the modify user form
    return render_template('modify_user_in_db.html', user=user_to_modify)

if __name__ == '__main__':
    app.run(debug=True)