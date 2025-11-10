import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask.cli import with_appcontext
import click

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-in-production')
# DATABASE_URL support (Postgres) or fallback to sqlite file
database_url = os.environ.get('DATABASE_URL') or 'sqlite:///stallerbike.db'
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

class Bike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(80), nullable=False)
    status = db.Column(db.String(80), nullable=False, default='verfügbar')
    location = db.Column(db.String(200), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@login_required
def index():
    total = Bike.query.count()
    by_cat = db.session.query(Bike.category, db.func.count(Bike.id)).group_by(Bike.category).all()
    recent = Bike.query.order_by(Bike.created_at.desc()).limit(5).all()
    return render_template('index.html', total=total, by_cat=by_cat, recent=recent)

@app.route('/bikes')
@login_required
def bikes():
    q = request.args.get('q','').strip()
    cat = request.args.get('category','')
    query = Bike.query
    if q:
        query = query.filter(Bike.name.ilike(f"%{q}%"))
    if cat:
        query = query.filter_by(category=cat)
    bikes = query.order_by(Bike.id.desc()).all()
    categories = sorted({b.category for b in Bike.query.all()})
    return render_template('bikes.html', bikes=bikes, categories=categories, q=q, cat=cat)

@app.route('/bikes/add', methods=['GET','POST'])
@login_required
def add_bike():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form['name'].strip()
        category = request.form['category']
        status = request.form['status']
        location = request.form.get('location','').strip()
        notes = request.form.get('notes','').strip()
        if not name or not category:
            flash('Name und Kategorie sind erforderlich', 'danger')
            return redirect(url_for('add_bike'))
        b = Bike(name=name, category=category, status=status, location=location, notes=notes)
        db.session.add(b)
        db.session.commit()
        flash('Bike hinzugefügt', 'success')
        return redirect(url_for('bikes'))
    categories = ['Mountainbike','E-bike','Rennrad','Gravelbike','Sonstiges']
    statuses = ['verfügbar','verliehen','in Reparatur','ausgemustert']
    return render_template('add_edit_bike.html', categories=categories, statuses=statuses, bike=None)

@app.route('/bikes/edit/<int:bike_id>', methods=['GET','POST'])
@login_required
def edit_bike(bike_id):
    b = Bike.query.get_or_404(bike_id)
    if request.method == 'POST':
        b.name = request.form['name'].strip()
        b.category = request.form['category']
        b.status = request.form['status']
        b.location = request.form.get('location','').strip()
        b.notes = request.form.get('notes','').strip()
        db.session.commit()
        flash('Bike aktualisiert', 'success')
        return redirect(url_for('bikes'))
    categories = ['Mountainbike','E-bike','Rennrad','Gravelbike','Sonstiges']
    statuses = ['verfügbar','verliehen','in Reparatur','ausgemustert']
    return render_template('add_edit_bike.html', categories=categories, statuses=statuses, bike=b)

@app.route('/bikes/delete/<int:bike_id>', methods=['POST'])
@login_required
def delete_bike(bike_id):
    if not current_user.is_admin:
        flash('Nur Admins dürfen löschen', 'danger')
        return redirect(url_for('bikes'))
    b = Bike.query.get_or_404(bike_id)
    db.session.delete(b)
    db.session.commit()
    flash('Bike gelöscht', 'info')
    return redirect(url_for('bikes'))

# Users (admin)
@app.route('/users')
@login_required
def users():
    if not current_user.is_admin:
        flash('Nur Admins dürfen Benutzer verwalten', 'danger')
        return redirect(url_for('index'))
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('users.html', users=users)

@app.route('/users/add', methods=['GET','POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        flash('Nur Admins dürfen Benutzer anlegen', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        is_admin = bool(request.form.get('is_admin'))
        if not username or not password:
            flash('Benutzername und Passwort nötig', 'danger')
            return redirect(url_for('add_user'))
        if User.query.filter_by(username=username).first():
            flash('Benutzer existiert bereits', 'danger')
            return redirect(url_for('add_user'))
        u = User(username=username, is_admin=is_admin)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash('Benutzer erstellt', 'success')
        return redirect(url_for('users'))
    return render_template('add_user.html')

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Nur Admins dürfen löschen', 'danger')
        return redirect(url_for('index'))
    u = User.query.get_or_404(user_id)
    if u.username == current_user.username:
        flash('Du kannst dein eigenes Konto nicht löschen', 'warning')
        return redirect(url_for('users'))
    db.session.delete(u)
    db.session.commit()
    flash('Benutzer gelöscht', 'info')
    return redirect(url_for('users'))

# Auth
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        print("DEBUG LOGIN:", username)
        print("DB Users:", [u.username for u in User.query.all()])
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Erfolgreich eingeloggt', 'success')
            return redirect(url_for('index'))
        flash('Ungültige Zugangsdaten', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Ausgeloggt', 'info')
    return redirect(url_for('login'))

# Simple JSON endpoints (for export or future frontend)
@app.route('/api/bikes')
@login_required
def api_bikes():
    bikes = Bike.query.all()
    data = [dict(id=b.id, name=b.name, category=b.category, status=b.status, location=b.location, notes=b.notes) for b in bikes]
    return jsonify(data)

# CLI commands
@click.command('init-db')
@with_appcontext
def init_db():
    db.create_all()
    click.echo('DB initialisiert.')

@click.command('create-user')
@click.option('--username', prompt=True)
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
@click.option('--admin', is_flag=True, default=False, help='Set user as admin')
@with_appcontext
def create_user(username, password, admin):
    if User.query.filter_by(username=username).first():
        click.echo('Benutzer existiert bereits.')
        return
    u = User(username=username, is_admin=admin)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    click.echo(f'Benutzer {username} erstellt. Admin={admin}')

# ➕ Force-Admin-Route (außerhalb der Funktion!)
# ➕ Force-Admin-Route
@app.route("/force-admin")
def force_admin():
    try:
        u = User.query.filter_by(username='admin').first()
        if not u:
            u = User(username='admin', is_admin=True)
            u.set_password('adminpass')
            db.session.add(u)
            db.session.commit()
            return "✅ Admin erstellt!"
        else:
            u.set_password('adminpass')
            db.session.commit()
            return "🔄 Passwort für Admin wurde zurückgesetzt!"
    except Exception as e:
        return f"❌ Fehler: {e}"


# ➕ CLI-Befehle
app.cli.add_command(init_db)
app.cli.add_command(create_user)


# ➕ Admin-Erstellung beim Start
with app.app_context():
    try:
        if not User.query.filter_by(username='admin').first():
            u = User(username='admin', is_admin=True)
            u.set_password('adminpass')
            db.session.add(u)
            db.session.commit()
            print("✅ Admin-Benutzer wurde erstellt!")
        else:
            print("⚠️ Benutzer 'admin' existiert bereits.")
    except Exception as e:
        print("❌ Fehler bei Admin-Setup:", e)


# ➕ Debug-Ausgabe aller registrierten Routen (erscheint im Render-Log)
@app.before_first_request
def show_registered_routes():
    print("========== REGISTERED ROUTES ==========")
    for rule in app.url_map.iter_rules():
        print(" →", rule)
    print("=======================================")


# Nur lokal relevant
if __name__ == '__main__':
    app.run(debug=True)
