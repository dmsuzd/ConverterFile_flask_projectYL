import os
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, abort, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from pdf2docx import Converter
from werkzeug.utils import secure_filename
from docx2pdf import convert as docx_to_pdf
from datetime import datetime
import csv
import io
from logging.handlers import RotatingFileHandler
import logging

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

DB = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

ALLOWED_EXTENSIONS = {
    'pdf_to_word': ['pdf'],
    'word_to_pdf': ['docx', 'doc']
}
FORMATS_MAP = {
    'pdf_to_word': 'PDF',
    'word_to_pdf': 'DOCX, DOC'
}

UPLOAD_FOLDER = 'uploads/'
OUTPUT_FOLDER = 'outputs/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['OUTPUT_FOLDER'] = OUTPUT_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)


class User(UserMixin, DB.Model):
    id = DB.Column(DB.Integer, primary_key=True)
    username = DB.Column(DB.String(80), unique=True, nullable=False)
    password_hash = DB.Column(DB.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class ConversionHistory(DB.Model):
    id = DB.Column(DB.Integer, primary_key=True)
    user_id = DB.Column(DB.Integer, DB.ForeignKey('user.id'), nullable=False)
    original_filename = DB.Column(DB.String(255), nullable=False)
    converted_filename = DB.Column(DB.String(255), nullable=False)
    conversion_type = DB.Column(DB.String(50), nullable=False)
    timestamp = DB.Column(DB.DateTime, default=datetime.utcnow)

    user = DB.relationship('User', backref=DB.backref('conversions', lazy=True))


with app.app_context():
    DB.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == '' or password == '':
            flash('Некорректное имя пользователя или пароль.')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Имя пользователя уже существует.')
            return redirect(url_for('register'))
        
        new_user = User(username=username)
        new_user.set_password(password)

        DB.session.add(new_user)
        DB.session.commit()

        flash('Регистрация прошла успешно. Пожалуйста, войдите в систему.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))

        flash('Неверное имя пользователя или пароль.')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/')
@app.route('/index')
@login_required
def index():
    return render_template('index.html', user=current_user)


@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({
            'success': False,
            'error': 'Файл не был отправлен',
            'redirect': url_for('index')
        }), 400

    file = request.files['file']
    conversion_type = request.form.get('conversion_type')

    if file.filename == '':
        return jsonify({
            'success': False,
            'error': 'Не выбран файл для загрузки',
            'redirect': url_for('index')
        }), 400

    if not allowed_file(file.filename, conversion_type):
        return jsonify({
            'success': False,
            'error': 'Недопустимый формат файла или повреждённый документ',
            'allowed_formats': get_allowed_formats(conversion_type),
            'redirect': url_for('index')
        }), 400

    try:
        if file and allowed_file(file.filename, conversion_type):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            if conversion_type == 'pdf_to_word':
                word_filename = filename.rsplit('.', 1)[0] + '.docx'
                word_path = os.path.join(app.config['OUTPUT_FOLDER'], word_filename)

                try:
                    cv = Converter(file_path)
                    cv.convert(word_path)
                    cv.close()
                except Exception as e:
                    return jsonify({
                        'success': False,
                        'error': 'Ошибка конвертации PDF в Word',
                        'details': str(e),
                        'redirect': url_for('index')
                    }), 500

                record = ConversionHistory(
                    user_id=current_user.id,
                    original_filename=filename,
                    converted_filename=word_filename,
                    conversion_type=conversion_type
                )
                DB.session.add(record)
                DB.session.commit()

                return jsonify({
                    'success': True,
                    'download_url': url_for('download_file', filename=word_filename)
                })

            elif conversion_type == 'word_to_pdf':
                pdf_filename = filename.rsplit('.', 1)[0] + '.pdf'
                pdf_path = os.path.join(app.config['OUTPUT_FOLDER'], pdf_filename)

                try:
                    docx_to_pdf(file_path, pdf_path)
                except Exception as e:
                    return jsonify({
                        'success': False,
                        'error': 'Ошибка конвертации Word в PDF',
                        'details': str(e),
                        'redirect': url_for('index')
                    }), 500

                record = ConversionHistory(
                    user_id=current_user.id,
                    original_filename=filename,
                    converted_filename=pdf_filename,
                    conversion_type=conversion_type
                )
                DB.session.add(record)
                DB.session.commit()

                return jsonify({
                    'success': True,
                    'download_url': url_for('download_file', filename=pdf_filename)
                })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Произошла непредвиденная ошибка',
            'details': str(e),
            'redirect': url_for('index')
        }), 500

    return jsonify({
        'success': False,
        'error': 'Неизвестная ошибка',
        'redirect': url_for('index')
    }), 400


@app.route('/download/<filename>')
@login_required
def download_file(filename):
    file_path = os.path.join(app.config['OUTPUT_FOLDER'], filename)
    return send_file(file_path, as_attachment=True)


@app.route('/profile')
@login_required
def profile():
    history = ConversionHistory.query.filter_by(user_id=current_user.id).order_by(
        ConversionHistory.timestamp.desc()).all()
    return render_template('profile.html', history=history)


@app.route('/delete_record/<int:record_id>', methods=['POST'])
@login_required
def delete_record(record_id):
    record = ConversionHistory.query.get_or_404(record_id)
    if record.user_id != current_user.id:
        abort(403)

    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], record.original_filename))
        os.remove(os.path.join(app.config['OUTPUT_FOLDER'], record.converted_filename))
        DB.session.delete(record)
        DB.session.commit()
        flash('Запись успешно удалена', 'success')
    except Exception as e:
        app.logger.error(f"error: {str(e)}")
        flash('Запись не удалена', 'error')

    return redirect(url_for('profile'))


def allowed_file(filename, conversion_type):
    if not conversion_type in ALLOWED_EXTENSIONS:
        return False

    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS[conversion_type]


def get_allowed_formats(conversion_type):
    return FORMATS_MAP.get(conversion_type, 'Неизвестный тип конвертации')


@app.route('/export_csv')
@login_required
def export_to_csv():
    history = ConversionHistory.query.filter_by(user_id=current_user.id).all()

    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')

    writer.writerow(['Исходный файл', 'Результат', 'Тип конвертации', 'Дата и время'])

    for record in history:
        writer.writerow([
            record.original_filename,
            record.converted_filename,
            'PDF → Word' if record.conversion_type == 'pdf_to_word' else 'Word → PDF',
            record.timestamp.strftime('%d.%m.%Y %H:%M')
        ])

    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=conversion_history.csv'
    response.headers['Content-type'] = 'text/csv; charset=utf-8-sig'

    return response


if __name__ == '__main__':
    app.run(debug=True)
