from flask import Flask, render_template, session, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

app = Flask(__name__)
app.config['SECRET_KEY'] = 'blablastring'

bootstrap = Bootstrap(app)

class NameForm(FlaskForm):
    name = StringField('Kako se zoveš?', validators=[DataRequired()])
    submit = SubmitField('Pošalji')

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')
