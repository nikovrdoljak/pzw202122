from flask import Flask, render_template
from flask_bootstrap import Bootstrap
from datetime import datetime
from flask_caching import Cache
import os
import requests
import locale
app = Flask(__name__)
bootstrap = Bootstrap(app)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

app.config['BOOTSTRAP_BOOTSWATCH_THEME'] = 'minty'
OPEN_WEATHER_API_KEY = os.environ.get('OPEN_WEATHER_API_KEY')
locale.setlocale(locale.LC_ALL, 'hr')

@app.route('/')
@cache.cached(timeout=60)
def index():
    now = datetime.now()
    url = 'https://api.openweathermap.org/data/2.5/weather'
    parameters = {'q': 'zadar', 'appid': OPEN_WEATHER_API_KEY, 'units': 'metric', 'lang': 'hr'}
    response = requests.get(url, parameters)
    weather = response.json()
    return render_template('index.html', weather = weather, now = now)

@app.route('/forecast_days')
def forecast_days():
    url = 'http://api.openweathermap.org/data/2.5/forecast/daily'
    parameters = {'q': 'zadar', 'appid': OPEN_WEATHER_API_KEY, 'cnt': '7', 'units': 'metric', 'lang': 'hr'}
    response = requests.get(url, parameters)
    weather = response.json()
    return render_template('forecast_days.html', weather = weather)

@app.template_filter('datetime')
def format_datetime(value, format='%d.%m.%Y %H:%M'):
    if format == 'time':
        format='%H:%M'
    elif format == 'Ddm':
        format='%a %d.%m'
    return datetime.fromtimestamp(value).strftime(format)