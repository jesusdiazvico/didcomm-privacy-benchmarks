from flask import Flask, render_template
import os

PEOPLE_FOLDER = os.path.join('static', '.')

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = PEOPLE_FOLDER

@app.route('/')
@app.route('/index')
def show_index():
    full_filename_enc = os.path.join(app.config['UPLOAD_FOLDER'], 'results-enc-cpu.png')
    full_filename_dec = os.path.join(app.config['UPLOAD_FOLDER'], 'results-dec-cpu.png')
    full_filename_size = os.path.join(app.config['UPLOAD_FOLDER'], 'results-size.png')
    return render_template("index.html", enc_cpu_image = full_filename_enc, dec_cpu_image = full_filename_dec, size_image = full_filename_size)
