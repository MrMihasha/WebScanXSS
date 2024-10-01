from flask import Flask, render_template, request
from xss_check import scan_xss

app = Flask(__name__)

#Main app
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        stop_time = 180  # max time testing
        timeout = 20     # max time waiting
        results = scan_xss(url, stop_time, timeout)
        return render_template('result.html', url=url, results=results)
    return render_template('index.html')

# Info
@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    app.run(debug=True)
