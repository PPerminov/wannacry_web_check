from flask import Flask, request, render_template
from wannacry import scan

app = Flask(__name__)


@app.route("/wannacry", methods=['GET', 'POST'])
def main_wannacry_check():
    answer = None
    error = None

    def main_page(answer=None, error=None):
        return render_template('index.html', error=error, answer=answer)
    if request.method == 'POST':
        answer = {'host': request.form['address'], 'status': {1: 'Bad IP or closed port',
                                                              6: 'can not detect vulnerable status',
                                                              5: 'is not vulnerable',
                                                              12: 'something happens',
                                                              4: 'is vulnerable',
                                                              3: 'pulsar injected'}[scan(request.form['address'])]}

    return main_page(answer, error)


if __name__ == "__main__":
    app.run(host='0.0.0.0')
