from flask import Flask, render_template, request, url_for, redirect, flash
import time

app = Flask(__name__)
app.secret_key = b'\xa3\x14\xa1B]\x8a\xda\xd3\xbf\xbf\x03E{\x1aYx'

user_db = [{'id': '34638', 'email': '34638@novasbe.pt', 'password': 'kevin'},
           {'id': '34646', 'email': '34646@novasbe.pt', 'password': 'nina'}]
votes_db = []
elections_db = [{'id': '1', 'name': 'Student Representatives Msc Finance 2019', 'allowed_voters': ['34638', '34646'], 'options': ['Alice', 'Bob', 'Charlie', 'Daniel']},
                {'id': '2', 'name': 'University President 2019', 'allowed_voters': ['34646'], 'options': ['President 1', 'President 2']}]


class user:
    def __init__(self, id, email, password):
        self.id = id
        self.email = email
        self.password = password


class vote:
    def __init__(self, id, election_id, user_id, option):
        self.id = id
        self.election_id = election_id
        self.user_id = user_id
        self.option = option
        self.timestamp = time.time()


@app.route('/')
@app.route('/home/')
def home():
    return render_template('index.html')


@app.route('/users/', methods=["GET", "POST"])
def users():
    if request.method == "POST":
        req = request.form
        if len(req) == 2:
            if login(req['login-email'], req['login-password']):
                return redirect(url_for('elections'))
            else:
                return render_template('users.html')
        elif len(req) == 3:
            if register(req['register-email'], req['register-password'],
                        req['register-password-confirm']):
                return redirect(url_for('elections'))
            else:
                return render_template('users.html')
    else:
        return render_template('users.html')


@app.route('/elections/', methods=["GET", "POST"])
def elections():
    if request.method == "POST":
        elections = elections_db
        req = request.form
        cast_ballot(req['voting-email'], req['voting-password'],
                    req['voting-option'], req['election-id'])
        return render_template('elections.html', elections=elections)
    else:
        elections = elections_db
        for election in elections:
        return render_template('elections.html', elections=elections)


# FUNCTIONS
def cast_ballot(email, password, option, election_id):
    for election in elections_db:
        if election_id == election['id']:
            if email[0:5] in election['allowed_voters']:
                for user in user_db:
                    if email[0:5] == user['id']:
                        if password == user['password']:
                            counter = 0
                            for vote in votes_db:
                                if email[0:5] == vote['user_id'] and election_id == vote['election_id']:
                                    flash(
                                        'You cannot vote twice on the same election!', 'multiple-fail-' + election_id)
                                    print(
                                        'You cannot vote twice on the same election!')
                                    return False
                                else:
                                    counter += 1
                            if counter == len(votes_db):
                                votes_db.append({'id': str((len(votes_db)+1)), 'election_id': election_id,
                                                 'user_id': email[0:5], 'option': option, 'timestamp': time.time()})
                                flash('You succesfully casted your ballot!',
                                      'ballot-success-' + election_id)
                                print(
                                    'You succesfully casted your ballot! ballot-success-' + election_id)
                                return True
                        else:
                            flash(
                                'You did not enter the correct password!', 'password-fail-' + election_id)
                            print('You did not enter the correct password!')
                            return False
            else:
                flash(
                    'You are not eligable to vote in this election or you did not enter your email-correct!', 'email-fail-' + election_id)
                print(
                    'You are not eligable to vote in this election or you did not enter your email-correct!')
                return False


def login(email_input, password_input):
    counter = 0
    for user in user_db:
        if user['email'] == email_input and user['password'] == password_input:
            flash('You were successfully logged in', 'login-success')
            print('You succesfully logged in!')
            return True
        else:
            counter += 1
    if counter == len(user_db):
        flash('The email or password are not correct.', 'login-fail')
        print('The email or password are not correct.')
        return False


def register(email_input, password_input, password_rep_input):
    counter = 0
    for user in user_db:
        if user['email'] == email_input:
            flash('This email is already registered.', 'register-email')
            print('This email is already registered.')
            return False
        else:
            counter += 1
    if counter == len(user_db):
        if password_input != password_rep_input:
            flash('The passwords do not match!', 'register-password')
            print('The passwords do not match!')
            return False
        else:
            user_db.append(
                {'id': email_input[0:5], 'email': email_input, 'password': password_input})
            flash('You successfully registered!', 'register-success')
            print('You successfully registered!')
            return True


if __name__ == "__main__":
    app.run(debug=True)
