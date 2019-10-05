from flask import Flask, render_template, request, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
import time

ENV = 'dev'

if ENV == 'dev':
    app.debug = True
else:
    app.debug = False

app = Flask(__name__)
app.secret_key = b'\xa3\x14\xa1B]\x8a\xda\xd3\xbf\xbf\x03E{\x1aYx'

# Before implementing an SQL database (preferably using PostreSQL) we determine some example users, elections and an empty votes list where we store all the casted votes inside. All of the current attributes are just the starting point. We can add some more later on like hashing, timestamps, time limits for the elections and so on.

user_db = [{'id': '34638', 'email': '34638@novasbe.pt', 'password': 'kevin'},
           {'id': '34646', 'email': '34646@novasbe.pt', 'password': 'nina'}]
votes_db = []
elections_db = [{'id': '1', 'name': 'Student Representatives Msc Finance 2019', 'allowed_voters': ['34638', '34646'], 'options': ['Alice', 'Bob', 'Charlie', 'Daniel']},
                {'id': '2', 'name': 'University President 2019', 'allowed_voters': ['34646'], 'options': ['President 1', 'President 2']}]

# Here we establish two classes based on the example above which are not used in the following code so far since I'm not sure if it actually makes more sense to use the classes in combination with the SQL database than just working with dictionaries.


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

# In this part we define the different routes for the different pages. Within the routes we define what is happening when some inputs are posted to the website and which templates have to redirected to or rendered.


@app.route('/')
@app.route('/home/')
def home():
    return render_template('index.html')

# The user route so far contains the sign up and sign in functionalities. If no data is posted it just renders the user.html. If some data is posted the function identifies (by checking the lengths of the input) if a sign in or a sign up is being processed. Afterwards it uses the corresponding functions to login the user by checking its credentials or creating a new one with the posted input information.


@app.route('/users/', methods=["GET", "POST"])
def users():
    if request.method == "POST":
        req = request.form
        print(req)
        if req['form-type'] == 'login':
            if login(req['login-email'], req['login-password']):
                return redirect(url_for('elections'))
            else:
                return render_template('users.html')
        elif req['form-type'] == 'register':
            if register(req['register-email'], req['register-password'],
                        req['register-password-confirm']):
                return redirect(url_for('elections'))
            else:
                return render_template('users.html')
    else:
        return render_template('users.html')

# First, the election route takes the election databse information to render the the elections.html with all the ongoing elections and displays them. Second, it gets the posted input values from the user and cast the ballot by adding the vote to the votes database.


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
        return render_template('elections.html', elections=elections)


# FUNCTIONS

# The cast_ballot functions takes the input from the elections.html route. Going through the function it checks the following criteria in the listed order:
    # - Looping through the election database until the right election for the casted ballot is found
    # - Checking if the entered email is part of the allowed voters for that election
    # - Looping through the user database until the right user is found and checking if the entered password matches the password in the database in order to successfully validate the user
    # - Looping through the already casted votes in order to check if the user did not already casted a ballot for this election or not
    # - If every single criteria is successfully validated, the vote is being added to the votes database and a flash message is send to the template, giving the user feedback that his ballot was successflly casted.
    # - If any of the criteria was not met, the user gets a flash message about the specific error

# Explanation Flash Messages
# The flash message contains two inputs, the actual message which is being displayed on the website and the category of the message which we can use to determine the styling and positioning of the flash message on the website.

def cast_ballot(email, password, option, election_id):
    errors = []
    for election in elections_db:
        if election_id == election['id']:
            if email[0:5] not in election['allowed_voters']:
                errors.append('email-fail')
                flash('You are not eligable to vote in this election or you did not enter your email-correct!',
                      'email-fail-' + election_id)
                print(
                    'You are not eligable to vote in this election or you did not enter your email-correct!')
    for user in user_db:
        if email[0:5] == user['id']:
            if password != user['password']:
                errors.append('password-fail')
                flash('You did not enter the correct password!',
                      'password-fail-' + election_id)
                print('You did not enter the correct password!')
    for vote in votes_db:
        if email[0:5] == vote['user_id'] and election_id == vote['election_id']:
            errors.append('multiple-fail')
            flash('You cannot vote twice on the same election!',
                  'multiple-fail-' + election_id)
            print('You cannot vote twice on the same election!')
    if len(errors) == 0:
        votes_db.append({'id': str((len(votes_db)+1)), 'election_id': election_id,
                         'user_id': email[0:5], 'option': option, 'timestamp': time.time()})
        flash('You succesfully casted your ballot!',
              'ballot-success-' + election_id)
        print('You succesfully casted your ballot! ballot-success-' + election_id)
        return True
    else:
        print(errors)
        return False

# The login function takes the credentials input from the users.html and loops through the user database in order to find the entered email and check if the entered password matches the one in the user database. Depending on the outcome it again sends a flash message to the template for giving the user feedback oabout the result of the login.


def login(email_input, password_input):
    for user in user_db:
        if user['email'] == email_input and user['password'] == password_input:
            flash('You were successfully logged in', 'login-success')
            print('You succesfully logged in!')
            return True
    flash('The email or password are not correct.', 'login-fail')
    print('The email or password are not correct.')
    return False

# Thre register function does take the email and twice the password to make sure there are no typos in it from the form as an input. It checks if the entered email is not registered yet and if the passwords match each other. If successfull, it adds the user to the suer database. Again, the function sends flash messages as feedback to the user


def register(email_input, password_input, password_rep_input):
    for user in user_db:
        if user['email'] == email_input:
            flash('This email is already registered.', 'register-email')
            print('This email is already registered.')
            return False
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
    app.run()
