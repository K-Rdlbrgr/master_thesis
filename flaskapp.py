from flask import Flask, render_template, request, url_for, redirect, flash, session
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import *
from sqlalchemy.orm import sessionmaker
from bitcoin import *
from oauthlib.oauth2 import WebApplicationClient
from redis import Redis
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
    UserMixin
)
import json
import os
import hashlib
import time
import datetime
import requests
import redis


# Initializing Flaskapp and setting the timelimit for the Sessions
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['PERMANENT_SESSION_LIFETIME']=datetime.timedelta(minutes=10)

# Setting up Google SignIn Configuration
# (Used env variables for setting the Google Client ID and Google CLient Secret)
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = ("https://accounts.google.com/.well-known/openid-configuration")

# User session management setup
# https://flask-login.readthedocs.io/en/latest
login_manager = LoginManager()
login_manager.init_app(app)

# We introduce the ENV variable to quickly switch on and off debug mode depending on if we just want to develop the app or deploy and use it. It also sets the connection to our postgres database

ENV = 'prod'

if ENV == 'dev':
    app.debug = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://postgres:thesis@localhost/master_thesis'
    GOOGLE_REDIRECT_ADDRESS = "https://127.0.0.1:5000/login/callback"
    VERIFICATION_REQUEST_URL = "https://127.0.0.1:5000/voting/"
    
else:
    app.debug = False
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
    GOOGLE_REDIRECT_ADDRESS = "https://votechain-sbe.herokuapp.com/login/callback"
    VERIFICATION_REQUEST_URL = "https://votechain-sbe.herokuapp.com/voting/"    
    SESSION_REDIS = redis.from_url(os.environ.get("REDIS_URL"))
    
    
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Setting up the Session
SESSION_TYPE = 'redis'
app.config.from_object(__name__)
Session(app)

# OAuth 2 client setup for the Google SignIn
client = WebApplicationClient(GOOGLE_CLIENT_ID)

# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Set Flask Login-Manager Login-View
login_manager.login_view = "login"

# We introduce our database model and define the different tables within the model  with all their columns

db = SQLAlchemy(app)

# The Users table contains all students eligible to vote in the election table and the id of their corresponding election
class Users(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey('elections.election_id'))
    email = db.Column(db.String(16), unique=True)

    def __init__(self, user_id, election_id, email):
        self.user_id = user_id
        self.election_id = election_id
        self.email = email

# The Election Table contains all the information being displayed online as well as their start and end time
class Elections(db.Model):
    __tablename__ = 'elections'
    election_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    start_time = db.Column(db.TIMESTAMP)
    end_time = db.Column(db.TIMESTAMP)
    program = db.Column(db.String(200))

    def __init__(self, election_id, name, start_time, end_time, program):
        self.election_id = election_id
        self.name = name
        self.start_time = start_time
        self.end_time = end_time
        self.program = program

# THe Candidates table contains all the information of the candidates such as the user_id and the name as well as the election_id they are candidating for
class Candidates(db.Model):
    __tablename__ = 'candidates'
    candidate_id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(
        db.Integer, db.ForeignKey('elections.election_id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    name = db.Column(db.String(100))
    program = db.Column(db.String(200))
    address = db.Column(db.String(34), unique=True)

    def __init__(self, candidate_id, election_id, user_id, name, program, address):
        self.candidate_id = candidate_id
        self.election_id = election_id
        self.user_id = user_id
        self.name = name
        self.program = program
        self.address = address

# The Votes Table is the actual Blockchain containing all the information necessary to ensure a secure connection between all the blocks.
class Votes(db.Model):
    __tablename__ = 'votes'
    hash = db.Column(db.String(64), primary_key=True)
    previous_hash = db.Column(db.String(64), unique=True)
    nonce = db.Column(db.Integer)
    timestamp = db.Column(db.TIMESTAMP)
    from_address = db.Column(db.String(300))
    to_address = db.Column(db.String(300))
    value = db.Column(db.Integer)
    signature = db.Column(db.String(88))

    def __init__(self, hash, previous_hash, nonce, timestamp, from_address, to_address, value, signature):
        self.hash = hash
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.timestamp = timestamp
        self.from_address = from_address
        self.to_address = to_address
        self.value = 1
        self.signature = signature
        
# The Vote_Check table is set up ahead of the elections and stores the correct version the user got directed to as well as the Boolean if the user already voted or not
class vote_check(db.Model):
    __tablename__ = 'vote_check'
    vote_check_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    election_id = db.Column(db.Integer, db.ForeignKey('elections.election_id'))
    already_voted = db.Column(db.Boolean)
    version = db.Column(db.String(1))
    
    def __init__(self, vote_check_id, user_id, election_id, already_voted, version):
        self.vote_check_id = vote_check_id
        self.user_id = user_id
        self.election_id = election_id
        self.already_voted = False
        self.version = version

# The Version_Control table has one row for each election and the corresponding last version of the app which was directed to a user. It is therefore crucial for making sure we get a balanced sample in the end
class version_control(db.Model):
    __tablename__ = 'version_control'
    version_control_id = db.Column(db.Integer, primary_key=True)
    latest_version = db.Column(db.String(1))
    election_id = db.Column(db.Integer, db.ForeignKey('elections.election_id'))
    
    def __init__(self, vesion_control_id, latest_version, election_id):
        self.version_control_id = version_control_id
        self.latest_version = latest_version
        self.election_id = election_id
        
# Establish a User class with the Flask module UserMixin which is used to support the Google SignIn

class User(UserMixin):
    def __init__(self, id, election_id, email):
        self.id = id
        self.election_id = election_id
        self.email = email
        
    @staticmethod
    def get(user_id):
        voter_query = f"""SELECT *
                          FROM users
                          WHERE user_id = {user_id}"""
        
        voter_result = engine.execute(voter_query)
        user = voter_result.first()
        
        if not user:
            return None

        user = User(
            id=user[0], election_id=user[1], email=user[2]
        )
        
        return user

# Functions considering Google SignIn
# Retrieving User Data from Google
def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

# Set Difficulty-Level for the Blockchain which makes sure we always have at least 3 0s in front of each hash
difficulty = 3

# Now we establish all functions which we need for creating and interacting with the Blockchain. So far, we just have every function connected to casting a vote (including providing a specified security level, hashing and so on). We still need to integrate the tallying function. The functions are leveraging the Bitcoin Module imported earlier

# This function calculates the Hash of a vote by taking all the information of a vote as inputs
def calculateHash(vote):
        return sha256((vote['previous_hash'] + vote['from_address'] + vote['to_address'] + str(vote['nonce']) + str(vote['value']) + str(vote['timestamp'])).encode('utf-8'))
 
# This function enables the minimum security(difficulty) level set earlier in the process. Increasing the difficulty level makes this process exponentially harder and longer   
def secureHash(vote, difficulty):
        while vote['hash'][0:difficulty] != ''.join(['0' for i in range(0, difficulty)]):
            vote['nonce'] += 1
            vote['hash'] = calculateHash(vote)
 
# This functions signs each vote with the user's private key to enable future verification
def signVote(vote, signingKey):
        if privtoaddr(signingKey) != vote['from_address']:
            print('You cannot sign transactions for other wallets!')
            return False
        else:
            sig = ecdsa_sign(vote['hash'], signingKey)
            vote['signature'] = sig
            return True

# This function is called each time a vote is about to be added to the Blockchain in order to finally check if the vote has a signature and addresses. It can also be called at any time in the future in order to verify if a vote is still valid
def isValid(vote, pubkey):
        if vote['from_address'] == None:
            return True
        try:
            if vote['signature'] == 0 or len(vote['signature']) == 0:
                print('No signature in this transaction')
        except:
            print('No signature in this transaction')
            return False

        return ecdsa_verify(calculateHash(vote), vote['signature'], pubkey)

# DB CONNECTION

# Creating the SQLAlchemy engine with an connnection pool of 20 to enable querying within the routes
engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
Session = sessionmaker(bind=engine)

# ROUTES

# In this part we define the different routes for the different pages. Within the routes we define what is happening when some inputs are posted to the website and which templates have to redirected to or rendered.

@app.route('/')

# Central Login Page for every Voter before being redirected to voting or verify
@app.route("/login")
def login():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=GOOGLE_REDIRECT_ADDRESS,
        scope=["openid", "email", "profile"],
        prompt="select_account",
    )
    return redirect(request_uri)

# Callback address from Google SignIn
@app.route("/login/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")
    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]
    # Prepare and send a request to get tokens! Yay tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))
    
    # Now that you have tokens, let's find and hit the URL
    # from Google that gives you the user's profile information,
    # including their Google profile image and email
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    
    # You want to make sure their email is verified.
    # The user authenticated with Google, authorized your
    # app, and now you've verified their email through Google!
    # We are also extracting the student-id based on the email
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        print(f'This is my Google ID {unique_id}')
        student_id = userinfo_response.json()["email"][0:5]
        users_email = userinfo_response.json()["email"]
        
    else:
        return "User email not available or not verified by Google.", 400
    
    # We need a check in this spot to see if the logged in user is part of our whitelist
    voter_query = f"""SELECT *
                      FROM users
                      WHERE user_id = {student_id}"""
        
    voter_result = engine.execute(voter_query)
    voter = voter_result.first()
    
    # If the User is part of the Whitelist, pass the voter into the User class and create an user object
    user = User(voter[0], voter[1], voter[2])
        
    # Begin user session by logging the user in
    login_user(user)
    voter_id = current_user.id
    
    # Start the Session Timeout Timer 
    session.permanent = True
    
    # QUERY to check if this variable corresponding to the already_voted boolean in the vote_check table of the link the user used. If it's false, proceed. If it's true, render the error of not able to vote twice
    already_voted_query = f"""SELECT already_voted FROM vote_check
                              WHERE user_id = '{voter_id}'"""
                    
    already_voted_results = engine.execute(already_voted_query)
    for r in already_voted_results:
        already_voted = r[0]
    # Close the ResultProxy to not risk open and unused DB connections
    already_voted_results.close()

    # Send user back to the application based on his voting status
    if already_voted == False:  
        return redirect(url_for("voting"))
    else:
        return redirect(url_for("verify"))

# Current Logout function for the Session (not in use so far since we are using session lifetime)
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# CENTRAL VOTING PAGE

@app.route('/voting/', methods=["GET", "POST"])
@login_required
def voting():
    # Making sure the User logged in with his Nova Account before entering this route
    if request.referrer == None:
        return redirect(url_for("login"))
    
    if request.method == "GET":
        
        # Getting the voter)id from current_user to render Election information
        voter_id = current_user.id
        
        # QUERY for the corresponding election and save that data
        voter_election_query = f"""SELECT e.election_id, e.name, e.start_time, e.end_time, e.program
                                   FROM elections AS e
                                   INNER JOIN users AS u
                                   ON e.election_id = u.election_id
                                   WHERE user_id = {voter_id}"""
        
        voter_election_results = engine.execute(voter_election_query)
        voter_election_result = voter_election_results.first()
        voter_election = {"election_id": voter_election_result[0],
                          "name": voter_election_result[1],
                          "start_time": voter_election_result[2],
                          "end_time": voter_election_result[3],
                          "program": voter_election_result[4]}
        
        # QUERY for the corresponding candidates and save that data
        election_candidates_query = f"""SELECT name
                                    FROM candidates
                                    WHERE election_id = {voter_election['election_id']}"""
        
        election_candidates_results = engine.execute(election_candidates_query)
        election_candidates = []
        
        # Also integrating a number key in the dictionary which is used in the HTML to distinguish radio buttons
        i = 1
        for candidate in election_candidates_results:
            election_candidates.append({"name": candidate[0],
                                        "number": i})
            i += 1
        # Close the ResultProxy to not risk open and unused DB connections
        election_candidates_results.close()
        
        return render_template('voting.html', election_candidates=election_candidates, voter_election=voter_election)   
    
# PROCESS PAGE
# This is were the User is redirected to after submitting their vote in the Voting Route
@app.route('/process/', methods=["GET", "POST"])
@login_required
def process():
    
    # Getting the voter)id from current_user to process the vote
    voter_id = current_user.id
    
    # QUERY to check if this variable corresponding to the already_voted boolean in the vote_check table of the link the user used. If it's false, proceed. If it's true, render the error of not able to vote twice
    already_voted_query = f"""SELECT already_voted FROM vote_check
                              WHERE user_id = '{voter_id}'"""
                    
    already_voted_results = engine.execute(already_voted_query)
    for r in already_voted_results:
        already_voted = r[0]
    # Close the ResultProxy to not risk open and unused DB connections
    already_voted_results.close()
    
    # Checking if the voter already voted and in case he did, render the pocess.html by passing in the corresponding error
    if already_voted == True:
        message = 'You already casted your vote for this election and you are not allowed to vote twice.'
        return render_template('process.html', message = message) 
        
    # QUERY the end_time/start_time of the corresponding Election in order to check if the election is still/already open
    time_query = f"""SELECT end_time, start_time
                     FROM elections as e
                     INNER JOIN users as u
                     ON e.election_id = u.election_id
                     WHERE user_id = {voter_id}"""
                         
    time_results = engine.execute(time_query)
    time_result = time_results.first()
    end_time = time_result[0]
    start_time = time_result[1]
    
    # Checking if the current voting approach is still valid regarding the end_time limit of the election
    if end_time < datetime.datetime.now():
        message = f'You cannot vote anymore since the election ended on {end_time.day}/{end_time.month}/{end_time.year} at {end_time.strftime("%H:%M:%S")}'
        return render_template('process.html', message = message)
    
    # Checking if the current voting approach is still valid regarding the start_time limit of the election
    if start_time > datetime.datetime.now():
        message = f'You cannot vote yet since the election just starts on {start_time.day}/{start_time.month}/{start_time.year} at {start_time.strftime("%H:%M:%S")}'
        return render_template('process.html', message = message)
    
    # Continuing with the Voting Process in case the user passes the first two crucial checks
    if request.method == "POST":
        
        # Creating User's KeyPair/Address and corresponding Sessions based on the Bitcoin Module
        user_privateKey = random_key()
        user_publicKey = privtopub(user_privateKey)
        user_address = pubtoaddr(user_publicKey)
        
        # Passing those Values in the current session to transfer them to the next route hidden from the user
        session['user_privateKey'] = user_privateKey
        session['user_publicKey'] = user_publicKey
        session['user_address'] = user_address
        
        # Accessing the input data from the User
        req = request.form
        candidate = req['candidate']
        
        # Querying the database to find the address of the candidate    
        address_query = f"""SELECT address FROM candidates
                            WHERE name = '{candidate}'"""
        
        address_results = engine.execute(address_query)
        for r in address_results:
            address = r[0]
        # Close the ResultProxy to not risk open and unused DB connections
        address_results.close()
        
        # Set error flag to false before checking for errors
        flag = False
        
        # Checking the blockchain if there is already a vote of the same address
        vote_twice_query = f"""SELECT * FROM votes
                               WHERE from_address = '{user_address}'"""
                    
        vote_twice_results = engine.execute(vote_twice_query)
        for r in vote_twice_results:
            if not len(r) == 0:
                print('Cannot vote twice')
                flag = True
        # Close the ResultProxy to not risk open and unused DB connections
        vote_twice_results.close() 

        #Check if both from and to address are given in the transaction
        if user_address == None or address == None:
            print('Transaction must include from and to address')
            flag = True
        
        # Creating a transaction to ensure jsut one block gets added at a time, to eliminate the chance of breaking the Blockchain
        connection = engine.connect()
        trans = connection.begin()    
        
        try:
            # Locking the Votes table before entering the critical querys for the block generation
            connection.execute('LOCK TABLE votes IN ACCESS EXCLUSIVE MODE;')
            
            # Querying the database to find the previous hash
            hash_query = """SELECT hash FROM votes
                            ORDER BY timestamp DESC
                            LIMIT 1"""
                        
            hash_results = connection.execute(hash_query)
            for r in hash_results:
                previous_hash = r[0]
            # Close the ResultProxy to not risk open and unused DB connections
            hash_results.close()               
                
            # Creating the vote as a dictionary to later add to the Blockchain
            new_vote = {'hash':'',
                        'previous_hash': previous_hash,
                        'nonce':0,
                        'timestamp':datetime.datetime.now(),
                        'from_address': user_address,
                        'to_address': address,
                        'value':1,
                        'signature': ''} 
            
            # Calculate the hash based on the information and secure it based on difficulty level
            new_vote['hash'] = calculateHash(new_vote)
            secureHash(new_vote, difficulty)
            
            # Sign the transaction and check if the transaction is valid
            if signVote(new_vote, user_privateKey):
                if not isValid(new_vote, user_publicKey):
                    print('Cannot add invalid transaction to chain')
                    flag = True
            else:
                flag = True

            # Add the vote to the Blockchain
            # The flag checks if any errors occured while creating the vote (e.g signature is missing, difficulty not met)
            if not flag:
                add_vote_query = f"""INSERT INTO votes (hash, previous_hash, nonce, timestamp, from_address, to_address, value, signature)
                                    VALUES ('{new_vote['hash']}', '{new_vote['previous_hash']}', {new_vote['nonce']}, '{new_vote['timestamp']}', '{new_vote['from_address']}', '{new_vote['to_address']}', {new_vote['value']}, '{new_vote['signature']}')"""
                        
                connection.execute(add_vote_query)
                # Commiting the changes which also Unlocks the votes table again
                trans.commit()
                print('Transaction on the Blockchain')
        
        # In case an error occured during the TRY, the transaction gets rolled back   
        except:
            trans.rollback()
            print('Got an except')
            
        # Finally the transaction gets closed to ensure no open idle connections
        finally:
            trans.close()
            print('I was here')
            
        if not flag:      
    
            # Add QUERY to switch boolean of already_voted in the vote_check table from False to True 
            update_already_voted_query = f"""UPDATE vote_check
                                            SET already_voted = True
                                            WHERE user_id = {voter_id}"""
                    
            engine.execute(update_already_voted_query)
            print('The already_voted status got updated')
            
            # Here the Version Control for the A/B Testing starts
            # Check which version was the last version
            latest_version_query = f"""SELECT latest_version
                                    FROM version_control as v
                                    INNER JOIN users as u
                                    ON v.election_id = u.election_id
                                    WHERE user_id = {voter_id}"""
                    
            latest_version_results = engine.execute(latest_version_query)
            latest_version_result = latest_version_results.first()
            latest_version = latest_version_result[0]
            
            # Select the version the voter gets displayed based on the last version
            if latest_version == 'A':
                voter_version = 'B'
                session['voter_version']=voter_version
            else:
                voter_version = 'A'
                session['voter_version']=voter_version
            
            # Update the database with the latest_version
            update_latest_version_query = f"""UPDATE version_control
                                            SET latest_version = '{voter_version}'
                                            FROM version_control AS v
                                            INNER JOIN users AS u
                                            ON v.election_id = u.election_id
                                            WHERE user_id = {voter_id}"""
                
            engine.execute(update_latest_version_query)
            print('The latest_version status got updated')
            
            # Update the used version for the voter in the database
            update_version_query = f"""UPDATE vote_check
                                    SET version = '{voter_version}'
                                    WHERE user_id = {voter_id}"""
                    
            engine.execute(update_version_query)
                
            return redirect(url_for('verification'))
        
        # If an Error occured somewhere along the isValid process the user will get a corresponding Error message
        else:
            message = 'Something went wrong while you were trying to cast your vote. To further investigate and solve this issue, please send an email to our support: 34638@novasbe.pt'
            return render_template('process.html', message = message)
        
        
# Verification Page

@app.route('/verification/', methods=["GET", "POST"])
@login_required
def verification():
    # Making sure the User logged in with his Nova Account before entering this route
    print(request.referrer)
    if request.referrer != VERIFICATION_REQUEST_URL:
        return redirect(url_for("login"))
    
    # Reset the Session Timer to grnt the User a maximum of 5 minutes before he has to login again for security reasons
    session.permanent = True
    
    # Get the version information from the session
    version = session['voter_version']
    
    # Get the user credentials from the process.html
    user_address = session['user_address']
    user_publicKey = session['user_publicKey']
    user_privateKey = session['user_privateKey']
    
    # Create empty list for Blockchain which will result in a list of dictionaries
    blockchain = []
    
    # Query data for visualizing the Blockchain
    blockchain_query = """SELECT * 
                          FROM votes
                          ORDER BY timestamp"""
    
    blockchain_results = engine.execute(blockchain_query)
    
    # Adding one block to the blockchain for every vote including a color for every hash and previous hash which will be used to visually emphazise the connections between each vote on the Blockchain
    counter = 0
    color_counter = 0
    previous_color_counter = 7
    colors = ['goldenrod', 'violet', 'lawngreen', 'yellow', 'magenta', 'palegreen', 'orangered', 'cyan']
    
    for vote in blockchain_results:
        counter += 1
        if color_counter > 7:
            color_counter = 0
        if previous_color_counter > 7:
            previous_color_counter = 0
            
        blockchain.append({'block_number': counter,
                            'hash': vote[0],
                            'previous_hash': vote[1],
                            'nonce': vote[2],
                            'timestamp': vote[3],
                            'from_address': vote[4],
                            'to_address': vote[5],
                            'value': vote[6],
                            'signature': vote[7],
                            'color': colors[color_counter],
                            'previous_color': colors[previous_color_counter]})
        
        color_counter += 1
        previous_color_counter += 1
        
    # Close the ResultProxy to not risk open and unused DB connections
    blockchain_results.close()
    
    return render_template('verification.html',user_address=user_address, user_publicKey=user_publicKey, user_privateKey=user_privateKey, version=version, blockchain=blockchain)
    
@app.route('/verify/', methods=["GET", "POST"])
@login_required
def verify():
    # Making sure the User logged in with his Nova Account before entering this route
    if request.referrer == None:
        return redirect(url_for("login"))
    
    # Error Handling in Chrome if there is no existing session
    try:
        version = session['voter_version']
        
    except KeyError:
        voter_id = current_user.id
        
        # Query the corresponding version(A/B) to render for each user
        version_control_query = f"""SELECT version
                                    FROM vote_check
                                    WHERE user_id = {voter_id}"""
                
        version_control_results = engine.execute(version_control_query)
        version_control_result = version_control_results.first()
        version = version_control_result[0]
        
        # Initialize the Session Version
        session['voter_version'] = version
        
        print(f'We are n the Verify Page and the version is {version}')
        print(f'We are n the Verify Page and the voter_id is {voter_id}')
        
    # The system distinguishes between a user coming from the Google SignIn or the verification/verify route since coming from the latter means the system has to perform the Verify Your Vote feature
    if request.method == "POST":
        
        # Create empty list for Blockchain which will result in a list of dictionaries
        blockchain = []
        
        # Query data for visualizing the Blockchain
        blockchain_query = """SELECT * 
                              FROM votes
                              ORDER BY timestamp""" 
        
        blockchain_results = engine.execute(blockchain_query)
        
        # Adding one block to the blockchain for every vote including a color for every hash and previous hash which will be used to visually emphazise the connections between each vote on the Blockchain
        counter = 0
        color_counter = 0
        previous_color_counter = 7
        colors = ['goldenrod', 'violet', 'lawngreen', 'yellow', 'magenta', 'palegreen', 'orangered', 'cyan']
        
        for vote in blockchain_results:
            counter += 1
            if color_counter > 7:
                color_counter = 0
            if previous_color_counter > 7:
                previous_color_counter = 0
                
            blockchain.append({'block_number': counter,
                               'hash': vote[0],
                               'previous_hash': vote[1],
                               'nonce': vote[2],
                               'timestamp': vote[3],
                               'from_address': vote[4],
                               'to_address': vote[5],
                               'value': vote[6],
                               'signature': vote[7],
                               'color': colors[color_counter],
                               'previous_color': colors[previous_color_counter]})
            
            color_counter += 1
            previous_color_counter += 1
        
        # Close the ResultProxy to not risk open and unused DB connections
        blockchain_results.close()
        
        # Getting the user input of the verify your vote form which should be their private key
        req = request.form
        
        # Use the private key to generate the corresponding address in case of a string that is actually 64 characters long
        if len(req['private_key']) == 64:
            vote_from_address = privtoaddr(req['private_key'])
        else:
            # Pass along a flash message to the HTML if this error occurs
            print('This is not a private key')
            flash('This is not a private key', 'no_private_key_fail')
            return render_template('verify.html', version=version, blockchain=blockchain)
        
        # QUERY to find the correct transaction based on the address (address is unique, so there will be a maximum of one row)
        verify_vote_query = f"""SELECT * FROM votes
                                WHERE from_address = '{vote_from_address}'"""
        
        verify_vote_results = engine.execute(verify_vote_query)
        verify_vote_result = verify_vote_results.first()
        
        # Check if there is an entry for the entered private key:
        if verify_vote_result == None:
            # Pass along a flash message to the HTML if this error occurs
            print('There is no corresponding vote to this private key')
            flash('There is no corresponding vote to this private key', 'wrong_private_key_fail')
            return render_template('verify.html', version=version, blockchain=blockchain)
        
        # Query for candidate name
        candidate_query = f"""SELECT name FROM candidates
                              WHERE address = '{verify_vote_result[5]}'"""
        
        candidate_results = engine.execute(candidate_query)
        candidate_result = candidate_results.first()
        
        # If the user input actually matches with a private key used for casting a vote which is on the Blockchain, the system found the vote and stored the data into a variable. That is now used to create a dictionary which is passed along to the HTML
        
        # Create a dictionary with the found transaction:
        casted_vote = {'hash': verify_vote_result[0],
                       'previous_hash': verify_vote_result[1],
                       'nonce': verify_vote_result[2],
                       'timestamp': verify_vote_result[3],
                       'from_address': verify_vote_result[4],
                       'to_address': verify_vote_result[5],
                       'candidate': candidate_result[0],
                       'value': verify_vote_result[6],
                       'signature': verify_vote_result[7],}
            
        return render_template('verify.html', casted_vote=casted_vote, version=version, blockchain=blockchain)
    
    else:
        # Create empty list for Blockchain which will result in a list of dictionaries
        blockchain = []
        
        # Query data for visualizing the Blockchain
        blockchain_query = """SELECT * 
                              FROM votes
                              ORDER BY timestamp""" 
        
        blockchain_results = engine.execute(blockchain_query)
        
        # Adding one block to the blockchain for every vote including a color for every hash and previous hash which will be used to visually emphazise the connections between each vote on the Blockchain
        counter = 0
        color_counter = 0
        previous_color_counter = 7
        colors = ['goldenrod', 'violet', 'lawngreen', 'yellow', 'magenta', 'palegreen', 'orangered', 'cyan']
        
        for vote in blockchain_results:
            counter += 1
            if color_counter > 7:
                color_counter = 0
            if previous_color_counter > 7:
                previous_color_counter = 0
                
            blockchain.append({'block_number': counter,
                               'hash': vote[0],
                               'previous_hash': vote[1],
                               'nonce': vote[2],
                               'timestamp': vote[3],
                               'from_address': vote[4],
                               'to_address': vote[5],
                               'value': vote[6],
                               'signature': vote[7],
                               'color': colors[color_counter],
                               'previous_color': colors[previous_color_counter]})
            
            color_counter += 1
            previous_color_counter += 1
            
        # Close the ResultProxy to not risk open and unused DB connections
        blockchain_results.close()
        
        return render_template('verify.html', version=version, blockchain=blockchain)

# Before running the app we check in which mdoe (development/production) we are
if ENV == 'dev':
    if __name__ == "__main__":
        app.run(ssl_context='adhoc')
        
else:
    if __name__ == "__main__":
        app.run(threaded=True, port=5000)