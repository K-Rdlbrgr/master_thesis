from flask import Flask, render_template, request, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import *
from bitcoin import *
import json
import hashlib
import time
import datetime

app = Flask(__name__)
app.secret_key = b'\xa3\x14\xa1B]\x8a\xda\xd3\xbf\xbf\x03E{\x1aYx'

# We introduce the ENV variable to quickly switch on and off debug mode depending on if we just want to develop the app or deploy and use it. It also sets the connection to our postgres database

ENV = 'dev'

if ENV == 'dev':
    app.debug = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:thesis@localhost/master_thesis'
else:
    app.debug = False
    app.config['SQLALCHEMY_DATABASE_URI'] = ''

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# We introduce our database model and define the different tables within the model  with all their columns

db = SQLAlchemy(app)


class Users(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey('elections.election_id'))
    email = db.Column(db.String(16), unique=True)
    password = db.Column(db.String(64))

    def __init__(self, user_id, election_id, email, password):
        self.user_id = user_id
        self.election_id = election_id
        self.email = email
        self.password = password


class Elections(db.Model):
    __tablename__ = 'elections'
    election_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    start_time = db.Column(db.TIMESTAMP)
    end_time = db.Column(db.TIMESTAMP)
    program = db.Column(db.String(50))

    def __init__(self, election_id, name, start_time, end_time, program):
        self.election_id = election_id
        self.name = name
        self.start_time = start_time
        self.end_time = end_time
        self.program = program


class Candidates(db.Model):
    __tablename__ = 'candidates'
    candidate_id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(
        db.Integer, db.ForeignKey('elections.election_id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    name = db.Column(db.String(100))
    program = db.Column(db.String(50))
    address = db.Column(db.String(34), unique=True)

    def __init__(self, candidate_id, election_id, user_id, name, program, address):
        self.candidate_id = candidate_id
        self.election_id = election_id
        self.user_id = user_id
        self.name = name
        self.program = program
        self.address = address


class Votes(db.Model):
    __tablename__ = 'votes'
    hash = db.Column(db.String(64), primary_key=True)
    previous_hash = db.Column(db.String(64))
    nonce = db.Column(db.Integer)
    timestamp = db.Column(db.TIMESTAMP)
    from_address = db.Column(db.String(300))
    to_address = db.Column(db.String(300))
    value = db.Column(db.Integer)

    def __init__(self, hash, previous_hash, nonce, timestamp, from_address, to_address, value):
        self.hash = hash
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.timestamp = timestamp
        self.from_address = from_address
        self.to_address = to_address
        self.value = 1

# Now we establish the classes which we need for creating the Blockchain. First, we need the Transaction class which corresponds to one vote and one block on the chain. Then we construct the Blockchain class connecting all those transactions. Every functions we need to interact with the Blockchain is already implemented as methods in the classes.

# 1. The Transactions class:


# Set Difficulty

difficulty = 3

class Transaction:
    def __init__(self, timestamp, fromAddress, toAddress, previousHash=''):
        self.fromAddress = fromAddress
        self.toAddress = toAddress
        self.previousHash = previousHash
        self.amount = 1
        self.timestamp = timestamp
        self.nonce = 0
        self.hash = self.calculateHash()

    def calculateHash(self):
        return sha256((self.previousHash + self.fromAddress + self.toAddress + str(self.nonce) + str(self.amount) + str(self.timestamp)).encode('utf-8'))

    # The secureHash method imitates mining. It forces the system to recalculate the hash until the required difficulty is matched, meaning a minimm number of 0s is placed at the start of the hash

    def secureHash(self, difficulty):
        while self.hash[0:difficulty] != ''.join(['0' for i in range(0, difficulty)]):
            self.nonce += 1
            self.hash = self.calculateHash()

    def signTransaction(self, signingKey):
        if privtopub(signingKey) != self.fromAddress:
            print('You cannot sign transactions for other wallets!')
            return False
        else:
            sig = ecdsa_sign(self.hash, signingKey)
            self.signature = sig
            return True

    def isValid(self):
        if self.fromAddress == None:
            return True
        try:
            if self.signature == 0 or len(self.signature) == 0:
                print('No signature in this transaction')
        except:
            print('No signature in this transaction')
            return False

        return ecdsa_verify(self.calculateHash(), self.signature, self.fromAddress)

# 2. The Blockchain class:

class Blockchain:
    def __init__(self):
        self.chain = [self.createGenesisTransaction()]
        self.difficulty = 1
        self.pendingTransactions = []
        self.miningReward = 100

    def createGenesisTransaction(self):
        return Transaction('13/11/2019', 'Genesis Transaction', 'Genesis Transaction')

    def getLatestTransaction(self):
        return self.chain[len(self.chain)-1]

    # Here the actual vote from above gets created, signed and checked if everything is filled in correctly

    def addTransaction(self, fromAddress, toAddress, signingKey):
        flag = False
        for trans in self.chain:
            if trans.fromAddress == 'Genesis Transaction':
                continue
            elif trans.fromAddress == fromAddress:
                print('Cannot vote twice')
                flag = True

        if fromAddress == None or toAddress == None:
            print('Transaction must include from and to address')
            flag = True

        newTx = Transaction(time.time(), fromAddress, toAddress,
                            self.getLatestTransaction().hash)
        newTx.secureHash(self.difficulty)
        if newTx.signTransaction(signingKey):
            if not newTx.isValid():
                print('Cannot add invalid transaction to chain')
                flag = True
        else:
            flag = True

        if not flag:
            self.chain.append(newTx)
            print('Transaction on the CHAIN')

    # The method usually responsible for calculating the balance of a specific address will be used to count the votes of a candidate

    def getBalanceOfAddress(self, address):
        balance = 0

        for trans in self.chain:
            if trans.fromAddress == 'Genesis Transaction':
                continue
            else:
                if trans.fromAddress == address:
                    print(trans.amount)
                    balance -= int(trans.amount)
                if trans.toAddress == address:
                    balance += trans.amount

        return balance

    # This method can be used to verify an individual vote after the user stated his private key

    def getAllTransactionsForWallet(self, address):
        txs = []

        for trans in self.chain:
            if trans.fromAddress == 'Genesis Transaction':
                continue
            elif trans.fromAddress == address or trans.toAddress == address:
                txs.append(trans)

        return txs

    # We don't have to use this function but could either use it internally for us to keep track of the blockchain, checking it every now and then or even include it in the verification page. Hence, the user would be able to check with a button if the whole chain is valid

    def isChainValid(self):
        realGenesis = json.dumps(
            self.createGenesisTransaction(), default=lambda x: x.__dict__)
        if realGenesis != json.dumps(self.chain[0], default=lambda x: x.__dict__):
            return False

        for i in range(1, len(self.chain)):
            currentTransaction = self.chain[i]
            previousTransaction = self.chain[i-1]

            if currentTransaction.hash != currentTransaction.calculateHash():
                print(f'\nTransaction Number {i} got manipulated')
                return False

            if currentTransaction.previousHash != previousTransaction.hash:
                print(
                    f'\nLink between Transaction {i} and {i-1} got destroyed by an malicious attack')
                return False

        return True

# Transition from Blockchain classes and methods to normal functions

def calculateHash(vote):
        return sha256((vote['previous_hash'] + vote['from_address'] + vote['to_address'] + str(vote['nonce']) + str(vote['value']) + str(vote['timestamp'])).encode('utf-8'))
    
def secureHash(vote, difficulty):
        while vote['hash'][0:difficulty] != ''.join(['0' for i in range(0, difficulty)]):
            vote['nonce'] += 1
            vote['hash'] = calculateHash(vote)
            
def signVote(vote, signingKey):
        if privtoaddr(signingKey) != vote['from_address']:
            print('You cannot sign transactions for other wallets!')
            return False
        else:
            sig = ecdsa_sign(vote['hash'], signingKey)
            vote['signature'] = sig
            return True

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

# Before implementing an SQL database (preferably using PostreSQL) we determine some example users, elections and an empty votes list where we store all the casted votes inside. All of the current attributes are just the starting point. We can add some more later on like hashing, timestamps, time limits for the elections and so on.

user_db = [{'id': '34638', 'email': '34638@novasbe.pt', 'password': 'kevin'},
           {'id': '34646', 'email': '34646@novasbe.pt', 'password': 'nina'}]
votes_db = []
elections_db = [{'id': '1', 'name': 'Student Representatives Msc Finance 2019', 'allowed_voters': ['34638', '34646'], 'options': ['Alice', 'Bob', 'Charlie', 'Daniel']},
                {'id': '2', 'name': 'University President 2019', 'allowed_voters': ['34646'], 'options': ['President 1', 'President 2']}]

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

# Central Voting Page

@app.route('/voting/', methods=["GET", "POST"])
def voting():
    if request.method == "POST":
        return render_template('voting.html')
    else:
        user_privateKey = random_key()
        user_publicKey = privtopub(user_privateKey)
        user_address = pubtoaddr(user_publicKey)
        print(user_address)
        
        
        return render_template('voting.html')
    
# Process Page

@app.route('/process/', methods=["GET", "POST"])
def process():
    if request.method == "POST":
        
        # Creating User's KeyPair and Address
        user_privateKey = random_key()
        user_publicKey = privtopub(user_privateKey)
        user_address = pubtoaddr(user_publicKey)
        
        # Accessing the input data from the User
        req = request.form
        print(req)
        candidate = req['candidate']
        
        # Querying the database to find the previous hash
        hash_query = """SELECT hash FROM votes
                    ORDER BY timestamp DESC
                    LIMIT 1"""
                    
        engine = create_engine('postgresql+psycopg2://postgres:thesis@localhost/master_thesis')
        hash_results = engine.execute(hash_query)
        for r in hash_results:
            previous_hash = r[0]
            
        # Querying the database to find the address of the candidate    
        address_query = f"""SELECT address FROM candidates
                        WHERE name = '{candidate}'"""
        
        engine = create_engine('postgresql+psycopg2://postgres:thesis@localhost/master_thesis')
        address_results = engine.execute(address_query)
        for r in address_results:
            address = r[0]
            
        # Creating the vote as a dictionary to later add to the Blockchain
        new_vote = {'hash':'',
                    'previous_hash': previous_hash,
                    'nonce':0,
                    'timestamp':datetime.datetime.now(),
                    'from_address': user_address,
                    'to_address': address,
                    'value':1,
                    'signature': ''} 
        
        # Set error flag to false before checking for errors
        flag = False
        
        # Checking the blockchain if there is already a vote of the same address
        vote_twice_query = f"""SELECT * FROM votes
                            WHERE from_address = '{new_vote['from_address']}'"""
                    
        engine = create_engine('postgresql+psycopg2://postgres:thesis@localhost/master_thesis')
        vote_twice_results = engine.execute(vote_twice_query)
        for r in vote_twice_results:
            if not len(r) == 0:
                print('Cannot vote twice')
                flag = True
        
        # for trans in self.chain:
        #     if trans.fromAddress == 'Genesis Transaction':
        #         continue
        #     elif trans.fromAddress == fromAddress:
        #         print('Cannot vote twice')
        #         flag = True

        #Check if both from and to address are given in the transaction
        if new_vote['from_address'] == None or new_vote['to_address'] == None:
            print('Transaction must include from and to address')
            flag = True
        
        # Calculate the hash based on the information and secure it
        print(new_vote)
        new_vote['hash'] = calculateHash(new_vote)
        secureHash(new_vote, difficulty)
        
        # Sign the transaction and check if the transaction is valid
        if signVote(new_vote, user_privateKey):
            if not isValid(new_vote, user_publicKey):
                print('Cannot add invalid transaction to chain')
                flag = True
        else:
            flag = True
            
        print(new_vote)

        #Add the vote to the Blockchain
        if not flag:
            add_vote_query = f"""INSERT INTO votes (hash, previous_hash, nonce, timestamp, from_address, to_address, value, signature)
                                VALUES ('{new_vote['hash']}', '{new_vote['previous_hash']}', {new_vote['nonce']}, '{new_vote['timestamp']}', '{new_vote['from_address']}', '{new_vote['to_address']}', {new_vote['value']}, '{new_vote['signature']}')"""
                    
            engine = create_engine('postgresql+psycopg2://postgres:thesis@localhost/master_thesis')
            engine.execute(add_vote_query)
            print('Transaction on the CHAIN')
        
        return render_template('process.html')

# Verification Page

@app.route('/verification/', methods=["GET", "POST"])
def verification():
    if request.method == "POST":
        return render_template('verification.html')
    else:
        return render_template('verification.html')


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
