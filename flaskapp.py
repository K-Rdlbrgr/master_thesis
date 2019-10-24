from flask import Flask, render_template, request, url_for, redirect, flash, session
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import *
from bitcoin import *
import json
import hashlib
import time
import datetime


# Initializing Flaskapp
app = Flask(__name__)
app.secret_key = b'\xa3\x14\xa1B]\x8a\xda\xd3\xbf\xbf\x03E{\x1aYx'

# Setting up the Session
SESSION_TYPE = 'redis'
app.config.from_object(__name__)
Session(app)

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
        
    # Proposed Solution for Double Spending
    class vote_check(db.Model):
        __tablename__ = 'vote_check'
        vote_check_id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
        election_id = db.Column(db.Integer, db.ForeignKey('elections.election_id'))
        link = db.Column(db.String(300), unique=True)
        already_voted = db.Column(db.Boolean)
        
        def __init__(self, vote_check_id, user_id, election_id, link, already_voted):
            self.vote_check_id = vote_check_id
            self.user_id = user_id
            self.election_id = election_id
            self.link = link
            self.already_voted = False

# Now we establish the classes which we need for creating the Blockchain. First, we need the Transaction class which corresponds to one vote and one block on the chain. Then we construct the Blockchain class connecting all those transactions. Every functions we need to interact with the Blockchain is already implemented as methods in the classes.

# Set Difficulty

difficulty = 3

# 1. The Transactions class:

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

# Link generation for the users
# 1. Get all user_ids from the users table in the database and store them
# 2. Loop through all the user_ids and use sha256 to encrypt it
# 3. Add the encryption to the general link www.herokuaddress.io/voting/?source= the hashed user_id
# 4. We store the link in the vote_check table in the database where we can also access it to give communications the links

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
    # else:
    if request.method == "GET":
        
        # Translate Hash of link into student id
        args = request.args.to_dict()
        voter_id_hash = args['source']
        
        voter_id_hash_query = f"""SELECT user_id
                                FROM vote_check
                                WHERE link = '{voter_id_hash}'"""
        
        engine = create_engine('postgresql+psycopg2://postgres:thesis@localhost/master_thesis')
        voter_id_hash_results = engine.execute(voter_id_hash_query)
        voter_id_hash_result = voter_id_hash_results.first()
        voter_id = voter_id_hash_result[0]
        
        # Initialize the Session User_ID and Voter_ID_Hash
        session['voter_id'] = voter_id
        session['voter_id_hash'] = voter_id_hash
        
        # Information about student will be gathered by using the link
        # USE SESSIONS TO PASS VALUES LIKE KEYS AND 
        # voter_id = 34646
        
        # QUERY for the corresponding election and save that data
        voter_election_query = f"""SELECT e.election_id, e.name, e.start_time, e.end_time, e.program
                                FROM elections AS e
                                INNER JOIN users AS u
                                ON e.election_id = u.election_id
                                WHERE user_id = {voter_id}"""
        
        engine = create_engine('postgresql+psycopg2://postgres:thesis@localhost/master_thesis')
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
        
        engine = create_engine('postgresql+psycopg2://postgres:thesis@localhost/master_thesis')
        election_candidates_results = engine.execute(election_candidates_query)
        election_candidates = []
        i = 1
        for candidate in election_candidates_results:
            election_candidates.append({"name": candidate[0],
                                        "number": i})
            i += 1
        
        return render_template('voting.html', election_candidates=election_candidates, voter_election=voter_election)
    
# Process Page

@app.route('/process/', methods=["GET", "POST"])
def process():
    # HERE we need to insert a condition in order to check if the voter alreday voted or not using the unique link they got via mail. Because afterwards the keys get generated which are different each time. This would allow users to vote over and over again because their addresses would change constantly.
    # A possible solution would be another table in the database with the user_id, the corresponding link and a boolean value for already_voted that switches to True once, the vote got processed and added to the blockchain. Doing so, we would also be able to see who voted or not, regarding additional information for the survey.
    
    # ADD the correct lines of code to get the url or the embedded data (probably user_id/user e-mail and election_id) and save it to a variable
    # For now
    # user_link = 'personalized_link'
    voter_id = session['voter_id']
    print(f'Process is using the user id: {voter_id}')
    
    # QUERY to check if this variable corresponding to the already_voted boolean in the vote_check table of the link the user used. If it's false, proceed. If it's true, render the error of not able to vote twice
    already_voted_query = f"""SELECT already_voted FROM vote_check
                            WHERE user_id = '{voter_id}'"""
                    
    engine = create_engine('postgresql+psycopg2://postgres:thesis@localhost/master_thesis')
    already_voted_results = engine.execute(already_voted_query)
    for r in already_voted_results:
        already_voted = r[0]
        print(already_voted)
    
    if request.method == "POST" and already_voted == False:
        
        # Creating User's KeyPair and Address
        user_privateKey = random_key()
        user_publicKey = privtopub(user_privateKey)
        user_address = pubtoaddr(user_publicKey)
        
        # Accessing the input data from the User
        req = request.form
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
                        WHERE name = '{candidate}'""" #{candidate}
        
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
        
        # IMPORTANT: WE NEED TO FIGURE OUT HOW TO CHECK HOW TO PREVENT DOUBLE VOTE SINCE WE'RE GENERATING NEW LINKS EVERYTIME THE USER RENDERS THE PAGE WHICH WOULD ALLOW THE USER TO GENERATE UNLIMITED KEYS AND ULTIMATELY VOTES

        #Check if both from and to address are given in the transaction
        if new_vote['from_address'] == None or new_vote['to_address'] == None:
            print('Transaction must include from and to address')
            flag = True
        
        # Calculate the hash based on the information and secure it
        new_vote['hash'] = calculateHash(new_vote)
        secureHash(new_vote, difficulty)
        
        # Sign the transaction and check if the transaction is valid
        if signVote(new_vote, user_privateKey):
            if not isValid(new_vote, user_publicKey):
                print('Cannot add invalid transaction to chain')
                flag = True
        else:
            flag = True

        #Add the vote to the Blockchain
        if not flag:
            add_vote_query = f"""INSERT INTO votes (hash, previous_hash, nonce, timestamp, from_address, to_address, value, signature)
                                VALUES ('{new_vote['hash']}', '{new_vote['previous_hash']}', {new_vote['nonce']}, '{new_vote['timestamp']}', '{new_vote['from_address']}', '{new_vote['to_address']}', {new_vote['value']}, '{new_vote['signature']}')"""
                    
            engine = create_engine('postgresql+psycopg2://postgres:thesis@localhost/master_thesis')
            engine.execute(add_vote_query)
            print('Transaction on the CHAIN')
            
            # Add QUERY to switch boolean of already_voted in the vote_check table from False to True 
            update_already_voted_query = f"""UPDATE vote_check
                                             SET already_voted = True
                                             WHERE user_id = {voter_id}"""
                    
            engine = create_engine('postgresql+psycopg2://postgres:thesis@localhost/master_thesis')
            engine.execute(update_already_voted_query)
            print('The already_voted status got updated')
            
            # Check which version was the last version
            latest_version_query = f"""SELECT latest_version
                                       FROM version_control as v
                                       INNER JOIN users as u
                                       ON v.election_id = u.election_id
                                       WHERE user_id = {voter_id}"""
                    
            engine = create_engine('postgresql+psycopg2://postgres:thesis@localhost/master_thesis')
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
            
            print(session['voter_version'])
            
            # Update the database
            update_latest_version_query = f"""UPDATE version_control
                                              SET latest_version = '{voter_version}'
                                              FROM version_control AS v
                                              INNER JOIN users AS u
                                              ON v.election_id = u.election_id
                                              WHERE user_id = {voter_id}"""
                  
            engine = create_engine('postgresql+psycopg2://postgres:thesis@localhost/master_thesis')
            engine.execute(update_latest_version_query)
            print('The latest_version status got updated')
            
            # Update the used version for the voter in the database
            update_version_query = f"""UPDATE vote_check
                                       SET version = '{voter_version}'
                                       WHERE user_id = {voter_id}"""
                    
            engine = create_engine('postgresql+psycopg2://postgres:thesis@localhost/master_thesis')
            update_version_results = engine.execute(update_version_query)
                
        return redirect(url_for('verification', user_address=user_address, user_publicKey=user_publicKey, user_privateKey=user_privateKey))
    
    else:
        message = 'You cannot vote Twice'
        return render_template('process.html', message = message)

# Verification Page

@app.route('/verification/<user_address>/<user_publicKey>/<user_privateKey>', methods=["GET", "POST"])
def verification(user_address, user_publicKey, user_privateKey):
    # Get the version and voter_id_hash information from the session
    voter_id_hash = session['voter_id_hash']
    print(f'We are n the Verification Page and the voter_id_hash is {voter_id_hash}')
    version = session['voter_version']
    print(f'We are n the Verification Page and the version is {version}')
    
    if request.method == "GET":
        # Get the user credentials from the process.html
        user_address = user_address
        user_publicKey = user_publicKey
        user_privateKey = user_privateKey
        
        # Create empty list for Blockchain which will result in a list of dictionaries
        blockchain = []
        
        # Query data for visualizing the Blockchain
        blockchain_query = "SELECT * FROM votes" 
        engine = create_engine('postgresql+psycopg2://postgres:thesis@localhost/master_thesis')
        blockchain_results = engine.execute(blockchain_query)
        
        # Adding one block to the blockchain for every vote
        for vote in blockchain_results:
            blockchain.append({'hash': vote[0],
                               'previous_hash': vote[1],
                               'nonce': vote[2],
                               'timestamp': vote[3],
                               'from_address': vote[4],
                               'to_address': vote[5],
                               'value': vote[6],
                               'signature': vote[7]})
            
        print(blockchain)
        print(len(blockchain))
        
        return render_template('verification.html',user_address=user_address, user_publicKey=user_publicKey, user_privateKey=user_privateKey, voter_id_hash=voter_id_hash, version=version)
    else:
        return render_template('verification.html', version=version)
    
@app.route('/verify/', methods=["GET", "POST"])
def verify():
    if session['voter_version'] == None:
        
        # Translate Hash of link into student id
        args = request.args.to_dict()
        voter_id_hash = args['source']
            
        voter_id_hash_query = f"""SELECT user_id
                                FROM vote_check
                                WHERE link = '{voter_id_hash}'"""
        
        engine = create_engine('postgresql+psycopg2://postgres:thesis@localhost/master_thesis')
        voter_id_hash_results = engine.execute(voter_id_hash_query)
        voter_id_hash_result = voter_id_hash_results.first()
        voter_id = voter_id_hash_result[0]
        
        # Query the corresponding version to render
        version_control_query = f"""SELECT version
                                    FROM vote_check
                                    WHERE user_id = {voter_id}"""
                
        engine = create_engine('postgresql+psycopg2://postgres:thesis@localhost/master_thesis')
        version_control_results = engine.execute(version_control_query)
        version_control_result = version_control_results.first()
        version = version_control_result[0]
        
        # Initialize the Session User ID and Version
        session['voter_id'] = voter_id
        session['voter_version'] = version
        
        print(f'We are n the Verify Page and the version is {version}')
        print(f'We are n the Verify Page and the voter_id is {voter_id}')
        
    else:
        version = session['voter_version']
        
    if request.method == "POST":
        # Create empty list for Blockchain which will result in a list of dictionaries
        blockchain = []
        
        # Query data for visualizing the Blockchain
        blockchain_query = "SELECT * FROM votes" 
        engine = create_engine('postgresql+psycopg2://postgres:thesis@localhost/master_thesis')
        blockchain_results = engine.execute(blockchain_query)
        
        # Adding one block to the blockchain for every vote
        for vote in blockchain_results:
            blockchain.append({'hash': vote[0],
                               'previous_hash': vote[1],
                               'nonce': vote[2],
                               'timestamp': vote[3],
                               'from_address': vote[4],
                               'to_address': vote[5],
                               'value': vote[6],
                               'signature': vote[7]})
        
        req = request.form
        
        # Use the private key to generate the corresponding address
        if len(req['private_key']) == 64:
            vote_from_address = privtoaddr(req['private_key'])
        else:
            print('This is not a private key')
            flash('This is not a private key', 'no_private_key_fail')
            return render_template('verify.html')
        
        # QUERY to find the correct transaction based on the address
        verify_vote_query = f"""SELECT * FROM votes
                        WHERE from_address = '{vote_from_address}'"""
        
        engine = create_engine('postgresql+psycopg2://postgres:thesis@localhost/master_thesis')
        verify_vote_results = engine.execute(verify_vote_query)
        verify_vote_result = verify_vote_results.first()
        
        # Query for candidate name
        candidate_query = f"""SELECT name FROM candidates
                            WHERE address = '{verify_vote_result[5]}'"""
        
        engine = create_engine('postgresql+psycopg2://postgres:thesis@localhost/master_thesis')
        candidate_results = engine.execute(candidate_query)
        candidate_result = candidate_results.first()
        
        # Check if there is an entry for the entered private key:
        if verify_vote_result == None:
            print('There is no corresponding vote to this private key')
            flash('There is no corresponding vote to this private key', 'wrong_private_key_fail')
            return render_template('verify.html', version=version)            
        else:
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
            
        return render_template('verify.html', casted_vote=casted_vote, version=version)
    else:
        # Create empty list for Blockchain which will result in a list of dictionaries
        blockchain = []
        
        # Query data for visualizing the Blockchain
        blockchain_query = "SELECT * FROM votes" 
        engine = create_engine('postgresql+psycopg2://postgres:thesis@localhost/master_thesis')
        blockchain_results = engine.execute(blockchain_query)
        
        # Adding one block to the blockchain for every vote
        for vote in blockchain_results:
            blockchain.append({'hash': vote[0],
                               'previous_hash': vote[1],
                               'nonce': vote[2],
                               'timestamp': vote[3],
                               'from_address': vote[4],
                               'to_address': vote[5],
                               'value': vote[6],
                               'signature': vote[7]})
            
        print(blockchain)
        print(len(blockchain))
        
        return render_template('verify.html', version=version)

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
