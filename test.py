import time
from bitcoin import *

user_db = [{'id': '34638', 'email': '34638@novasbe.pt', 'password': 'mojalaska'},
           {'id': '34646', 'email': '34646@novasbe.pt', 'password': 'mrkremlin'}]

email_input = '33333@novasbe.pt'
password_input = 'ninochka'


def login(email_input, password_input):
    counter = 0
    for user in user_db:
        if user['email'] == email_input and user['password'] == password_input:
            return print('You succesfully logged in!')
        else:
            counter += 1
    if counter == len(user_db):
        return print('The email or password are not correct.')


def register(email_input, password_input, password_rep_input):
    counter = 0
    for user in user_db:
        if user['email'] == email_input:
            return print('This email is already registered.')
        else:
            counter += 1
    if counter == len(user_db):
        if password_input != password_rep_input:
            return print('The passwords do not match!')
        else:
            user_db.append(
                {'id': email_input[0:5], 'email': email_input, 'password': password_input})
            return print('You successfully registered!')


register(email_input, password_input, password_input)
login(email_input, password_input)

votes = [{'id': 1, 'election_id': 1, 'user_id': 44444,
          'option': 'Stefan', 'timestamp': time.time()}]
elections = [1]
options = ['Lukas', 'Stefan', 'Andrew']
allowed_voters = ['11111', '22222', '33333', '44444', '55555', '66666']


def cast_ballot(email, option, election):
    if election in elections:
        if email[0:5] in allowed_voters:
            if option in options:
                max_id = 0
                for vote in votes:
                    if vote['id'] > max_id:
                        max_id = vote['id']
                votes.append({'id': (max_id+1), 'election_id': election,
                              'user_id': email[0:5], 'option': option, 'timestamp': time.time()})
                return print('Vote successfully transmitted!')
            else:
                return print('Invalid option!')
        else:
            return print('You are not allowed to vote in this election.')
    else:
        return print('This election is either closed or does not exist.')


cast_ballot(email_input, 'Lukas', 1)
