from flask import Flask, request, jsonify, render_template, url_for, flash, session, redirect
from pymongo import MongoClient
from bson import json_util
from bson.json_util import dumps
from json import loads
import requests 
import random
from flask_cors import CORS
import os
import copy
import string

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = os.path.join(os.path.abspath(os.path.dirname(__file__)),"client_secret.json")

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = ['https://www.googleapis.com/auth/plus.profile.emails.read']
API_SERVICE_NAME = 'plus'
API_VERSION = 'v1'

price = {}

app = Flask(__name__)
app.secret_key = os.urandom(24)
CORS(app)

# List of characters to make a valid node id
alpha_num = string.ascii_lowercase + string.digits

@app.after_request
def add_header(r):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, post-check = 0, pre-check = 0"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    return r

# Get list of already used node id to avoid any duplicacy
def get_id_list():
    l = []
    star = db.node_id
    for s in star.find():
        l.append(s['node_id'])
    return l
    
# MongoDB Connection
try:
    client = MongoClient('mongodb://admin:admin@35.187.13.95:27017/EpServer')
    db = client['EpServer']
except Exception as err:
    print(str(err))

#render firstpage
@app.route('/')
def home():
    if 'email' in session:
        return  redirect(url_for('flows'))
    else:
        return redirect(url_for('render_login'))

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/amazon')
def amazon():
    collection = db.price
    doc  = collection.find_one({'name':'amazon'})
    del doc['_id']
    return render_template('amazon.html',price = doc)

@app.route('/flipkart')
def flipkart():
    collection = db.price
    doc  = collection.find_one({'name':'flipkart'})
    del doc['_id']
    return render_template('flipkart.html',price = doc)

@app.route('/ebay')
def ebay():
    collection = db.price
    doc  = collection.find_one({'name':'ebay'})
    del doc['_id']
    return render_template('ebay.html',price = doc)

@app.route('/paytm')
def paytm():
    collection = db.price
    doc  = collection.find_one({'name':'paytm'})
    del doc['_id']
    return render_template('paytm.html',price = doc)

@app.route('/myntra')
def myntra():
    collection = db.price
    doc  = collection.find_one({'name':'myntra'})
    del doc['_id']
    return render_template('myntra.html',price = doc)

# Render google cretificate for verified website
# @app.route('/googlec39db921cf2d9dcc.html', methods=['GET'])
# def render_certificate():
#     return render_template('googlec39db921cf2d9dcc.html')

# Render login page
@app.route('/login', methods=['GET','POST'])
def render_login():
    if 'email' not in session:
        if request.method == 'GET':
            return render_template('login.html')
        elif request.method == 'POST':
            users = db['users']
            email = request.form['email']
            password = request.form['password']
            u = users.find_one({'email':email})
            if u:
                if 'password'  in u:
                    if u['password'] == password:
                        session['email'] = u['email']
                        session['name'] = u['name']
                        return redirect(url_for('flows'))
                    else:
                        flash('Invalid Email-address or Password','text-danger')
                else:
                    flash('Use previous sign in option', 'text-danger')
            else:
                flash('Invalid Email-address or Password','text-danger')
            return render_template('login.html')
    else:
        return redirect(url_for('flows'))

@app.route('/logout', methods=['GET'])
def render_logout():
    if 'email' in session:
        print(session['email'],session['name'])
        if request.method == 'GET':
            if 'email' in session:
                session.pop('email',None)
                session.pop('name',None)
            if 'credentials' in session:
            	session.pop('credentials',None)
            return redirect(url_for('render_login'))
    else:
        return redirect(url_for('render_login'))
            
#render register user page
@app.route('/register', methods=['GET','POST'])
def register_user():
    if 'email' in session:
        return redirect(url_for('flows'))
    else:
        if request.method == 'GET':
            return render_template('register.html')
        elif request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            conf_password = request.form['conf_password']
            name = request.form['name']
            if password == conf_password:
                users = db['users']
                if (users.find_one({'email':email})):
                    #print("modalcalled")
                    flash("Email already exists",'text-danger')
                    return render_template('register.html')
                else:
                    x = users.insert({"name": name,"password":password,"email":email})
                    print(x)
                    return render_template('login.html')
            else:
                flash('Passwords do  not match','text-danger')
                return render_template('register.html')

#render forgetpassword page
@app.route('/change_password', methods=['GET','POST'])
def change_password():
    if 'email' in session:
        useremail=session['email']
        users=db['users']
        if request.method=='GET':
            return render_template('change_password.html')
        elif request.method=='POST':
            oldpassword=request.form['oldpassword']
            newpassword=request.form['newpassword']
            confirmpassword=request.form['confirmpassword']
            if (users.find_one({'password':oldpassword})):
                if newpassword == confirmpassword:
                    users.update({'email':useremail},{'$set':{'password':newpassword}},upsert=False)
                    flash("Your password is successfully changed",'text-success')
                    return redirect(url_for('change_password'))
            else:
                flash('Invalid Password','text-danger')
                return redirect(url_for('change_password')) 
        else:
            return redirect(url_for('flows'))
    else:
        return redirect(url_for('render_login'))

#render flows page
@app.route('/flows')
def flows():                                
    if 'email' in session:
        return render_template('flows.html')
    else:
        return redirect(url_for('render_login'))

#render cloud services flows page
@app.route('/cloud_services', methods=['GET','POST'])
def cloud_services():
    if 'email' in session:
        if request.method == 'GET':
            return render_template('cloud_services.html')
        if request.method == 'POST':
            flash('Your flow has been sucessfully deployed', 'text-success')
            return render_template('cloud_services.html')
    else:
        return redirect(url_for('render_login'))

#render cloud services flows page
@app.route('/ecommerce', methods=['GET','POST'])
def ecommerce():
    if 'email' in session:
        if request.method == 'GET':
            return render_template('e-commerce.html')
        elif request.method == 'POST':
            name = request.form['name']
            websiteName = request.form.getlist('websiteName')
            websiteURL = request.form.getlist('websiteURL')
            field = request.form.getlist('field')
            s1 = get_flow_json('ecommerce')
            s1['label'] = name
            s2 = get_flow_json('ecommerce_extra_node')
            l = get_id_list()
            for i in range(len(websiteName)):
                s = copy.deepcopy(s2)
                print(websiteName[i])
                print(websiteURL[i])
                print(field[i])
                s[0]['id'] = get_new_id(l)
                s[0]['name'] = websiteName[i]
                s[0]['url'] = websiteURL[i]
                s[0]['field'] = field[i]
                s[1]['id'] = get_new_id(l)
                s[0]['wires'][0][0] = s[1]['id']
                s[1]['func'] = s[1]['func'].replace('FLIPKART',websiteName[i])
                s1['nodes'][2]['count'] = str(int(s1['nodes'][2]['count']) + 1)
                s1['nodes'][0]['wires'][0].append(s[0]['id'])
                s1['nodes'].extend(copy.deepcopy(s))
            s1 = update_id(s1, get_id_list())
            flowid = post_flow_json(s1)
            print(flowid)
            useremail = session['email']
            users = db['users']
            users.update({'email': useremail}, {'$push': {'flowid': flowid}})
            flash('Your flow has been sucessfully deployed','text-success')
            return render_template('e-commerce.html')
    else:
        return redirect(url_for('render_login'))

#render mqtt flows page
@app.route('/mqtt', methods=['GET','POST'])
def mqtt():
    if 'email' in session:
        if request.method == 'GET':
            return render_template('mqtt.html')
        elif request.method == 'POST':
            # Gathering structure of json for mqtt
            s1 = get_flow_json('mqtt2')
            s2 = get_flow_json('mqtt2_display')
            # Gathering form inputs
            in_server = request.form['in_server']
            in_port = request.form['in_port']
            in_topic = request.form['in_topic']
            in_value = request.form['in_value']
            in_operator= request.form['in_operator']
            out_server = request.form['out_server']
            out_port = request.form['out_port']
            out_topic = request.form['out_topic']
            out_value = request.form['out_value']
            key       = request.form['key']
            # Making appropriate changes in the json
            s1['label'] = request.form['name']
            s2['label'] = request.form['name']+' chart display'
            s1['nodes'][0]['topic'] = in_topic
            s1['nodes'][2]['property'] = key
            s1['nodes'][2]['rules'][0]['t'] = in_operator
            s1['nodes'][2]['rules'][0]['v'] = in_value
            s1['nodes'][3]['func'] = s1['nodes'][3]['func'].replace('1',out_value)
            s1['nodes'][4]['topic'] = out_topic
            s1['configs'][0]['broker'] = in_server
            s1['configs'][1]['broker'] = out_server
            s1['configs'][0]['port'] = in_port
            s1['configs'][1]['port'] = out_port
            s2['configs'][0]['port'] = in_port
            s2['configs'][0]['broker'] = in_server
            s2['nodes'][0]['topic'] = in_topic
            s2['nodes'][2]['func'] = s2['nodes'][2]['func'].replace('{1}', key)
            s1 = update_id(s1, get_id_list())
            s2 = update_id(s2, get_id_list())
            useremail = session['email']
            users = db['users']
            flowid = post_flow_json(s1)
            users.update({'email': useremail}, {'$push': {'flowid': flowid}})
            flowid = post_flow_json(s2)
            users.update({'email': useremail}, {'$push': {'flowid': flowid}})
            flash('Your flow has been sucessfully deployed','text-success')
            return render_template('mqtt.html')
    else:        
        return redirect(url_for('render_login'))

#render your flows page to display user's flows
@app.route('/yourflows', methods=['GET','POST'])
def yourflows():
    if 'email'  in session:
        useremail=session['email']
        users=db['users']
        if request.method=="GET":            
            data = users.find_one({'email' :useremail})
            if 'flowid' in data:
                flowid = data['flowid']
                context = []
                for flow in flowid:
                    data = {}
                    url = "http://35.187.13.95:1880/flow/" + flow['id']
                    print(url)
                    r = requests.get(url)
                    if r.status_code == 200:
                        resp = r.json()
                        data['flow_name'] = resp['label']
                        data['flow_id'] = flow
                        context.append(data)
                return render_template('tables.html',context = context)
            return render_template('tables.html')
        elif request.method=="POST":
            action=request.form["action"]
            if "Delete" in action:
                #print(action)
                flow_id = action.replace("Delete","")
                #print(flow_id)
                result=db.users.update({'email':useremail},{'$pullAll':{'flowid':[{'id':flow_id}]}})
                #print(result)
                if result['nModified']==0 :
                     flash("oops...Your flow is not Deleted")
                else :
                    Delete(flow_id)
                    flash("Your flow has been successfully deleted")
                    return redirect("/yourflows")
            else:
                pass


    else:
        return redirect(url_for('render_login'))

def Delete(flow_id):
    r = requests.delete(('http://35.187.13.95:1880/flow/{0}'.format(flow_id)).encode())
    return True    


# Render customflows page
@app.route('/customflows', methods=['GET','POST'])
def render_customflows():
    if 'email' in session:
        if request.method == 'GET':
            return render_template('customflows.html')
        elif request.method == 'POST':
            s = {}      #Final object to be sent to node-red via admin API to deploy the flow
            name = request.form['name']
            output = request.form['output']
            input = request.form['input']
            s['label'] = name
            output_nodes = []       #This array stores the list of output nodes
            output_configs = []     #This array stores the list of configuration required for output nodes
            input_nodes = []        #This array stores the list of input nodes
            input_configs = []      #This array stores the list of configuration required for input nodes
            output_start_id = ''    #This variable points to the start of output flow

            # If output target node is EMAIL
            if(output == 'EMAIL'):
                # Gathering form inputs
                email = request.form['email']
                subject = request.form['subject']
                # Gathering structure of json for email
                output_nodes = get_flow_json('email_nodes')['nodes']
                # Making appropriate changes in the json
                output_nodes[1]['to'] = email
                output_nodes[1]['subject'] = subject
                output_start_id = output_nodes[0]['id']

            # If output target node is MONGODB
            elif(output == 'MONGODB'):
                # Gathering form inputs
                mongodburi = request.form['mongodburi']
                dbname = request.form['dbname']
                collectionname = request.form['collectionname']
                # Gathering structure of json for mongodb
                output_nodes = get_flow_json('mongo_nodes')['nodes']
                output_configs = get_flow_json('mongo_configs')['configs']
                # Making appropriate changes in the json
                output_nodes[1]['collection'] = collectionname
                output_configs[0]['uri'] = mongodburi
                output_configs[0]['name'] = dbname
                output_start_id = output_nodes[0]['id']

            if(input == 'TWITTER'):
                # Gathering form inputs
                query = request.form['query']
                sentiment_score = request.form['sentiment-score']
                # Gathering structure of json for twiiter
                input_nodes = get_flow_json('twitter_nodes')['nodes']
                input_configs = get_flow_json('twitter_configs')['configs']
                # Making appropriate changes in the json
                input_nodes[0]['topics'] = query
                # Connecting output flow with the input flow
                if (sentiment_score == 'POSITIVE'):
                    input_nodes[4]['wires'][0].append(output_start_id)
                elif (sentiment_score == 'NUETRAL'):
                    input_nodes[4]['wires'][1].append(output_start_id)
                elif (sentiment_score == 'NEGATIVE'):
                    input_nodes[4]['wires'][2].append(output_start_id)

            elif(input == 'MQTT'):
                # Gathering form inputs
                server = request.form['server']
                port = request.form['port']
                topic= request.form['topic']
                qos = request.form['qos']
                property  = request.form['property']
                operator  = request.form['operator']
                value  = request.form['value']
                # Gathering structure of json for mqtt
                input_nodes = get_flow_json('mqtt_nodes')['nodes']
                input_configs = get_flow_json('mqtt_configs')['configs']
                # Making appropriate changes in the json
                input_nodes[0]['topic'] = topic
                input_nodes[0]['qos'] = qos
                input_nodes[3]['rules'][0]['t'] = operator
                input_nodes[3]['rules'][0]['v'] = value
                input_nodes[3]['property'] = property
                input_configs[0]['broker']  = server
                input_configs[0]['port'] = port
                # Connecting output flow with the input flow
                input_nodes[3]['wires'][0].append(output_start_id)

            elif(input == 'WEBSCRAPER'):
                # Gathering form inputs
                repeat  = request.form['repeat']
                url = request.form['url']
                field = request.form['field']
                # Gathering structure of json for webscraper
                input_nodes = get_flow_json('webscraper_nodes')['nodes']
                # Making appropriate changes in the json
                input_nodes[0]['repeat'] = repeat
                input_nodes[1]['url'] = url
                input_nodes[1]['field'] = field
                # Connecting output flow with the input flow
                input_nodes[1]['wires'][0].append(output_start_id)

            s['nodes'] = []     #This array stores the list of all nodes for the current flow
            s['configs'] = []   #This array stores the list of configuration required by all nodes for the current flow
            # Adding input and output nodes
            s['nodes'].extend(input_nodes)
            s['nodes'].extend(output_nodes)
            # Adding configurations input and output nodes
            s['configs'].extend(input_configs)
            s['configs'].extend(output_configs)
            # Updating all the node id to avoid any duplicacy
            s = update_id(s,get_id_list())
            # Deploy the flow  on th server
            flowid = post_flow_json(s)
            useremail=session['email']
            users=db['users']
            users.update({'email': useremail}, {'$push': {'flowid': flowid}})
            
            flash('Your flow has been sucessfully deployed','text-success')
            return render_template('customflows.html')
    else:
        return redirect(url_for('render_login'))

@app.route('/webscrap', methods=['GET','POST'])
def render_webscraping():
    if 'email' in session:
        if request.method == 'GET':
            return render_template('webscrap.html')
        elif request.method == 'POST':
            # Gathering structure of json for webscraping
            s = get_flow_json('Webscraper')
            # Gathering form inputs
            url = request.form['url']
            field = request.form['field']
            name = request.form['name']
            mongoURI = request.form['mongodburi']
            dbName = request.form['dbname']
            collectionName = request.form['collectionname']
            # Making appropriate changes in the json
            s['label'] = name
            s['nodes'][0]['url'] = url
            s['nodes'][0]['field'] = field
            s['nodes'][2]['collection'] = collectionName
            s['configs'][0]['uri'] = mongoURI
            s['configs'][0]['name'] = dbName
            # Updating all the node id to avoid any duplicacy
            s = update_id(s,get_id_list())
            # Deploy the flow on the server
            flowid = post_flow_json(s)
            useremail=session['email']
            users=db['users']
            users.update({'email': useremail}, {'$push': {'flowid': flowid}})
            flash('Your flow has been sucessfully deployed','text-success')
            return render_template('webscrap.html')
    else:
        return redirect(url_for('render_login'))

@app.route('/filemonitor', methods=['GET','POST'])
def render_filemonitoring():
    if 'email' in session:
        if request.method == 'GET':
            return render_template('filemonitor.html')
        elif request.method == 'POST':
            # Gathering structure of json for google sheet monitoring
            s = get_flow_json('filemonitor')
            # Making appropriate changes in the json
            s['nodes'][5]['to'] = request.form['email']
            s['nodes'][0]['url'] = request.form['url']
            s['nodes'][4]['url'] = str(request.form['url']) + '/{{payload}}'
            s['label'] = request.form['name']
            # Updating all the node id to avoid any duplicacy
            s = update_id(s,get_id_list())
            # Deploy the flow  on th server
            flowid = post_flow_json(s)
            useremail=session['email']
            users=db['users']
            users.update({'email': useremail}, {'$push': {'flowid': flowid}})
            flash('Your flow has been sucessfully deployed','text-success')
            return render_template('filemonitor.html')
    else:
        return redirect(url_for('render_login'))

@app.route('/formmonitor', methods=['GET','POST'])
def render_formmonitoring():
    if 'email' in session:
        if request.method == 'GET':
            return render_template('formmonitor.html')
        elif request.method == 'POST':
            # Gathering structure of json for google sheet monitoring
            s = get_flow_json('formmonitor')
            # Making appropriate changes in the json
            responseMessage = request.form['response']
            subject = request.form['subject']
            colKey = request.form['colKey']
            colEmail = request.form['colEmail']
            value = request.form['value']
            s['nodes'][0]['url'] = request.form['url']
            s['nodes'][4]['url'] = str(request.form['url']) + '/{{payload}}'
            s['nodes'][6]['func'] = s['nodes'][6]['func'].replace('{1}',responseMessage).replace('{2}',subject).replace('{3}',colKey).replace('{4}',colEmail).replace('{5}',value)
            s['label'] = request.form['name']
            # Updating all the node id to avoid any duplicacy
            s = update_id(s,get_id_list())
            # Deploy the flow  on th server
            flowid = post_flow_json(s)
            useremail=session['email']
            users=db['users']
            users.update({'email': useremail}, {'$push': {'flowid': flowid}})
            flash('Your flow has been sucessfully deployed','text-success')
            return render_template('formmonitor.html')
    else:
        return redirect(url_for('render_login'))

# This function POST the json flow to the node red ADMIN API to deply it
def post_flow_json(flow):
    r = requests.post('http://35.187.13.95:1880/flow',json=flow)
    return r.json()

# This function gets the structure of a required flow stored in mongodb
def get_flow_json(flow_name):
    print(flow_name)
    star = db.node_red
    s = star.find_one({'name':flow_name})
    s = s['json']
    return s

# This function updates all the node ids in the given json s and looks over that no node id is already present in l to avoid duplicacy
def update_id(s,l):
    if 'configs' in s:
        for config in s['configs']:
            # Get the old node id
            old_id = config['id']
            # Get a new node id
            new_id = get_new_id(l)
            # Convert json to string
            str_s = dumps(s)
            # Replace old node id to new node id
            str_s = str_s.replace(old_id,new_id)
            # Convert string back to json
            s = loads(str_s)
    if 'nodes' in s:
        for node in s['nodes']:
            # Get the old node id
            old_id = node['id']
            # Get a new node id
            new_id = get_new_id(l)
            # Convert json to string
            str_s = dumps(s)
            # Replace old node id to new node id
            str_s = str_s.replace(old_id, new_id)
            # Convert string back to json
            s = loads(str_s)
    # Return the json with updated node id
    return s

# This function generates a new node id which is not present in l (list of already in use node id)
# node id is of the form [########.######] where # can be alpha-numeric[a-z0-9]
def get_new_id(l):
    flag = True
    while(flag):
        new_id = ''
        for i in range(8):
            r = random.randint(0,35)
            new_id += alpha_num[r]
        new_id += '.'
        for i in range(6):
            r = random.randint(0, 35)
            new_id += alpha_num[r]
        # If the newly generated node id is not present in the list add it to the list as well as database
        if new_id  not in l:
            l.append(new_id)
            star = db.node_id
            star.insert({'node_id':new_id})
            return new_id

@app.route('/gpluslogin', methods=['GET','POST'])
def test_api_request():
  if 'credentials' not in session:
    return redirect('authorize')

  # Load credentials from the session.
  credentials = google.oauth2.credentials.Credentials(
      **session['credentials'])

  service = googleapiclient.discovery.build(
      API_SERVICE_NAME, API_VERSION, credentials=credentials)

  # This sample assumes a client object has been created.
  # To learn more about creating a client, check out the starter:
  #  https://developers.google.com/+/quickstart/python


  people_resource = service.people()
  people_document = people_resource.get(userId='me').execute()
  name = people_document['displayName']
  email  = people_document['emails'][0]['value']
  users = db['users']
  u = users.find_one({'email': email})
  if not u:
    x = users.insert({"name": name, "email": email})
  session['email'] = email
  session['name'] = name
  # Save credentials back to session in case access token was refreshed.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  session['credentials'] = credentials_to_dict(credentials)
  return redirect(url_for('flows'))

@app.route('/authorize')
def authorize():
  # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)

  flow.redirect_uri = url_for('oauth2callback', _external=True)

  authorization_url, state = flow.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      access_type='offline',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='true')

  # Store the state so the callback can verify the auth server response.
  session['state'] = state

  return redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
    try:
        # Specify the state when creating the flow in the callback so that it can
        # verified in the authorization server response.
        state = session['state']

        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
          CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
        flow.redirect_uri = url_for('oauth2callback', _external=True)

        # Use the authorization server's response to fetch the OAuth 2.0 tokens.
        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response)

        # Store credentials in the session.
        # ACTION ITEM: In a production app, you likely want to save these
        #              credentials in a persistent database instead.
        credentials = flow.credentials
        session['credentials'] = credentials_to_dict(credentials)
        return redirect(url_for('test_api_request'))
    except:
        return redirect(url_for('render_login'))

# @app.route('/revoke')
# def revoke():
#   if 'credentials' not in session:
#     return ('<p>You need to <a href="'+url_for('authorize')+'">authorize</a> before ' +
#             'testing the code to revoke credentials.</p>')
#
#   credentials = google.oauth2.credentials.Credentials(
#     **session['credentials'])
#
#   revoke = requests.post('https://accounts.google.com/o/oauth2/revoke',
#       params={'token': credentials.token},
#       headers = {'content-type': 'application/x-www-form-urlencoded'})
#
#   status_code = getattr(revoke, 'status_code')
#   if 'credentials' in session:
#     del session['credentials']
#   if status_code == 200:
#     return('<p>Credentials successfully revoked.</p>')
#   else:
#     return('An error occurred.' )

@app.route('/get_prices/<company>')
def get_prices(company):
    collection = db.price
    document = collection.find_one({'name':company})
    del document['_id']
    return jsonify(document)


def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

# Run Flask application
if __name__ == '__main__':
    # When running locally, disable OAuthlib's HTTPs verification.
    # ACTION ITEM for developers:
    #     When running in production *do not* leave this option enabled.
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run(host='0.0.0.0', port=int("5009"),debug=True) #0.0.0.0 corresponds to localhost
