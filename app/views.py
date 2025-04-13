import json
import os
import requests
from flask import render_template, redirect, request, send_file, flash, url_for
from werkzeug.utils import secure_filename
from flask_login import login_user, logout_user, current_user, login_required
from app import app, bcrypt, login_manager, users
from timeit import default_timer as timer
from bson.objectid import ObjectId

class User:
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.email = user_data['email']
        self.password = user_data['password']
        self.is_master = user_data.get('is_master', False)

    @staticmethod
    def get(user_id):
        user_data = users.find_one({'_id': ObjectId(user_id)})
        return User(user_data) if user_data else None

    @staticmethod
    def get_by_username(username):
        user_data = users.find_one({'username': username})
        return User(user_data) if user_data else None

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route('/master/login', methods=['POST'])
def master_login():
    """Special master login endpoint"""
    from config import Config
    data = request.json
    if (data.get('username') == Config.MASTER_USERNAME and
        data.get('password') == Config.MASTER_PASSWORD and
        data.get('secret') == Config.MASTER_SECRET):
        user_data = users.find_one({'username': Config.MASTER_USERNAME})
        if user_data:
            user = User(user_data)
            login_user(user)
            return jsonify({'status': 'success'})
    return jsonify({'status': 'unauthorized'}), 401

# Stores all the post transaction in the node
request_tx = []
#store filename
files = {}
#destiantion for upload files
UPLOAD_FOLDER = "app/static/Uploads"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# store  address
ADDR = "http://127.0.0.1:8800"


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_data = users.find_one({'username': username})
        
        if user_data and bcrypt.check_password_hash(user_data['password'], password):
            user = User(user_data)
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login failed. Check username and password', 'danger')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        if users.find_one({'username': username}):
            flash('Username already exists', 'danger')
        else:
            users.insert_one({
                'username': username,
                'email': email,
                'password': hashed_password,
                'is_master': username == 'admin'  # Set first admin as master
            })
            flash('Account created successfully! Please login', 'success')
            return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/view_block/<int:block_index>/<filename>')
@login_required
def view_block(block_index, filename):
    """Display block contents for authenticated user"""
    chain_addr = f"{ADDR}/chain"
    resp = requests.get(chain_addr)
    if resp.status_code == 200:
        chain = json.loads(resp.content.decode())
        for block in chain["chain"]:
            if block["index"] == block_index:
                for trans in block["transactions"]:
                    if (trans.get("v_file") == filename and 
                        (current_user.username == trans.get("owner") or 
                         current_user.is_master)):
                        return render_template("view_block.html",
                            block=block,
                            transaction=trans,
                            filename=filename)
        flash('Block or file not found', 'danger')
    return redirect(url_for('index'))

# Create a list of requests that peers has send to upload files
def get_tx_req():
    global request_tx
    chain_addr = "{0}/chain".format(ADDR)
    resp = requests.get(chain_addr)
    if resp.status_code == 200:
        content = []
        chain = json.loads(resp.content.decode())
        for block in chain["chain"]:
            for trans in block["transactions"]:
                trans["index"] = block["index"]
                trans["hash"] = block["prev_hash"]
                content.append(trans)
        request_tx = sorted(content,key=lambda k: k["hash"],reverse=True)


# Loads and runs the home page
@app.route("/")
def index():
    get_tx_req()
    # Show anonymous files to all, private files only to owner/master
    filtered_tx = [tx for tx in request_tx 
                  if 'v_file' in tx and 
                  (tx.get('owner') == 'anonymous' or
                   (current_user.is_authenticated and 
                    (current_user.username == tx.get('owner') or 
                     current_user.is_master)))]
    return render_template("index.html",
                         title="FileStorage",
                         subtitle="A Decentralized Network for File Storage/Sharing",
                         node_address=ADDR,
                         request_tx=filtered_tx)


@app.route("/submit", methods=["POST"])
# When new transaction is created it is processed and added to transaction
def submit():
    start = timer()
    user = request.form["user"]
    up_file = request.files["v_file"]
    
    # Get the original file path if available
    original_path = request.files['v_file'].filename
    if os.path.exists(original_path):
        # Use the original file if it exists
        files[up_file.filename] = original_path
        file_states = os.stat(original_path).st_size
    else:
        # Save to upload directory if no original path
        up_file.save(os.path.join("app/static/Uploads/", secure_filename(up_file.filename)))
        files[up_file.filename] = os.path.join(app.root_path, "static", "Uploads", up_file.filename)
        file_states = os.stat(files[up_file.filename]).st_size
    
    # Read file data - handle CSV files specially
    if up_file.filename.lower().endswith('.csv'):
        with open(files[up_file.filename], 'r', encoding='utf-8') as f:
            file_data = f.read()
    else:
        with open(files[up_file.filename], 'rb') as f:
            file_data = str(f.read())
    
    # Create transaction object
    post_object = {
        "user": user,
        "v_file": up_file.filename,
        "file_data": file_data,
        "file_size": file_states,
        "owner": current_user.username if current_user.is_authenticated else "anonymous",
        "original_path": original_path if os.path.exists(original_path) else None
    }
   
    # Submit a new transaction
    address = "{0}/new_transaction".format(ADDR)
    requests.post(address, json=post_object)
    end = timer()
    print(end - start)
    return redirect("/")

#creates a download link for the file
@app.route("/submit/<string:variable>",methods = ["GET"])
@login_required
def download_file(variable):
    # Get file info from blockchain
    chain_addr = "{0}/chain".format(ADDR)
    resp = requests.get(chain_addr)
    if resp.status_code == 200:
        chain = json.loads(resp.content.decode())
        for block in chain["chain"]:
            for trans in block["transactions"]:
                if trans.get("v_file") == variable:
                    # Check if current user is owner, master, or file is anonymous
                    if (current_user.is_authenticated and 
                        (current_user.username == trans.get("owner") or 
                         current_user.is_master)) or trans.get("owner") == "anonymous":
                        p = files[variable]
                        return send_file(p, as_attachment=True)
                    else:
                        flash('You do not have permission to access this file', 'danger')
                        return redirect(url_for('index'))
    flash('File not found', 'danger')
    return redirect(url_for('index'))
