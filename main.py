import time
from flask import Flask
from flask import Flask, flash, redirect, render_template, request, session, abort, url_for
import os
import hashlib
import json
import pyperclip as pc

app = Flask(__name__)

def getUser(username: str):
    users = json.loads(open('data/users.json','r').read())
    for i in users:
        if(users[i]['username'] == username):
            return i
    return None

def getName(id: str):
    users = json.loads(open('data/users.json','r').read())
    for i in users:
        if(i == id):
            return users[i]['username']
    return None


def wipeSession(s):
    for i in s: 
        if(i not in ['logged_in', 'account']):
            s.remove(i)

def getSettings(): return json.loads(open('data/settings.json', 'r').read())
def getRank(num = False):
    settings = getSettings()
    admins = settings['admins']
    trusted = settings['trusted']
    if session['account'] in admins:
        r = "Admin "
        n = 0
    elif session['account'] in trusted:
        r = "Trusted "
        n = 1
    else: 
        r = "User "
        n = 2
    
    if(num):
        return n
    else:
        return r

@app.route('/', methods = ['POST', 'GET'])
def home():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        sesId = getUser(session['account'])
        clist = json.loads(open('data/currencies.json','r').read())
        selcur = {}
        users = json.loads(open('data/users.json','r').read())
        temp = [i for i in users[sesId]['wallet']]
        for i in temp:
            if(i not in clist):
                users[sesId]['wallet'].pop(i)
        open('data/users.json','w').write(json.dumps(users))
        if(request.method == 'POST'):
            if 'click' in request.form:
                if(request.form['click'] == "Update"):
                    clist[session['currency']['name']]['key'] = request.form['key']
                    session['currency']['key'] = request.form['key'] 
                    open('data/currencies.json','w').write(json.dumps(clist))
                    clist = json.loads(open('data/currencies.json','r').read())
                elif request.form['click'].startswith("R"):
                    data = json.loads(request.form["click"][1:].replace("\'", "\""))
                    clist[session['currency']['name']]['members'].pop(getUser(data['name']))
                    session['currency']['members'].pop(getUser(data['name']))
                    open('data/currencies.json','w').write(json.dumps(clist))
                    clist = json.loads(open('data/currencies.json','r').read())
                elif request.form['click'] == "Add Player":
                    if(getUser(request.form['player']) not in list(clist[session['currency']['name']]['members'].keys())):
                        
                        if(getUser(request.form['player']) in list(users.keys())):
                            clist[session['currency']['name']]['members'][getUser(request.form['player'])] = 1
                            open('data/currencies.json','w').write(json.dumps(clist))
                elif request.form['click'] == "Add Currency":
                    currencyName = request.form['currency']
                    if(currencyName not in clist):
                        clist[currencyName] = {"key":"","members":{getUser(session['account']): 3}}
                    open('data/currencies.json','w').write(json.dumps(clist))
                    selcur = clist[request.form['currency']]
                    selcur['name'] = request.form['currency']
                    session['currency'] = selcur
                elif request.form['click'] == "del-cur":
                    clist.pop(session['currency']['name'])
                    open('data/currencies.json','w').write(json.dumps(clist))
                    session.pop('currency')
                elif request.form['click'].startswith("ED"):
                    perm = 0
                    if(session['currency'] != {}): perm = clist[session['currency']['name']]['members'][getUser(session['account'])]
                    data = json.loads(request.form["click"][2:].replace("\'", "\""))
                    rank = clist[session['currency']['name']]['members'][getUser(data['name'])]
                    rank += 1
                    if(rank >= perm):
                        rank = 1
                    clist[session['currency']['name']]['members'][getUser(data['name'])] = rank
                    session['currency']['members'][getUser(data['name'])] = rank
                    open('data/currencies.json','w').write(json.dumps(clist))
                    clist = json.loads(open('data/currencies.json','r').read())
                elif request.form['click'] == "trans":
                    targetId = getUser(request.form['to'])
                    if(targetId):
                        users = json.loads(open('data/users.json','r').read())
                        wallet = users[sesId]['wallet']
                        if(request.form['transCur'] in wallet):
                            if(request.form['amt'].isdigit()):
                                amt = round(float(request.form['amt']))
                                if(wallet[request.form['transCur']] >= amt and amt > 0):
                                    # Transaction is valid!
                                    if(not request.form['transCur'] in users[targetId]['wallet']):
                                        users[targetId]['wallet'][request.form['transCur']] = amt
                                    else:
                                        users[targetId]['wallet'][request.form['transCur']] += amt
                                    users[sesId]['wallet'][request.form['transCur']] -= amt
                                    open('data/users.json','w').write(json.dumps(users))
            else:
                try:
                    selcur = clist[request.form['cur']]
                    selcur['name'] = request.form['cur']
                    session['currency'] = selcur
                except Exception as e:
                    print(e)
        clist = json.loads(open('data/currencies.json','r').read())
        users = json.loads(open("data/users.json",'r').read())
        wal = users[getUser(session['account'])]['wallet']
        wallet = []
        for i in wal: wallet.append([i,wal[i]])
        code = len(users[getUser(session['account'])]['cart']['items']) >= 1
        mem = []
        if('currency' not in session):
            session['currency'] = {}
        else:
            if('name' in session['currency']):
                roles = ["User","Mod","Admin"]
                for i in clist[session['currency']['name']]['members']:
                    mem.append({'name':getName(i), "rank": roles[clist[session['currency']['name']]['members'][i]-1]})
        display = []
        for i in clist:
            if(getUser(session['account']) in clist[i]['members']):
                display.append(i)
        perm = 0
        if(session['currency'] != {}): perm = clist[session['currency']['name']]['members'][getUser(session['account'])]
        formedWallet = []
        for i in wal:
            formedWallet.append([i,wal[i]])
        return render_template('index.html', icon="192.168.1.28:4000/favicon.ico",code = code, prank = getRank(True), perms = perm, members = mem, rank = getRank(), name = session['account'], selcur=session['currency'], currencies=display, wallet = formedWallet)

@app.route('/login', methods=['POST', 'GET'])
def login():
    acc = json.loads(open("data/users.json",'r').read())
    try:
        if(request.form['click'] == "Log In"):
            id = getUser(request.form['username'])
            if(id):
                if acc[id]['password'] == hashlib.sha256(request.form['password'].encode()).hexdigest() and request.form['click'] == "Log In":
                    session['logged_in'] = True
                    session['account'] = request.form['username']
                else:
                    print("Invalid username or password!")
        elif request.form['click'] == "copy": #
            c = f""
            pc.copy(c)
            open('data/users.json','w').write(json.dumps(acc))
        elif request.form['click'] == "Sign Up":
            return redirect(url_for('signup'))
    except:
        pass
    return home()

@app.route('/signup', methods=['POST'])
def signup():
    if request.form['click'] == "Create Account":
        acc = json.loads(open("data/users.json",'r').read())
        if(getUser(request.form['username']) == None):
            uuid = hashlib.sha256(str(time.time()).encode()).hexdigest()
            session['logged_in'] = True
            session['account'] = request.form['username']
            acc[uuid] = {'username':request.form['username'],'wallet':{}, "cart": {"price": 0, "currency": "", "items": [], "key": "5337089855", "scramble": "0001"}}
            acc[uuid]['password'] = hashlib.sha256(request.form['password'].encode()).hexdigest()
            open('data/users.json','w').write(json.dumps(acc))
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/admin')
def admin():
    if(session['logged_in']):
        if(getRank(True) == 0):
            return render_template('admin.html', rank = getRank(), prank = getRank(True), name = session['account'])
        else: return home()
    else: return home()

@app.route("/logout")
def logout():
    session['logged_in'] = False
    return home()

# def recieveCode(code):

if __name__ == "__main__":
    internet = '192.168.1.28'
    local = '127.0.0.1'

    app.secret_key = os.urandom(12)
    app.run(debug=True,host=local, port=4000)