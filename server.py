from subprocess import Popen, PIPE, STDOUT, DEVNULL
from flask import Flask
from flask import render_template
from flask import request
from markupsafe import escape
from pathlib import Path
from hashlib import sha256

app = Flask(__name__)

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/project2")
def p2():
    return render_template('project2.html')

@app.route("/basic", methods=['GET', 'POST'])
def demo():
    if request.method == 'GET':
        return render_template('basic.html')
    else:
        cmd = escape(request.get_json(force=True).get('command'))
        list = cmd.split(';')
        trip = ""
        safe = True
        for i in list[1:]:
            if (i[:2] != 'ls' and i[:3] != 'cat' and i[:4] != 'echo') or '<' in i or '|' in i or '>' in i or '&' in i:
                safe = False
                trip = i
        if safe:
            p = Popen(["./run.sh systemvuln " + cmd], shell=True, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
            ret = p.communicate()[0].decode()
            ret = ret.replace("\n", "<br>")
        else:
            ret = "If you're seeing this, you either ran a command which doesn't deal in text or used quotation marks. Email me if you have any questions. Your problematic command was (if you see nothing, get rid of your quote marks): " + trip
        return ret

@app.route("/rop")
def ropmenu():
    return render_template('ropmenu.html')

@app.route("/rop/demo", methods=['GET', 'POST'])
def rop():
    if request.method == 'GET':
        return render_template('ropdemo.html')
    else:
        cmd = escape(request.get_json(force=True).get('command'))
        list = cmd.split(';')
        if len(cmd) > 9:
            if len(cmd) > 53 and cmd[22:54] == r"\x89\x84\x04\x08\x70\x85\x04\x08":
                p = Popen(["cat ./secretfile.txt"], shell=True, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
                ret = p.communicate()[0].decode()
            elif len(cmd) > 37 and cmd[22:38] == r"\x6b\x84\x04\x08":
                ret = "Not a shell\n"
                p = Popen(["/bin/date"], shell=True, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
                ret += p.communicate()[0].decode()
            else:
                ret = "segmentation fault(core dumped)"
        else:
            ret = "Thank you for sending your email!"
        return ret

#I recommend anyone looking at this code to tweak the results to be better. A lot of the ROP demo had to be manually programmed because of 64 vs. 32-bit code issues.
#In the event that you can run a 32-bit server yourself, then you can just use the code in the else statement on line 124 as the entire argument.
@app.route("/rop/gdb", methods=['GET', 'POST'])
def ropgdb():
    if request.method == 'GET':
        return render_template('ropgdb.html')
    else:
        cmd = escape(request.get_json(force=True).get('command'))
        if cmd[0] == 'x/s mycmd' or cmd[0] == 'x mycmd': #T/D: Add compatibility for X.
            ret = '0x08048570:      "cat ./secretfile.txt"'
        elif cmd == 'x/s intermedia_code' or cmd == 'x intermedia_code':
            ret = '0x0804846b:      intermedia_code'
        elif cmd == 'disas intermedia_code':
            ret =  ('0x0804846b <+0>:       push   %ebp\n' +
                    '0x0804846c <+1>:       mov    %esp,%ebp\n' + 
                    '0x0804846e <+3>:       sub    $0x8,%esp\n' +
                    '0x08048471 <+6>:       sub    $0xc,%esp\n' +
                    '0x08048474 <+9>:       push   $0x08048578\n' +
                    '0x08048479 <+14>:      call   0x08048330 <puts@plt>\n' + 
                    '0x0804847e <+19>:      add    $0x10,%esp\n' +
                    '0x0804847e <+22>:      sub    $0xc,%esp\n' +
                    '0x08048484 <+25>:      push   $0x08048584\n' + 
                    '0x08048489 <+30>:      call   $0x08048340\n' +
                    '0x0804848e <+35>:      add    $0x10,%esp\n' +
                    '0x08048491 <+38>:      nop\n' +
                    '0x08048492 <+39>:      leave\n' +
                    '0x08048493 <+40>:      ret\n')
        elif cmd == 'x/s vulnerable_function' or cmd == 'x vulnerable_function':
            ret = '0x08048494:      vulnerable_function'
        elif cmd == 'disas vulnerable_function':
            ret =  ('0x08048494 <+0>:       push   %ebp\n' +
                    '0x08048495 <+1>:       mov    %esp,%ebp\n' + 
                    '0x08048497 <+3>:       sub    $0x18,%esp\n' +
                    '0x0804849a <+6>:       sub    $0x8,%esp\n' +
                    '0x0804849d <+9>:       pushl  $0x8(%ebp)\n' +
                    '0x080484a0 <+12>:      lea    -0x12(%ebp),%eax\n' + 
                    '0x080484a3 <+15>:      push   %eax\n' +
                    '0x080484a4 <+16>:      call   0x08048320 <strcpy@plt>\n' +
                    '0x080484a9 <+21>:      add    $0x10,%esp\n' + 
                    '0x080484ac <+24>:      nop\n' +
                    '0x080484ad <+25>:      leave\n' +
                    '0x080484ae <+26>:      ret\n')
        elif cmd == 'x/s main' or cmd == 'x main':
            ret = '0x080484af:      main'
        elif cmd == 'disas main':
            ret =  ('0x080484af <+0>:       push   %ebp\n' +
                    '0x080484b0 <+1>:       mov    %esp,%ebp\n' + 
                    '0x080484b3 <+4>:       sub    $0x10,%esp\n' +
                    '0x080484b6 <+7>:       mov    $0xedi,-0x4(%ebp)\n' +
                    '0x080484b9 <+10>:      mov    $esi,-0x10(%ebp)\n' +
                    '0x080484bd <+14>:      mov    $-0x10(%ebp),%eax\n' + 
                    '0x080484c1 <+18>:      add    $0x08,%eax\n' +
                    '0x080484c5 <+22>:      mov    (%eax),%eax\n' +
                    '0x080484c8 <+25>:      mov    %eax,%edi\n' + 
                    '0x080484cb <+28>:      callq  $0x08048494 <vulnerable_function>\n' +
                    '0x080484d1 <+33>:      add    $0x10,%esp\n' +
                    '0x080484d2 <+34>:      nop\n' +
                    '0x080484d3 <+35>:      leave\n' +
                    '0x080484d4 <+36>:      ret\n')
        else:
            p = Popen(["gdb -q rop "], shell=True, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
            ret = p.communicate(cmd.encode())[0].decode()
        ret = escape(ret)
        return ret

@app.route("/heap", methods=['GET', 'POST'])
def heapvuln():
    if request.method == 'GET':
        return render_template('heap.html')
    else:
        cmd = escape(request.get_json(force=True).get('command'))
        if ';' in cmd or '<' in cmd or '|' in cmd or '>' in cmd or '&' in cmd or 'python' in cmd:
            ret = "Text only, please."
        else:
            p = Popen(["./heap " + cmd], shell=True, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
            ret = p.communicate()[0].decode()
            ret = escape(ret)
        return ret

@app.route("/project2/symlinker", methods=['GET', 'POST'])
def symlink():
    if request.method == 'GET':
        return render_template('symlinker.html', files=getFiles())
    else:
        safe = True
        cmd1 = escape(request.get_json(force=True).get('command1'))
        cmd2 = escape(request.get_json(force=True).get('command2'))
        cmd = cmd1 + ' ' + cmd2
        if  '<' in cmd or '|' in cmd or '>' in cmd or '&' in cmd or ';' in cmd or '/' in cmd or '..' in cmd:
            safe = False
        if safe:
            if cmd2 == 'secret':
                ret = "The secret file can't be overwritten!"
            elif Path("./p2/"+cmd2).is_file():
                ret = "That file already exists!"
            elif not Path("./p2/"+cmd1).is_file():
                ret = "That target doesn't exist!"
            else:
                p = Popen(["ln -s " + cmd1 + ' ./p2/' + cmd2], shell=True, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
                p.communicate()
                ret = "Link Created!"
                ret = ret.replace("\n", "<br>")
        else:
            ret = "No command injection or files outside the designated folder, please!\n" 
        return ret

@app.route("/project2/reader", methods=['GET', 'POST'])
def reader():
    if request.method == 'GET':
        return render_template('reader.html', files=getFiles())
    else:
        confirming = escape(request.get_json(force=True).get('confirming'))
        cmd = escape(request.get_json(force=True).get('command'))
        if confirming == 'y':
            if  '<' in cmd or '|' in cmd or '>' in cmd or '&' in cmd or ';' in cmd or '/' in cmd or '..' in cmd or cmd == 'secret':
                ret = "NO."
            else:
                if not Path("./p2/"+cmd).is_file():
                    return "That file doesn't exist!"
                p = Popen(["cat ./p2/" + cmd], shell=True, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
                ret = p.communicate()[0].decode()
                    
                #Clear the folder of any symlinks
                p = Popen(["rm ./p2/*"], shell=True, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
                p.communicate()
                p = Popen(["cp ./p3/* ./p2"], shell=True, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
                ret += p.communicate()[0].decode()

        else:
            if '/' in cmd or '..' in cmd:
                ret = 'No files outside the designated folder, please!'
            else:
                if Path("./p2/"+cmd).resolve() == Path("./p2/secret").resolve():
                    ret = "That's the secret file. No touchy!"
                else:
                    return render_template('confirm.html', file=cmd)
        return ret
    
#Using this login method is NOT recommended for anyone who actually wants to write logins. This is a hacky way of doing it. I'd care, but this is for one project in one course.
@app.route("/project3", methods=['GET', 'POST'])
def p3log():
    if request.method == 'GET':
        return render_template('p3login.html', files=getFiles())
    else:
        uname = escape(request.get_json(force=True).get('uname'))
        password = escape(request.get_json(force=True).get('password'))
        folderString = sha256(uname.encode('utf-8')).hexdigest()
        fileName = sha256((password + uname).encode('utf-8')).hexdigest()
        post = request.get_json(force=True).get('post')
        if(post == '0000000000000000'):
            if Path("./templates/p3users/"+folderString).is_dir():
                if Path("./templates/p3users/"+folderString + "/" + fileName).is_file():
                    return render_template("p3users/" + folderString + "/index.html", posts=getPosts(folderString), username=uname, pw=password)
                else:
                    return "Incorrect login or username is already taken!"
            else:
                p = Popen(["./createUser.sh " + folderString + " " + fileName], shell=True, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
                p.communicate()
                return "User created. Re-enter your credentials to log in."
        else:
                if Path("./templates/p3users/"+folderString + "/" + fileName).is_file():
                    with open("templates/p3users/"+folderString+"/posts.txt", "a") as tfile:
                        tfile.write(post+"\n")
                        tfile.close()
                    return getPosts(folderString)
                else:
                    return "Nope."

    
def getFiles():
    p = Popen(["ls ./p2"], shell=True, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
    ret = p.communicate()[0].decode()
    return ret

def getPosts(folder):
    p = Popen(["cat ./templates/p3users/" + folder + "/posts.txt"], shell=True, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
    ret = p.communicate()[0].decode()
    return ret

def create_app():
    return app
