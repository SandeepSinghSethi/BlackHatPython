import paramiko

def sshcmd(ip,port,user,passwd,cmd):
    client =  paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    key = paramiko.RSAKey.from_private_key_file('/home/sandeep/userdata/crackmes/lvmst/black-hat-python/blackhat-python3/chapter02/test_rsa.key')

    client.connect(ip,username=user,password=passwd,port=port,pkey=key)
    session = client.get_transport().open_session()
    if session.active:
        session.exec_command(cmd)
        print(session.recv(4096))
    return

sshcmd('localhost',22,'wadu','wadu','id')
