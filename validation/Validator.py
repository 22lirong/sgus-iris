import functools
from flask import Flask, jsonify, request, g, redirect
from config.Settings import Settings

import jwt
import re


def login_required(func):
    @functools.wraps(func)
    def secure_login(*args, **kwargs):
        auth = True
        auth_token = request.cookies.get("jwt")
        print(auth_token)

        if auth_token == None:
            auth = False
        
        '''
        auth_header = request.headers.get('Authorization') #retrieve authorization bearer token
        if auth_header: 
            auth_token = auth_header.split(" ")[1]#retrieve the JWT value without the Bearer 
        else:
            auth_token = ''
            auth = False #Failed check
        '''    
        if auth_token:
            try:
                payload = jwt.decode(auth_token, Settings.secretKey,algorithms=['HS256'])
                #print(payload)
                g.user_id=payload['user_id']#update info in flask application context's g which lasts for one req/res cyycle
                g.role = payload['role']

            except jwt.exceptions.InvalidSignatureError as err:
                print(err)
                auth = False #Failed check

        if auth == False:

            #return jsonify({"Message":"Not Authorized!"}),403 #return response
            return redirect("login.html")
        
        return func(*args, **kwargs)

    return secure_login


def admin_required(func):
    @functools.wraps(func)
    def secure_login(*args, **kwargs):
  
        if(g.role!="admin"):
            #return jsonify({"Message":"Not Authorized!"}),403 #return response
            return redirect("login.html")
        else:
            return func(*args, **kwargs)

    return secure_login
    

def validateRegister(func):
    @functools.wraps(func)
    def validate(*args, **kwargs):
        user_name=request.json['user_name']
        email=request.json['email']
        role=request.json['role']
        password=request.json['password']

        patternUsername=re.compile('^[a-zA-Z0-9]+$')

        #simple email check
        patternEmail=re.compile('^[a-zA-Z0-9]+[\._]?[a-zA-Z0-9]+@\w+\.\w+$')

        patternPassword=re.compile('^[a-zA-Z0-9]{8,}$')

        #print(patternUsername.match(user_name))
        #print(patternEmail.match(email))
        #print(patternPassword.match(password))

        if(patternUsername.match(user_name) and patternEmail.match(email) and patternPassword.match(password) and (role.lower()=="admin" or role.lower()=="member" or role.lower()=="user")):
            print("Correct")
            return func(*args, **kwargs)

        else:
            return jsonify({"Message":"Validation Failed!"}),403 #return response

    return validate
