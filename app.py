from flask import Flask, jsonify, request, g, render_template, abort, make_response, redirect, url_for

from model.User import User
from model.Pred import Pred

from validation.Validator import *

import numpy as np
import joblib
import re

from flask_cors import CORS

app = Flask(__name__)

CORS(app)

# landing page
@app.route("/")
@app.route("/index")
@app.route("/home")
def index():
    return render_template("index.html")


# register page
@app.route("/register")
def register():
    return render_template("register.html")


# register form
@app.route('/registerUser', methods=['GET', 'POST'])
def registerUser():
    try:
        user_name = request.form['user_name']
        email = request.form['email']
        pwd = request.form['pwd']
        pwd2 = request.form['pwd2']

        print(user_name)
        print(email)
        print(pwd)
        print(pwd2)

        msg = ""

        if pwd != pwd2:
            msg = "Password and Confirm Password do not match! Please try again."
            return render_template("register.html", message = msg)

        elif not re.match(r'[A-Za-z0-9]+', user_name):
            msg = "User Name must contain only characters and numbers! Please try again."
            return render_template("register.html", message = msg)

        else:
            userJson = {
                            "user_name": user_name,
                            "email": email,
                            "password": pwd,
                            "role": "user"
                        }
            print(userJson)

            output = User.insertUser(userJson)

            return render_template("register.html", message = "Thank you! You have successfully registered.")

    except Exception as err:
        print(err)
        return render_template("register.html", message = "Error! Please try again.")


# login page
@app.route("/login")
def login():
    return render_template("login.html")


# login form
@app.route('/loginUser', methods=['POST'])
def loginUser():
    try:
        email = request.form['email']
        pwd = request.form['pwd']

        print(email)
        print(pwd)

        output = User.loginUser({"email": email, "password":pwd})
        print(output)

        jsonUser = User.getUserId(email)
        user_id = jsonUser[0]['user_id']
        user_name = jsonUser[0]['user_name']

        print(user_id)
        print(user_name)
        
        if output["jwt"] == "":
            return render_template("login.html", message = "Invalid Login Credentials! Please try again.")
       
        else:
            resp = make_response(render_template("viewPreds.html", user_id = user_id, user_name = user_name))
            resp.set_cookie('jwt', output["jwt"])
    
            return resp
    except Exception as err:
        print(err)
        return render_template("login.html",message="Error! Please try again.")


# prediction page
@app.route('/viewPreds.html')
@login_required
def searchPred():
    try:
        user_id=request.args.get("user_id")
        user_name = request.args.get("user_name")

        print(user_id)
        print(user_name)
        
        jsonPreds = Pred.getPredByUser(user_id)
        #print(jsonPreds)

        return render_template("viewPreds.html", preds = jsonPreds, user_id = user_id, user_name = user_name)
    
    except Exception as err:
        print(err)
        return render_template("viewPreds.html", user_id = user_id, user_name = user_name)


# predict form
@app.route('/predict', methods = ['GET', 'POST'])
@login_required
def predict():
    try:
        sepal_length = request.form['sepal_length']
        sepal_width = request.form['sepal_width']
        petal_length = request.form['petal_length']
        petal_width = request.form['petal_width']
        user_id = request.form['user_id']
        user_name = request.form['user_name']
        
        msg = ""

        print(sepal_length, sepal_width, petal_length, petal_width, user_id)

        # keep all inputs in array
        test_data = [sepal_length, sepal_width, petal_length, petal_width]
        print(test_data)
    
        # convert value data into numpy array
        test_data = np.array(test_data)
    
        # reshape array
        test_data = test_data.reshape(1,-1)
        print(test_data)
    
        # open file
        file = open("randomforest_model.pkl","rb")
    
        # load trained model
        trained_model = joblib.load(file)
    
        # predict
        prediction = trained_model.predict(test_data)
    
        print(prediction[0])
        
        # save data to sql
        jsonPreds = Pred.insertPred(user_id, sepal_length, sepal_width, petal_length, petal_width, prediction[0])
        print(jsonPreds)
        
        return render_template("viewPreds.html", prediction = prediction,
                                                 preds = jsonPreds,
                                                 sepal_length = sepal_length,
                                                 sepal_width = sepal_width,
                                                 petal_length = petal_length,
                                                 petal_width = petal_width,
                                                 user_id = user_id,
                                                 user_name = user_name)

    except Exception as err:
        print(err)
        msg = "To make prediction, please fill in all fields with numeric values from 0 to 8, then click on 'Predict' button. To see results, click on 'View Prediction Results' button."
        return render_template("viewPreds.html", user_id = user_id, user_name = user_name, message = msg)


# delete predict
@app.route('/deletePred', methods = ['POST'])
@login_required
def deletePred():
    try:
        user_id = request.args.get("user_id")
        user_name = request.args.get("user_name")

        print(user_id)
        print(user_name)
        
        pred_id = request.args.get("pred_id")
        print(pred_id)

        output = Pred.deletePred(pred_id)
        print(output)

        resp = make_response(render_template("viewPreds.html", user_id = user_id, user_name = user_name))
        return resp
        
    except Exception as err:
        print(err)
        return render_template("login.html")


# request reset password page
@app.route("/reset")
def reset():
    return render_template("resetReq.html")


# resetReq form
@app.route('/resetReq', methods=['GET', 'POST'])
def resetReq():
    try:
        email = request.form['email']
        print(email)
        
        msg = ""

        output = User.resetReq({"email": email})
        print(output)

        if output["valid"] == "yes":
            msg = "Reset email sent! > testing: /resetPwd.html"
        else:
            msg = "Account not found! Please try again"
        
        return render_template("resetReq.html", message = msg)

    except Exception as err:
        print(err)
        return render_template("resetReq.html", message = "Error! Please try again")


# change password
@app.route('/reset_pwd', methods=['GET', 'POST'])
def resetPwd():
    try:
        # hard-coded user_name and email for testing use
        user_name = request.form['user_name']
        email = request.form['email']
        
        password = request.form['pwd']
        password2 = request.form['pwd2']

        print(user_name)
        print(email)
        print(password)
        print(password2)

        msg = ""

        if password != password2:
            msg = "Password and Confirm Password do not match! Please try again."
            return render_template("resetPwd.html", message = msg)

        else:
            output = User.resetPwd(password, email)
            print(output)
            return render_template("resetPwd.html", message = "You have successfully reset your password!")

    except Exception as err:
        print(err)
        return render_template("resetPwd.html", message = "Error! Please try again.")


# admin page
@app.route('/admin.html')
@login_required
@admin_required
def searchUser():
    try:
        user_name = request.args.get("search")
        # print(user_name)

        jsonUsers = User.searchUser(user_name)
        # print(jsonUsers)

        return render_template("admin.html", users=jsonUsers, search=user_name)
    except Exception as err:
        print(err)
        return render_template("admin.html")


# user details page
@app.route('/userDetails.html')
@login_required
@admin_required
def getUserDetails():
    try:
        user_id = request.args.get("user_id")
        
        jsonUser = User.getUser(user_id)
        # print(jsonUser)

        jsonPreds = Pred.getPredByUser(user_id)
        # print(jsonPreds)

        return render_template("userDetails.html", user=jsonUser[0], preds=jsonPreds)
    except Exception as err:
        print(err)
        return redirect("admin.html?search=")


# remove predict record
@app.route('/removePred', methods = ['POST'])
@login_required
@admin_required
def removePred():
    try:
        pred_id = request.args.get("pred_id")
        print(pred_id)

        output = Pred.deletePred(pred_id)
        print(output)

        return redirect("admin.html?search=")
    except Exception as err:
        print(err)
        return redirect("admin.html?search=")


# remove user
@app.route('/removeUser', methods = ['POST'])
@login_required
@admin_required
def removeUser():
    try:
        user_id = request.args.get("user_id")
        print(user_id)

        output = User.deleteUser(user_id)
        print(output)

        return redirect("admin.html?search=")
    except Exception as err:
        print(err)
        return redirect("admin.html?search=")


# change user's role to 'admin'
@app.route('/changeRole', methods = ['POST'])
@login_required
@admin_required
def changeRole():
    try:
        user_id = request.args.get("user_id")
        print(user_id)

        # role is 'admin'
        role = "admin"

        output = User.changeRole(role, user_id)
        print(output)

        return redirect("admin.html?search=")
    except Exception as err:
        print(err)
        return redirect("admin.html?search=")


# logout
@app.route('/logout')
def logout():
    resp = make_response(redirect("/"))
    resp.delete_cookie('jwt')
    
    return resp


@app.route('/<string:url>')
def staticPage(url):
    try:
        return render_template(url)
    except Exception as err:
        abort(404)


@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(debug=True)

