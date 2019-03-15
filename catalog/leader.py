from flask import Flask, render_template, url_for
from flask import request, redirect, flash, make_response, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from Database_Setup import Base, InstitutionName, CourseName, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests
import datetime
engine = create_engine('sqlite:///institutions.db',
                       connect_args={'check_same_thread': False}, echo=True)
Base.metadata.create_all(engine)
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json',
                            'r').read())['web']['client_id']
APPLICATION_NAME = "Institutions"

DBSession = sessionmaker(bind=engine)
session = DBSession()
# Create anti-forgery state token
pqrs_rat = session.query(InstitutionName).all()


# login
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    pqrs_rat = session.query(InstitutionName).all()
    pqres = session.query(CourseName).all()
    return render_template('login.html',
                           STATE=state, pqrs_rat=pqrs_rat, pqres=pqres)
    # return render_template('myhome.html', STATE=state
    # pqrs_rat=pqrs_rat,pqres=pqres)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print ("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px; border-radius: 150px;'
    '-webkit-border-radius: 150px; -moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print ("done!")
    return output


# User Helper Functions
def createUser(login_session):
    User1 = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(User1)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception as error:
        print(error)
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session
# Home


@app.route('/')
@app.route('/home')
def home():
    pqrs_rat = session.query(InstitutionName).all()
    return render_template('myhome.html', pqrs_rat=pqrs_rat)

#####
# Institution Hub for admins


@app.route('/InstitutionCenters')
def InstitutionCenters():
    try:
        if login_session['username']:
            name = login_session['username']
            pqrs_rat = session.query(InstitutionName).all()
            pqrs = session.query(InstitutionName).all()
            pqres = session.query(CourseName).all()
            return render_template('myhome.html', pqrs_rat=pqrs_rat,
                                   pqrs=pqrs, pqres=pqres, uname=name)
    except:
        return redirect(url_for('showLogin'))

######
# Showing Institutions based on Institution category


@app.route('/InstitutionCenters/<int:pqrsid>/AllInstitution')
def showInstitutions(pqrsid):
    pqrs_rat = session.query(InstitutionName).all()
    pqrs = session.query(InstitutionName).filter_by(id=pqrsid).one()
    pqres = session.query(CourseName).filter_by(institutionnameid=pqrsid).all()
    try:
        if login_session['username']:
            return render_template('showInstitutions.html', pqrs_rat=pqrs_rat,
                                   pqrs=pqrs, pqres=pqres,
                                   uname=login_session['username'])
    except:
        return render_template('showInstitutions.html',
                               pqrs_rat=pqrs_rat, pqrs=pqrs, pqres=pqres)

#####
# Add New Institution


@app.route('/InstitutionCenters/addInstitutionName', methods=['POST', 'GET'])
def addInstitutionName():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        institutionname = InstitutionName(name=request.form['name'],
                                          user_id=login_session['user_id'])
        session.add(institutionname)
        session.commit()
        return redirect(url_for('InstitutionCenters'))
    else:
        return render_template('addInstitutionName.html', pqrs_rat=pqrs_rat)

########
# Edit Institution Name


@app.route('/InstitutionCenters/<int:pqrsid>/edit', methods=['POST', 'GET'])
def editInstitutionName(pqrsid):
    if 'username' not in login_session:
        return redirect('/login')
    editInstitutionName = session.query(InstitutionName).filter_by(
        id=pqrsid).one()
    creator = getUserInfo(editInstitutionName.user_id)
    user = getUserInfo(login_session['user_id'])
    # If logged in user != Course owner redirect them
    if creator.id != login_session['user_id']:
        flash("You cannot edit this Institution Name."
              "This is belongs to %s" % creator.name)
        return redirect(url_for('InstitutionCenters'))
    if request.method == "POST":
        if request.form['name']:
            editInstitutionName.name = request.form['name']
        session.add(editInstitutionName)
        session.commit()
        flash("Institution Name Edited Successfully")
        return redirect(url_for('InstitutionCenters'))
    else:
        # pqrs_rat is global variable we can them in entire application
        return render_template('editInstitutionName.html',
                               pqrsb=editInstitutionName, pqrs_rat=pqrs_rat)

######
# Delete InstitutionName


@app.route('/InstitutionCenters/<int:pqrsid>/delete', methods=['POST', 'GET'])
def deleteInstitutionName(pqrsid):
    if 'username' not in login_session:
        return redirect('/login')
    pqrsb = session.query(InstitutionName).filter_by(id=pqrsid).one()
    creator = getUserInfo(pqrsb.user_id)
    user = getUserInfo(login_session['user_id'])
    # If logged in user != Course owner redirect them
    if creator.id != login_session['user_id']:
        flash("You cannot Delete this Institution Name."
              "This is belongs to %s" % creator.name)
        return redirect(url_for('InstitutionCenters'))
    if request.method == "POST":
        session.delete(pqrsb)
        session.commit()
        flash("Institution Name Deleted Successfully")
        return redirect(url_for('InstitutionCenters'))
    else:
        return render_template('deleteInstitutionName.html',
                               pqrsb=pqrsb, pqrs_rat=pqrs_rat
                               )

######
# Add NewInstitution Name Details


@app.route('/InstitutionCenters/addInstitutionName/'
           'addInstitutionCourseDetails/<string:pqrsbname>/add',
           methods=['GET', 'POST'])
def addInstitutionDetails(pqrsbname):
    if 'username' not in login_session:
        return redirect('/login')
    pqrs = session.query(InstitutionName).filter_by(name=pqrsbname).one()
    # See if the logged in user is not the owner of byke
    creator = getUserInfo(pqrs.user_id)
    user = getUserInfo(login_session['user_id'])
    # If logged in user != course owner redirect them
    if creator.id != login_session['user_id']:
        flash("You can't add new Institution course."
              "This is belongs to %s" % creator.name)
        return redirect(url_for('showInstitutions', pqrsid=pqrs.id))
    if request.method == 'POST':
        name = request.form['name']
        duration = request.form['duration']
        address = request.form['address']
        fee = request.form['fee']
        feedback = request.form['feedback']
        coursedetails = CourseName(name=name,
                                   duration=duration,
                                   address=address,
                                   fee=fee,
                                   feedback=feedback,
                                   date=datetime.datetime.now(),
                                   institutionnameid=pqrs.id,
                                   user_id=login_session['user_id'])
        session.add(coursedetails)
        session.commit()
        return redirect(url_for('showInstitutions', pqrsid=pqrs.id))
    else:
        return render_template('addInstitutionCourseDetails.html',
                               pqrsbname=pqrs.name, pqrs_rat=pqrs_rat)

######
# Edit coursedetails


@app.route('/InstitutionCenters/<int:pqrsid>/<string:pqrsbename>/edit',
           methods=['GET', 'POST'])
def editInstitutionCourse(pqrsid, pqrsbename):
    if 'username' not in login_session:
        return redirect('/login')
    pqrsb = session.query(InstitutionName).filter_by(id=pqrsid).one()
    coursedetails = session.query(CourseName).filter_by(name=pqrsbename).one()
    # See if the logged in user is not the owner of byke
    creator = getUserInfo(pqrsb.user_id)
    user = getUserInfo(login_session['user_id'])
    # If logged in user != Course owner redirect them
    if creator.id != login_session['user_id']:
        flash("You can't edit this Institution Course"
              "This is belongs to %s" % creator.name)
        return redirect(url_for('showInstitutions', pqrsid=pqrsb.id))
    # POST methods
    if request.method == 'POST':
        coursedetails.name = request.form['name']
        coursedetails.duration = request.form['duration']
        coursedetails.address = request.form['address']
        coursedetails.fee = request.form['fee']
        coursedetails.feedback = request.form['feedback']
        coursedetails.date = datetime.datetime.now()
        session.add(coursedetails)
        session.commit()
        flash("course Edited Successfully")
        return redirect(url_for('showInstitutions', pqrsid=pqrsid))
    else:
        return render_template('editInstitutionCourse.html',
                               pqrsid=pqrsid, coursedetails=coursedetails,
                               pqrs_rat=pqrs_rat
                               )

#####
# Delte Courses in Institution


@app.route('/InstitutionCenters/<int:pqrsid>/<string:pqrsbename>/delete',
           methods=['GET', 'POST'])
def deleteInstitutionCourse(pqrsid, pqrsbename):
    if 'username' not in login_session:
        return redirect('/login')
    pqrsb = session.query(InstitutionName).filter_by(id=pqrsid).one()
    coursedetails = session.query(CourseName).filter_by(name=pqrsbename).one()
    # See if the logged in user is not the owner of Course
    creator = getUserInfo(pqrsb.user_id)
    user = getUserInfo(login_session['user_id'])
    # If logged in user != Course owner redirect them
    if creator.id != login_session['user_id']:
        flash("You can't delete this Course"
              "This is belongs to %s" % creator.name)
        return redirect(url_for('showInstitutions', pqrsid=pqrsb.id))
    if request.method == "POST":
        session.delete(coursedetails)
        session.commit()
        flash("Deleted Course Successfully")
        return redirect(url_for('showInstitutions', pqrsid=pqrsid))
    else:
        return render_template('deleteInstitutionCourse.html',
                               pqrsid=pqrsid, coursedetails=coursedetails,
                               pqrs_rat=pqrs_rat
                               )
####
# Logout from current user


@app.route('/logout')
def logout():
    access_token = login_session['access_token']
    print ('In gdisconnect access token is %s', access_token)
    print ('User name is: ')
    print (login_session['username'])
    if access_token is None:
        print ('Access Token is None')
        response = make_response(
            json.dumps('Current user not connected....'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = login_session['access_token']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = \
        h.request(uri=url, method='POST', body=None,
                  headers={
                      'content-type': 'application/x-www-form-urlencoded'})[0]

    print (result['status'])
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash("Successful logged out")
        return redirect(url_for('showLogin'))
        # return response
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

#####
# Json


@app.route('/InstitutionCenters/JSON')
def allInstitutionsJSON():
    institutionnames = session.query(InstitutionName).all()
    category_dict = [c.serialize for c in institutionnames]
    for c in range(len(category_dict)):
        institutions = [
                        i.serialize for i in session.query(
                            CourseName).filter_by(
                                institutionnameid=category_dict[c]["id"]
                                  ).all()]
        if institutions:
            category_dict[c]["institutions"] = institutions
    return jsonify(InstitutionName=category_dict)

####


@app.route('/InstitutionCenters/institutionName/JSON')
def categoriesJSON():
    institutions = session.query(InstitutionName).all()
    return jsonify(InstitutionName=[c.serialize for c in institutions])

####


@app.route('/InstitutionCenters/institutions/JSON')
def coursesJSON():
    courses = session.query(CourseName).all()
    return jsonify(institutions=[i.serialize for i in courses])

#####


@app.route('/InstitutionCenters/<path:institution_name>/institutions/JSON')
def categorycoursesJSON(institution_name):
    institutionName = session.query(
        InstitutionName).filter_by(name=institution_name).one()
    institutions = session.query(CourseName).filter_by(
        institutionname=institutionName).all()
    return jsonify(institutionName=[i.serialize for i in institutions])

#####


@app.route(
    '/InstitutionCenters/<path:institution_name>'
    '/<path:institutioncourse_name>/JSON')
def CourseJSON(institution_name, institutioncourse_name):
    institutionName = session.query(InstitutionName).filter_by(
        name=institution_name).one()
    institutionCourseName = session.query(CourseName).filter_by(
           name=institutioncourse_name, institutionname=institutionName).one()
    return jsonify(institutionCourseName=[institutionCourseName.serialize])

if __name__ == '__main__':
    app.secret_key = "super_secret_key"
    app.debug = True
    app.run(host='127.0.0.1', port=2000)
