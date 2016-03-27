from flask import Flask, url_for, render_template
from flask import request, redirect, flash, jsonify
from flask import session as login_session
import random
import string

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

# Setup database connection
engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

app = Flask(__name__)


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.
                    ascii_lowercase + string. digits) for x in xrange(32))
    login_session['state'] = state
    return render_template("login.html", STATE=state)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code
    access_token = request.data
    app_id = json.loads(open('fb_client_secrets.json',
                             'r').read())['web']['app_id']
    app_secret = json.loads(open('fb_client_secrets.json',
                                 'r').read())['web']['app_secret']
    url = ('https://graph.facebook.com/oauth/access_token?grant_type'
           '=fb_exchange_token&client_id=%s&client_secret=%s&'
           'fb_exchange_token=%s') % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    userinfo_url = "https://graph.facebook.com/v2.5/me"
    token = result.split("&")[0]

    # Retrieve user information
    url = "%s?%s&fields=name,id,email" % (userinfo_url, token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']

    # The token must be stored in the login_session in order to properly
    # logout, let's strip out the information before the equals sign in
    # our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # get user picture
    url = ("%s/picture?%s&redirect=0&height=300"
           "&width=300") % (userinfo_url, token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['picture'] = data['data']['url']

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    # Display splash messages
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += (' " style = "width: 300px; height: 300px;border-radius: 150px;'
               '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> ')
    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    CLIENT_ID = json.loads(
        open('g_client_secrets.json', 'r').read())['web']['client_id']
    APPLICATION_NAME = "Restaurant Menu Application"

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('g_client_secrets.json', scope='')
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
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials
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
    login_session['provider'] = 'google'

    # see if user exists
    user_id = getUserID(data['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    # Display splash messages
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += (' " style = "width: 300px; height: 300px;border-radius: 150px;'
               '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> ')
    flash("you are now logged in as %s" % login_session['username'])
    return output


# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
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
    except:
        return None


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = ('https://graph.facebook.com/%s/permissions?'
           'access_token=%s') % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        del login_session['access_token']
        flash("You have successfully been logged out.")
        return redirect(url_for('showRestaurants'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showRestaurants'))


@app.route('/')
@app.route('/restaurants')
def showRestaurants():
    """ This page shows a list with all restaurants in the
    database, and a button link "Add New Restaurant", that points
    to Restaurant creation page """

    # set user_id to implement user authorizarion
    # on Edit and Delete actions
    try:
        user_id = login_session['user_id']
    except:
        user_id = None

    restaurants = session.query(Restaurant).all()
    # user_id is used in the template. Edit and Delete buttons are only
    # displayed for the restaurant creator
    return render_template('restaurants.html', restaurants=restaurants,
                           user_id=user_id)


@app.route('/restaurant/new', methods=['GET', 'POST'])
def newRestaurant():
    """ This page provides a form that allows to input information
    about the new restaurant """

    # Only Authenticated user are allowed to create new Restaurants
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
        restaurant = Restaurant(name=request.form['name'],
                                user_id=login_session['user_id'])
        session.add(restaurant)
        session.commit()
        flash('Restaurant "%s" has been created!' % request.form['name'])
        return redirect(url_for('showRestaurants'))
    else:
        return render_template('newrestaurant.html')


@app.route('/restaurant/<int:id>/edit', methods=['GET', 'POST'])
def editRestaurant(id):
    """ This page will show a form that allows to update data
    for the restaurant with id=id """

    # Only Authenticated user are allowed to edit
    if 'username' not in login_session:
        return redirect('/login')

    restaurant = session.query(Restaurant).filter_by(id=id).one()

    # Check that restaurant to Edit is owned by user
    if restaurant.user_id != login_session['user_id']:
        response = make_response(
            json.dumps('Forbidden! You are not allowed to '
                       'perform this action.'), 403)
        response.headers['Content-Type'] = 'application/json'
        return response

    if request.method == 'POST':
        if request.form['name']:
            oldName = restaurant.name
            restaurant.name = request.form['name']
        session.add(restaurant)
        session.commit()
        flash(('Restaurant "%s" has been edited and '
               'is now called "%s"') % (oldName, restaurant.name))
        return redirect(url_for('showRestaurants'))
    else:
        return render_template('editrestaurant.html', restaurant=restaurant)


@app.route('/restaurant/<int:id>/delete', methods=['GET', 'POST'])
def deleteRestaurant(id):
    """ This page shows confirmation message to delete
    restaurant with id=id from the database """

    # Only Authenticated user are allowed to edit
    if 'username' not in login_session:
        return redirect('/login')

    restaurant = session.query(Restaurant).filter_by(id=id).one()

    # Check that restaurant to Edit is owned by user
    if restaurant.user_id != login_session['user_id']:
        response = make_response(
            json.dumps('Forbidden! You are not allowed to '
                       'perform this action.'), 403)
        response.headers['Content-Type'] = 'application/json'
        return response

    if request.method == 'POST':
        session.delete(restaurant)
        session.commit()
        flash('Restaurant "%s" has been deleted' % restaurant.name)
        return redirect(url_for('showRestaurants'))
    else:
        return render_template('deleterestaurant.html', restaurant=restaurant)


@app.route('/restaurant/<int:id>')
@app.route('/restaurant/<int:id>/menu')
def restaurantMenu(id):
    """ This page will show all menu items for a restaurant"""

    restaurant = session.query(Restaurant).filter_by(id=id).one()
    creator = getUserInfo(restaurant.user_id)
    items = session.query(MenuItem).filter_by(restaurant_id=id).all()
    try:
        user_id = login_session['user_id']
    except:
        # User is not logged in
        user_id = None
    return render_template('menu.html', restaurant=restaurant, items=items,
                           user_id=user_id, creator=creator)


@app.route('/restaurant/<int:restaurant_id>/menu/new', methods=['GET', 'POST'])
def newMenuItem(restaurant_id):
    """ This page will show a form to create a new menu
    item for restaurant with id=restaurant_id """

    # Only Authenticated user are allowed to create
    if 'username' not in login_session:
        return redirect('/login')

    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    # Check that user can create an item for this restaurant
    if restaurant.user_id != login_session['user_id']:
        response = make_response(
            json.dumps('Forbidden! You are not allowed to '
                       'perform this action.'), 403)
        response.headers['Content-Type'] = 'application/json'
        return response

    if request.method == 'POST':
        item = MenuItem(name=request.form['name'],
                        course=request.form['course'],
                        description=request.form['description'],
                        price=request.form['price'],
                        restaurant_id=restaurant_id,
                        user_id=restaurant.user_id)
        session.add(item)
        session.commit()
        flash(('Menu item "%s" has been created for '
               'restaurant "%s"') % (request.form['name'], restaurant.name))
        return redirect(url_for('restaurantMenu', id=restaurant_id))
    else:
        return render_template('newmenuitem.html', restaurant=restaurant)


@app.route('/restaurant/<int:restaurant_id>/menu/<int:item_id>/edit',
           methods=['GET', 'POST'])
def editMenuItem(restaurant_id, item_id):
    """ This page will show a form to update data for
    item with restaurant_id=restaurant_id and id=item_id """

    # Only Authenticated user are allowed to edit
    if 'username' not in login_session:
        return redirect('/login')

    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    item = session.query(MenuItem).filter_by(restaurant_id=restaurant_id,
                                             id=item_id).one()
    # Check that item to Edit is owned by user
    if item.user_id != login_session['user_id']:
        response = make_response(
            json.dumps('Forbidden! You are not allowed to '
                       'perform this action.'), 403)
        response.headers['Content-Type'] = 'application/json'
        return response

    if request.method == 'POST':
        if request.form['name']:
            oldName = item.name
            item.name = request.form['name']
            item.course = request.form['course']
            item.description = request.form['description']
            item.price = request.form['price']
        session.add(item)
        session.commit()
        flash(('Menu item "%s" has been edited for restaurant '
               '"%s"') % (item.name, restaurant.name))
        return redirect(url_for('restaurantMenu', id=restaurant_id))
    else:
        return render_template('editmenuitem.html', restaurant=restaurant,
                               item=item)


@app.route('/restaurant/<int:restaurant_id>/menu/<int:item_id>/delete',
           methods=['GET', 'POST'])
def deleteMenuItem(restaurant_id, item_id):
    """ This page will show a confirmation message to delete
    item with restaurant_id=restaurant_id and id=item_id from the database """

    # Only Authenticated user are allowed to delete
    if 'username' not in login_session:
        return redirect('/login')

    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    item = session.query(MenuItem).filter_by(restaurant_id=restaurant_id,
                                             id=item_id).one()
    # Check that item to Delete is owned by user
    if item.user_id != login_session['user_id']:
        response = make_response(
            json.dumps('Forbidden! You are not allowed to '
                       'perform this action.'), 403)
        response.headers['Content-Type'] = 'application/json'
        return response

    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash('Menu item "%s" has been deleted' % item.name)
        return redirect(url_for('restaurantMenu', id=restaurant_id))
    else:
        return render_template('deletemenuitem.html', restaurant=restaurant,
                               item=item)


# API Endpoints
@app.route('/restaurants/JSON')
def showRestaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(Restaurants=[r.serialize for r in restaurants])


@app.route('/restaurant/<int:id>/menu/JSON')
def restaurantMenuJSON(id):
    items = session.query(MenuItem).filter_by(restaurant_id=id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:item_id>/JSON')
def editMenuItemJSON(restaurant_id, item_id):
    item = session.query(MenuItem).filter_by(restaurant_id=restaurant_id,
                                             id=item_id).one()
    return jsonify(Restaurants=[item.serialize])


if __name__ == '__main__':
    app.secret_key = "clave super secreta!!"
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
