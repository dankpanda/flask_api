from flask import Flask, request, jsonify,make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(50))

class Venue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    address = db.Column(db.String(50))

class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    venue_id = db.Column(db.Integer)
    author_id = db.Column(db.Integer)
    
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(username = data['username']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401
            
        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/users',methods=['GET'])
@token_required
def get_all_users(current_user):
    users = User.query.all()
    output = []

    for i in users:
        user_data = {}
        user_data['id'] = i.id
        user_data['username'] = i.username 
        user_data['password'] = i.password
        output.append(user_data)
    return jsonify({'users': output})

@app.route('/users/<user_id>',methods=['GET'])
@token_required
def get_one_user(current_user,user_id):
    user = User.query.filter_by(id = user_id).first()
    if not user:
        return jsonify({'message':'No user found!'})

    user_data = {}
    user_data['id'] = user.id
    user_data['username'] = user.username 
    user_data['password'] = user.password

    return jsonify({'user':user_data})

@app.route('/users',methods=['POST'])
@token_required
def create_user(current_user):
    data = request.get_json(force=True)
    hashed_password = generate_password_hash(data['password'])
    new_user = User(username = data['username'],password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created'})

@app.route('/venues',methods=['GET'])
@token_required
def get_all_venues(current_user):
    venues = Venue.query.all()
    output = []

    for i in venues:
        venue_data = {}
        venue_data['id'] = i.id
        venue_data['name'] = i.name
        venue_data['address'] = i.address
        output.append(venue_data)
    return jsonify({'venues': output})

@app.route('/venues/<venue_id>',methods=['GET'])
@token_required
def get_one_venue(current_user,venue_id):
    venue = Venue.query.filter_by(id = venue_id).first()
    if not venue:
        return jsonify({'message':'No venue found!'})
    
    venue_data = {}
    venue_data['id'] = venue.id
    venue_data['name'] = venue.name
    venue_data['address'] = venue.address
    return jsonify({'venue':venue_data})


@app.route('/venues',methods=['POST'])
@token_required
def create_venue(current_user):
    data = request.get_json(force=True)
    new_venue = Venue(name = data['name'],address=data['address'])
    db.session.add(new_venue)
    db.session.commit()
    return jsonify({'message': 'New venue added'})

@app.route('/venues/<venue_id>',methods=['DELETE'])
@token_required
def delete_venue(current_user,venue_id):
    venue = Venue.query.filter_by(id = venue_id).first()
    if not venue:
        return jsonify({'message':'No venue found!'})
    db.session.delete(venue)
    db.session.commit()
    return jsonify({'message':'Delete successful'})

@app.route('/venues/<venue_id>/photos/<photo_id>',methods=['GET'])
@token_required
def get_photo(current_user,venue_id, photo_id):
    venue = Venue.query.filter_by(id = venue_id).first()
    if not venue:
        return jsonify({'message':'No venue found!'})
    photos = Photo.query.filter_by(id = photo_id).first()
    if not photos:
        return jsonify({'message':'No photo found!'})
    photo_data = {}
    photo_data['id'] = photos.id
    photo_data['venue_id'] = photos.venue_id 
    photo_data['author_id'] = photos.author_id
    return jsonify({"photo":photo_data})

@app.route('/venues/<venue_id>/photos',methods=['GET'])
@token_required
def get_all_photo(current_user,venue_id):
    venue = Venue.query.filter_by(id = venue_id).first()
    if not venue:
        return jsonify({'message':'No venue found!'})
    output = []
    photos = Photo.query.filter_by(venue_id = venue_id)

    if not photos:
        return jsonify({'message':'No photos for this venue'})

    for i in photos:
        photo_data = {}
        photo_data['id'] = i.id
        photo_data['venue_id'] = i.venue_id 
        photo_data['author_id'] = i.author_id
        output.append(photo_data)
    return jsonify({"photo":output})



@app.route('/venues/<venue_id>/photos',methods=['POST'])
@token_required
def create_photo(current_user,venue_id):
    venue = Venue.query.filter_by(id = venue_id).first()
    if not venue:
        return jsonify({'message':'No venue found!'})

    new_photo = Photo(venue_id = venue_id,author_id=current_user.id)
    db.session.add(new_photo)
    db.session.commit()
    return jsonify({'message': 'New photo added'})

@app.route('/venues/<venue_id>/photos/<photo_id>',methods=['DELETE'])
@token_required
def delete_photo(current_user,venue_id,photo_id):
    venue = Venue.query.filter_by(id = venue_id).first()
    if not venue:
        return jsonify({'message':'No venue found!'})
    photos = Photo.query.filter_by(id = photo_id).first()
    if not photos:
        return jsonify({'message':'No photo found!'})
    db.session.delete(photos)
    db.session.commit()
    return jsonify({'message':'Delete successful'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'username':user.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token':token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})
    
if __name__ == '__main__':
    app.run(debug=True)

