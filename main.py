from flask import Flask, render_template,request,jsonify,make_response
from flask_restful import Api, Resource, reqparse, abort, fields, marshal_with
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql.schema import UniqueConstraint
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship, backref,joinedload
import uuid
import jwt
import datetime
from functools import wraps

from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.ext.declarative import declarative_base

app = Flask(__name__)
api = Api(app)
app.config['SECRET_KEY']='Th1s1ss3cr3t'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:fitelec@localhost:5432/calculationGenerator'
db = SQLAlchemy(app)

class UserModel(db.Model):
	__tablename__ = "t_user"
	userId = db.Column(db.Integer, primary_key=True,autoincrement=True)
	userPublicId = db.Column(db.String(100))
	userName = db.Column(db.String(100), nullable=False)
	userPsw = db.Column(db.String(100), nullable=False)
	userAdmin = db.Column(db.Boolean)
	cash = db.Column(db.Integer)
	#scores = db.relationship('ScoreModel', backref='player', lazy=True)
	scores = db.relationship('ScoreModel', back_populates='player', lazy=True)
	activeThemeId = db.Column(db.Integer, db.ForeignKey('t_user_object.userObjectId'),nullable=True)

	#def __repr__(self):
	#	return f"User(userId = {userId}, userName = {userName}, userPsw = {userPsw}, userPublicId = {userPublicId})"

class ScoreModel(db.Model):
	__tablename__ = "t_score"
	scoreId = db.Column(db.Integer, primary_key=True,autoincrement=True)
	scoreValue = db.Column(db.Integer, nullable=False)
	scoreTime = db.Column(db.Integer, nullable=False)
	userId = db.Column(db.Integer, db.ForeignKey('t_user.userId'),nullable=False)
	player = db.relationship('UserModel', back_populates='scores', lazy=True)

	#def __repr__(self):
		#return f"Score(scoreId = {scoreId}, scoreValue = {scoreValue}, scoreTime = {scoreTime}, userId = {userId})"

class UserObjectModel(db.Model):
	__tablename__ = "t_user_object"
	userObjectId = db.Column(db.Integer, primary_key=True,autoincrement=True)
	objectName = db.Column(db.String(100))
	objectType = db.Column(db.String(100))
	attribut1 = db.Column(db.Integer)
	attribut2 = db.Column(db.Integer)
	attribut3 = db.Column(db.Integer)
	attribut4 = db.Column(db.Integer)
	attribut5 = db.Column(db.Integer)
	attribut6 = db.Column(db.Integer)
	userId = db.Column(db.Integer, db.ForeignKey('t_user.userId'),nullable=False)

class SetupModel(db.Model):
	__tablename__ = "t_setup"
	setupId = db.Column(db.Integer, primary_key=True,autoincrement=True)
	currentVersion 	= db.Column(db.String(10))
	apkLink 		= db.Column(db.String(200))

user_put_args = reqparse.RequestParser()
user_put_args.add_argument("userName", type=str, help="Nom de l'utilisateur", required=True)
user_put_args.add_argument("userPsw", type=str, help="Mot de passe", required=True)
user_put_args.add_argument("userAdmin", type=bool, help="Administrateur", required=False)
user_put_args.add_argument("userPublicId", type=str, help="ID public", required=False)
user_put_args.add_argument("userId", type=int, help="Id de l'utilisateur", required=False)
user_put_args.add_argument("cash", type=int, help="Argent total de l'utilisateur", required=False)

user_update_args = reqparse.RequestParser()
user_update_args.add_argument("userName", type=str, help="User Name is required")
user_update_args.add_argument("userPsw", type=str, help="Views of the video")
user_update_args.add_argument("userId", type=int, help="Id de l'utilisateur",required=True)
user_update_args.add_argument("cash", type=int, help="Argent total de l'utilisateur", required=False)

score_put_args = reqparse.RequestParser()
score_put_args.add_argument("scoreValue", type=int, help="Valeur du score", required=True)
score_put_args.add_argument("scoreTime", type=int, help="Temps de la partie", required=True)
score_put_args.add_argument("scoreId", type=int, help="Id score", required=False)
score_put_args.add_argument("userId", type=int, help="Id de l'utilisateur", required=True)

score_patch_args = reqparse.RequestParser()
score_patch_args.add_argument("scoreValue", type=int, help="Valeur du score", required=True)
#score_patch_args.add_argument("scoreTime", type=int, help="Temps de la partie", required=True)

user_object_post_args = reqparse.RequestParser()
user_object_post_args.add_argument("objectName", type=str, help="Nom de l'objet", required=True)
user_object_post_args.add_argument("objectType", type=str, help="Type de l'objet", required=True)
user_object_post_args.add_argument("userId", type=int, help="Id de l'utilisateur", required=True)

user_resource_fields = {
	'userId': fields.Integer,
	'userName': fields.String,
	'userPsw': fields.String,
	'userPublicId': fields.String,
	'userAdmin': fields.Boolean,
	"cash" : fields.Integer,
	'token' : fields.String,
	'activeThemeId' : fields.Integer
}
score_resource_fields = {
	'scoreId': fields.Integer,
	'scoreValue': fields.Integer,
	'scoreTime': fields.Integer,
	'userId': fields.Integer,
	'player' : fields.Nested(user_resource_fields)
}
user_resource_fields = {
	'userId': fields.Integer,
	'userName': fields.String,
	'userPsw': fields.String,
	'userPublicId': fields.String,
	'userAdmin': fields.Boolean,
	"cash" : fields.Integer,
	'token' : fields.String,
	'activeThemeId' : fields.Integer,
	'scores' : fields.Nested(score_resource_fields)
}

user_object_resource_fields = {
	'userObjectId': fields.Integer,
	'objectName': fields.String,
	'objectType': fields.String,
	'attribut1': fields.Integer,
	'attribut2': fields.Integer,
	'attribut3': fields.Integer,
	'attribut4': fields.Integer,
	'attribut5': fields.Integer,
	'attribut6': fields.Integer,
	'userId': fields.Integer
}

setup_resource_fields = {
	'currentVersion' : fields.String,
	'apkLink' : fields.String
}

user_active_theme_resource_fields = {
	'userObjectId': fields.Integer,
	'objectName': fields.String
}

# Fonction TOKEN
def token_required(f):
	@wraps(f)
	def decorator(*args, **kwargs):
		print("Début de fonction token")
		token = None
		if 'x-access-tokens' in request.headers:
			token = request.headers['x-access-tokens']
		print("Token : ",token)
		if not token or token == None:
			return make_response('A valid token is missing !',401,{'WWW.Authentication':'Basic realm: "login required"'})
		try:
			print("On va décoder !")
			data = jwt.decode(token, app.config['SECRET_KEY'])
			print("On a décodé et le contenu de data est : ",data)
			current_user = UserModel.query.filter_by(userPublicId=data['userPublicId']).first()
		except Exception as err:
			print(err)
			return jsonify({'message': 'token is invalid'})
		return f(current_user, *args, **kwargs)
	return decorator

#db.drop_all()
#db.create_all() #For first run
class LoginUser(Resource):
	#@marshal_with(user_resource_fields)
	#LOGIN
	def get(self): 
		auth = request.authorization
		if not auth or not auth.username or not auth.password:  
			return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})
		user = UserModel.query.filter_by(userName=auth.username).first()
		if user == None :
			return make_response('Utilisateur inconnu !',  401, {'WWW.Authentication': 'Basic realm: "login required"'})
		if check_password_hash(user.userPsw, auth.password):
			token = jwt.encode({'userPublicId': user.userPublicId, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(hours=720)}, app.config['SECRET_KEY']) 
			print("Le contenu de token est : ",token, " et il est de type : ",type(token))
			#return jsonify({'token' : token.decode('UTF-8')})
			return make_response(jsonify({'token' : token.decode('UTF-8')}),  201)
		return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})
	@token_required
	def put(self,test):
		return make_response(jsonify({'userName' : self.userName,'cash' : self.cash, 'userId' : self.userId}),  201)
class RegisterUser(Resource):
	@marshal_with(user_resource_fields)
	def put(self):
		args = user_put_args.parse_args()
		result = UserModel.query.filter_by(userName=args['userName']).first()
		if result:
			abort(409, message="Utilisateur déjà existant ...")
		isAdmin = False
		if args['userAdmin']:
			isAdmin = args['userAdmin']
		hashed_password = generate_password_hash(args['userPsw'], method='sha256')
		print("Le contenu du hash est : ",hashed_password)
		user = UserModel(userId=args['userId'], userPublicId=str(uuid.uuid4()), userName=args['userName'], userPsw=hashed_password, userAdmin=isAdmin)
		db.session.add(user)
		db.session.commit()
		return user, 201

	@marshal_with(user_resource_fields)
	@token_required
	def patch(self,test):
		print("Entrée dans le patch")
		print(self.userPublicId)
		args = user_update_args.parse_args()
		print("Args : ",args)
		result = UserModel.query.filter_by(userId=args['userId']).first()
		print("Après le résult !")
		if not result:
			abort(404, message="User doesn't exist, cannot update")
		if result.userPublicId != self.userPublicId and not self.userAdmin:
			abort(404, message="Vous n'avez pas le droit de modifier les informations d'un autre utilisateur !")
		if args['userName']:
			result.userName = args['userName']
		if args['userPsw']:
			hashed_password = generate_password_hash(args['userPsw'], method='sha256')
			result.userPsw = hashed_password
		if args['cash']:
			result.cash = args['cash'] + result.cash
		db.session.commit()
		print("OK")
		return result
  
class Score(Resource):
	@marshal_with(score_resource_fields)
	def get(self):
		#result = ScoreModel.query.filter_by(name)
		#result = ScoreModel.query.filter_by(scoreId='1').first()
		result = ScoreModel.query.all()
		if not result:
			abort(404, message="Impossible d'afficher le score !")
		if result == None:
			abort(404, message="Impossible d'afficher le score !")
		print (result[1].scoreValue)
		print (result[1].player.userName)
		#return make_response(result,201)
		return result
	#@marshal_with(score_resource_fields)
	@token_required
	def put(self,test):
		args = score_put_args.parse_args()
		score = ScoreModel(scoreValue=args['scoreValue'], scoreTime=args['scoreTime'], scoreId=args['scoreId'], userId=args['userId'])
		db.session.add(score)
		db.session.commit()
		return make_response('OK',201)
		#return score, 201
	#@marshal_with(score_resource_fields)
	@token_required
	def patch(self,test):
		#print(self.userName)
		#print(self.scores[0].scoreValue)
		args = score_patch_args.parse_args()
		result = ScoreModel.query.filter_by(userId=self.userId).first()
		if not result:
			score = ScoreModel(scoreValue=args['scoreValue'], scoreTime="100",userId=self.userId)
			db.session.add(score)
			db.session.commit()
			return make_response('FIRST SCORE',200)
			#abort(404, message="User doesn't exist, cannot update")
		if args['scoreValue'] > result.scoreValue:
			result.scoreValue = args['scoreValue']
			db.session.commit()
			return make_response('NEW BETTER SCORE',200)
		return make_response('N/A',201)
class User(Resource):
	#@token_required
	@marshal_with(user_resource_fields)
	def get(self):
		result = UserModel.query.all()
		print(result[1].userName)
		print(result[1].userPublicId)
		return result
		#return make_response(jsonify({'userName' : self.userName}),  201)

class UserObject(Resource):
	@token_required
	def post(self,test):
		args = user_object_post_args.parse_args()
		userObject = UserObjectModel(objectName=args['objectName'], objectType=args['objectType'], userId=args['userId'])
		db.session.add(userObject)
		db.session.commit()
		return make_response('OK',201)
	@token_required
	@marshal_with(user_object_resource_fields)
	def get(self,test):
		result = UserObjectModel.query.filter_by(userId=self.userId)
		return result

class Setup(Resource):
	@marshal_with(setup_resource_fields)
	def get(self):
		result = SetupModel.query.first()
		return result
class ActiveUserTheme(Resource):
	@token_required
	@marshal_with(user_object_resource_fields)
	def get(self,test):
		result = UserObject.query.filter_by(userObjectId=self.activeThemeId)
		return result
	@token_required
	#@marshal_with(user_resource_fields)
	#TODO : Fonction patch à développer ! 
	def patch(self,test):
		result = ScoreModel.query.filter_by(userId=self.userId).first()
		if not result:
			return
		return

api.add_resource(LoginUser, "/login")
api.add_resource(RegisterUser, "/register")
api.add_resource(Score, "/score")
api.add_resource(User, "/user")
api.add_resource(UserObject, "/object_user")
api.add_resource(Setup, "/setup")
api.add_resource(ActiveUserTheme, "/active_user_theme")

@app.route('/')
def index():
	return render_template('index.html')

if __name__ == "__main__":
	app.run(host='0.0.0.0')
	#app.run(debug=True)
# Commentaire depuis la tablette S7+ avant le push !