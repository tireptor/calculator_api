from flask import Flask, render_template,request,jsonify,make_response
from flask_restful import Api, Resource, reqparse, abort, fields, marshal_with
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
api = Api(app)
app.config['SECRET_KEY']='Th1s1ss3cr3t'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:fitelec@localhost:5433/calculationGenerator'
db = SQLAlchemy(app)

class UserModel(db.Model):
	__tablename__ = "t_user"
	userId = db.Column(db.Integer, primary_key=True,autoincrement=True)
	userPublicId = db.Column(db.String(100))
	userName = db.Column(db.String(100), nullable=False)
	userPsw = db.Column(db.String(100), nullable=False)
	userAdmin = db.Column(db.Boolean)
	scores = db.relationship('ScoreModel', backref='userModel', lazy=True)

	#def __repr__(self):
	#	return f"User(userId = {userId}, userName = {userName}, userPsw = {userPsw}, userPublicId = {userPublicId})"

class ScoreModel(db.Model):
	__tablename__ = "t_score"
	scoreId = db.Column(db.Integer, primary_key=True,autoincrement=True)
	scoreValue = db.Column(db.Integer, nullable=False)
	scoreTime = db.Column(db.Integer, nullable=False)
	userId = db.Column(db.Integer, db.ForeignKey('t_user.userId'),nullable=False)

	def __repr__(self):
		return f"Score(scoreId = {scoreId}, scoreValue = {scoreValue}, scoreTime = {scoreTime}, userId = {userId})"

user_put_args = reqparse.RequestParser()
user_put_args.add_argument("userName", type=str, help="Nom de l'utilisateur", required=True)
user_put_args.add_argument("userPsw", type=str, help="Mot de passe", required=True)
user_put_args.add_argument("userAdmin", type=bool, help="Administrateur", required=False)
user_put_args.add_argument("userPublicId", type=str, help="ID public", required=False)
user_put_args.add_argument("userId", type=int, help="Id de l'utilisateur", required=False)

user_update_args = reqparse.RequestParser()
user_update_args.add_argument("userName", type=str, help="User Name is required")
user_update_args.add_argument("userPsw", type=str, help="Views of the video")
user_update_args.add_argument("userId", type=int, help="Id de l'utilisateur",required=True)

score_put_args = reqparse.RequestParser()
score_put_args.add_argument("scoreValue", type=int, help="Valeur du score", required=True)
score_put_args.add_argument("scoreTime", type=int, help="Temps de la partie", required=True)
score_put_args.add_argument("scoreId", type=int, help="Id score", required=False)
score_put_args.add_argument("userId", type=int, help="Id de l'utilisateur", required=True)

user_resource_fields = {
	'userId': fields.Integer,
	'userName': fields.String,
	'userPsw': fields.String,
	'public_id': fields.String,
	'admin': fields.Boolean,
	'token' : fields.String
}
score_resource_fields = {
	'scoreId': fields.Integer,
	'scoreValue': fields.Integer,
	'scoreTime': fields.Integer,
	'userId': fields.Integer
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
			token = jwt.encode({'userPublicId': user.userPublicId, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY']) 
			print("Le contenu de token est : ",token, " et il est de type : ",type(token))
			#return jsonify({'token' : token.decode('UTF-8')})
			return make_response(jsonify({'token' : token.decode('UTF-8')}),  201)
		return make_response('could not verify',  401, {'WWW.Authentication': 'Basic realm: "login required"'})


class RegisterUser(Resource):
	@marshal_with(user_resource_fields)
	def put(self):
		args = user_put_args.parse_args()
		result = UserModel.query.filter_by(userName=args['userName']).first()
		if result:
			abort(409, message="User taken...")
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

		db.session.commit()
		print("OK")
		return result
  
class Score(Resource):
	@marshal_with(score_resource_fields)
	def get(self):
		result = ScoreModel.query.all()
		if not result:
			abort(404, message="Impossible d'afficher le score !")
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

api.add_resource(LoginUser, "/login")
api.add_resource(RegisterUser, "/register")
api.add_resource(Score, "/score")

@app.route('/')
def index():
	return render_template('index.html')

if __name__ == "__main__":
	app.run(host='0.0.0.0')
	#app.run(debug=True)