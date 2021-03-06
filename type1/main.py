from flask import Flask,jsonify,request 
from flask_restful import Api, Resource, reqparse,abort, fields, marshal_with
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
api = Api(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:fitelec@localhost:5433/calculationGenerator'
app.debug = False
db = SQLAlchemy(app)

class cUser(db.Model):
    __tablename__ = "user"
    userId = db.Column(db.Integer(), primary_key=True,autoincrement=True)
    userName = db.Column(db.String(100), nullable=False)
    userPsw = db.Column(db.String(100),nullable = False)

    def __init__(self,userId, userName,userPsw):
        self.userId = userId
        self.userName = userName
        self.userPsw = userPsw

class cScore(db.Model):
    __tablename__ = "score"
    scoreId = db.Column(db.Integer(), primary_key=True)
    userId = db.Column(db.Integer(),nullable = False)
    scoreValue = db.Column(db.Integer(), nullable = False)
    scoreTime = db.Column(db.Integer(), nullable = False)

    def __init__(self,scoreId, userId,scoreValue,scoreTime):
        self.scoreId = scoreId
        self.userId = userId
        self.scoreValue = scoreValue
        self.scoreTime = scoreTime

db.drop_all()
db.create_all() #For first run

@app.route('/test',methods=['GET'])
def test():
    return {
        'test': 'test'
    }

@app.route('/user',methods=['GET'])
def getuser():
    allUsers = cUser.query.all()
    output = []
    for user in allUsers:
        currUser = {}
        currUser['userId'] = user.userId
        currUser['userName'] = user.userName
        currUser['userPsw'] = user.userPsw
        output.append(currUser)
    return jsonify(output)

@app.route('/user',methods=['POST'])
def postuser():
    userData = request.get_json()
    print("Contenu de userData : ", userData)
    #userId=userData['userId']
    user = cUser(userName=userData['userName'],userPsw = userData['userPsw'])
    db.session.add(user)
    db.session.commit()
    return jsonify(userData)

if __name__ == "__main__":
	app.run(host='0.0.0.0')
    #app.run(debug=True)