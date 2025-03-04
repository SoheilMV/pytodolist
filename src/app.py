from flask import *
from flask_restful import *
from wtforms import *
from pymongo import *
from bson import ObjectId
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity,JWTManager,get_jwt


########################################### Database ###########################################
client = MongoClient(host="localhost", port=27017)
db = client["NitroTodoList"]
usersCollection = db["users"]
tasksCollection = db["tasks"]
roleCollection = db["role"]


def initData():
    if len(list(roleCollection.find())) == 0 :
        roles = [
            {"name":"admin"},
            {"name":"user"}
        ]
        roleCollection.insert_many(roles)
        # adminRoleId = roleCollection.find_one({"name":"admin"})["_id"]
        adminUser = {
            "name":"Mohammad",
            "family":"Alaee",
            "number":"09036343063",
            "password":"123456",
            "roleName":"admin"
        }
        usersCollection.insert_one(adminUser)
        
def isAdminOrNot(claims):
    if claims["role"] == "admin":
        return True
    else:
        return False
    
def isAdminOrSameUser(claims,identity, userId):
    if claims["role"] == "admin" or identity == str(userId):
        return True
    else :
        return False

########################################### Validators ###########################################
class UserValidator(Form):
    name = StringField("name", validators=[validators.DataRequired(), validators.length(min=1)])
    family = StringField("family", validators=[validators.DataRequired(), validators.length(min=1)])
    number = StringField("number", validators=[validators.DataRequired(), validators.length(min=11, max=11)])
    password = StringField("password", validators=[validators.DataRequired(), validators.length(min=6, max=32)])

class TaskValidator(Form):
    title = StringField("title", validators=[validators.DataRequired(), validators.length(min=1, max=50)])
    description = StringField("description", validators=[validators.DataRequired(), validators.length(min=1)])
    priority = StringField("priority", validators=[validators.DataRequired()])
    status = StringField("status", validators=[validators.Optional()])

########################################### Resources ###########################################
class User(Resource):
    def post(self, id=None):
        userValidtor = UserValidator(request.form)
        if userValidtor.validate():
            userData = request.form.to_dict()
            userData["roleName"] = "user"
            print(userData)
            usersCollection.insert_one(userData)
            return {"job": "ok", "message": "User created successfuly!"}, 200
        else:
            return {"job": "error", "message": userValidtor.errors}
    
    @jwt_required()
    def get(self, id=None):
        if not isAdminOrNot(get_jwt()):
            return {"job":"error","message":"unauthorized access"}
            
        if id != None:
            user = usersCollection.find_one({"_id": ObjectId(id)})
            user["_id"] = str(user["_id"])
            return {"job": "ok", "user": user}, 200
        else:
            page = int(request.args.get("page"))
            limit = int(request.args.get("limit"))
            skip = (page - 1) * limit
            user = list(usersCollection.find().limit(limit).skip(skip))
            for u in user:
                u["_id"] = str(u["_id"])
            return {"job": "ok", "users": user}, 200
    @jwt_required()
    def put(self, id=None):
        if id is None:
            return {"job":"error","errorMessage":"id needed !"}
        else:
            if not isAdminOrSameUser(get_jwt(),get_jwt_identity(),id):
                return {"job":"error","message":"unauthorized access"}
        
            foundedUser = usersCollection.find_one({"_id":ObjectId(id)})
            if foundedUser is None : 
                return {"job":"error","errorMessage":"invalid id"}
            else:
                userValidtor = UserValidator(request.form)
                newUserData = request.form.to_dict()
                if userValidtor.validate():
                    usersCollection.update_one({"_id":ObjectId(id)},{"$set":newUserData})
                    return {"job":"ok","message":"User Updated"}
                else:
                    return {"job":"error","errorMessage":userValidtor.errors}
                
    @jwt_required()
    def delete(self, id=None):  
        if not id is None:
            if not isAdminOrSameUser(get_jwt(),get_jwt_identity(),id):
                return {"job":"error","message":"unauthorized access"}
            foundedUser = usersCollection.find_one({"_id": ObjectId(id)})
            if foundedUser is None:
                return {"job":"error","errorMessage":"invalid id"},404
            else:
                usersCollection.delete_one({"_id": ObjectId(id)})
                return {"job": "ok", "message": "User Deleted"}, 200
        else:
            return {"job":"error","errorMessage":"id needed"}

class Login(Resource):
    def post(self):
        insertedData = request.form.to_dict()
        foundedUser = usersCollection.find_one({"number":insertedData["number"]})
        if foundedUser is None:
            return {"job": "error", "message": "Invalid number or password!"}, 401
        else:
            if foundedUser["password"] == insertedData["password"]:
                accessToken = create_access_token(identity=str(foundedUser["_id"]),additional_claims={"role":foundedUser["roleName"]})
                return {"job":"ok","accessToken":accessToken}
            else:
                return {"job": "error", "message": "Invalid number or password!"}, 401
        

class Task(Resource):
    @jwt_required()
    def post(self, id=None):
        taskValidator = TaskValidator(request.form)
        if taskValidator.validate():
            taskData = request.form.to_dict()
            taskData["status"] = "Pending"
            taskData["ownerId"] = get_jwt_identity()
            tasksCollection.insert_one(taskData)
            return {"job":"ok", "message": "Task created successfuly!"}
        else:
            return {"job": "error", "messages": taskValidator.errors}
    
    @jwt_required()
    def get(self, id=None):
        if id != None:
            task = tasksCollection.find_one({"_id": ObjectId(id)})
            if task is None:
                return {"job": "error", "message": "Invalid id!"}, 404
            else:
                task["_id"] = str(task["_id"])
                if task["ownerId"] == get_jwt_identity() or isAdminOrNot(get_jwt()):
                    return {"job": "ok", "task": task}, 200
                else:
                    return {"job": "error", "message": "Invalid id!"}, 404
        else:
            
            page = request.args.get("page")
            limit = request.args.get("limit")
            if page is None or limit is None:
                return {"job": "error", "message": "Page and limit needed!"}, 400
            else:
                skip = (int(page) - 1) * int(limit)
                if isAdminOrNot(get_jwt()):
                    tasks = list(tasksCollection.find().limit(int(limit)).skip(skip))
                else:
                    tasks = list(tasksCollection.find({"ownerId": get_jwt_identity()}).limit(int(limit)).skip(skip))
                
                for t in tasks:
                    t["_id"] = str(t["_id"])
                return {"job": "ok", "tasks": tasks}
            
    
    @jwt_required()
    def put(self, id=None):
        if id is None:
            return {"job":"error","errorMessage":"id needed !"}
        else:
            foundedTask = tasksCollection.find_one({"_id":ObjectId(id)})
            if foundedTask is None :
                return {"job":"error","errorMessage":"invalid id"}
            else:
                taskValidator = TaskValidator(request.form)
                newTaskData = request.form.to_dict()
                if taskValidator.validate():
                    task = tasksCollection.find_one({"_id": ObjectId(id)})
                    if not task is None:
                        if task["ownerId"] == get_jwt_identity() or isAdminOrNot(get_jwt()):
                            tasksCollection.update_one({"_id":ObjectId(id)},{"$set":newTaskData})
                            return {"job":"ok","message":"Task Updated"}, 200
                        else:
                            return {"job":"error","errorMessage":"unauthorized access"}, 403
                    else:
                        return {"job":"error","errorMessage":"invalid id"}
                else:
                    return {"job":"error","errorMessage":taskValidator.errors}

    @jwt_required()
    def delete(self, id=None):
        if not id is None:
            foundedTask = tasksCollection.find_one({"_id": ObjectId(id)})
            if foundedTask is None:
                return {"job":"error","errorMessage":"invalid id"},404
            else:
                if foundedTask["ownerId"] == get_jwt_identity() or isAdminOrNot(get_jwt()):
                    tasksCollection.delete_one({"_id": ObjectId(id)})
                    return {"status": "ok", "message": "Task Deleted"}, 200
                else:
                    return {"job":"error","errorMessage":"unauthorized access"}, 403
        else:
            return {"job":"error","errorMessage":"id needed"}



########################################### Main ###########################################
def main():
    app = Flask(__name__)
    
    api = Api(app)
    api.add_resource(User, "/user/<string:id>", "/user")
    api.add_resource(Login, "/login")
    api.add_resource(Task, "/task/<string:id>", "/task")
    app.config["JWT_SECRET_KEY"] = "nitro4Flask"
    jwt = JWTManager(app)
    initData()
    app.run(debug=True)




if __name__ == "__main__":
    main()