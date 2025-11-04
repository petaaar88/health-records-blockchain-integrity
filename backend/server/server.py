import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
import uuid
import json
import datetime
from datetime import timezone
from flask import Flask, request, jsonify
from pymongo import MongoClient
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity,decode_token
from werkzeug.security import check_password_hash, generate_password_hash
from flask_cors import CORS
from dotenv import load_dotenv

from entities.patient import Patient
from entities.health_authority import HealthAuthority
from blockchain.backend.core.transaction import Transaction
from blockchain.backend.core.transaction_body import TransactionBody
from blockchain.backend.util import util
from entities.doctor import Doctor
from util.util import generate_secret_key_b64, convert_secret_key_to_bytes, encrypt, decrypt, send_to_blockchain_per_request, serialize_doc

load_dotenv()

app = Flask(__name__)
CORS(app)

app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)  # Token ističe za 1 sat
jwt = JWTManager(app)


client = MongoClient(os.getenv("DB"))
db = client[os.getenv("DB_NAME")]  # baza

@app.route('/api/auth/verify', methods=['POST'])
def verify_token():
    
    try:
        
        auth_header = request.headers.get('Authorization')
        token = None
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        else:
            
            data = request.get_json()
            if data and 'token' in data:
                token = data['token']
        
        if not token:
            return jsonify({
                'valid': False,
                'message': 'Token nije pronađen'
            }), 400
        
        
        try:
           
            decoded_token = decode_token(token)
            
            
            exp_timestamp = decoded_token.get('exp')
            current_timestamp = datetime.datetime.now(timezone.utc).timestamp()
            
            if exp_timestamp and current_timestamp > exp_timestamp:
                return jsonify({
                    'valid': False,
                    'message': 'Token je istekao'
                }), 401
            
           
            return jsonify({
                'valid': True,
                'message': 'Token is valid',
                'user_id': decoded_token.get('sub'),  # 'sub' je standard za user_id u JWT
                'user_data': decoded_token,
                'expires_at': datetime.datetime.fromtimestamp(exp_timestamp).isoformat() if exp_timestamp else None
            }), 200
            
        except Exception as e:
            
            return jsonify({
                'valid': False,
                'message': 'Token is invalid!'
            }), 401
            
    except Exception as e:
        return jsonify({
            'valid': False,
            'message': f'Error while token verification: {str(e)}'
        }), 500
    

def get_current_user():
   
    from flask_jwt_extended import get_jwt_identity
    
    user_id = get_jwt_identity()
    
    
    collections = {
        'patients': db['patients'],
        'health_authorities': db['health_authorities'], 
        'doctors': db['doctors'],
        'central_authority': db['central_authority']
    }
    
   
    for collection_name, collection in collections.items():
        user = collection.find_one({'_id': user_id})
        if user:
            return user, collection_name
    
    return None, None

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'message': 'Token expired'}), 401


@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'message': 'Invalid token!'}), 401


@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'message': 'Token required to access!'}), 401



def require_user_type(*allowed_types):
   
    def decorator(f):
        from functools import wraps
        
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            try:
                from flask_jwt_extended import get_jwt
                claims = get_jwt()
                user_type = claims.get('user_type', '')
                
                if user_type not in allowed_types:
                    return jsonify({'message': 'Access denied for this user type'}), 403
                    
            except:
                return jsonify({'message': 'Invalid token'}), 401
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/api/login', methods=['POST'])
def login():
    user_id = request.json.get('id', None)
    password = request.json.get('password', None)
    
    if not user_id or not password:
        return jsonify({'message': 'ID and password are required!'}), 400
    
    collections = {
        'patients': db['patients'],
        'health_authorities': db['health_authorities'], 
        'doctors': db['doctors'],
        'central_authority': db['central_authority']
    }
    
    user = None
    user_type = None

    
    for collection_name, collection in collections.items():
        user = collection.find_one({'_id': user_id})
        if user:
            user_type = collection_name
            break
    
    if not user:
        return jsonify({'message': 'User not found!'}), 401
    
    if not check_password_hash(user.get('password', ''), password):
        return jsonify({'message': 'Invalid credentials!'}), 401
    
    additional_claims = {
        'user_type': user_type
    }
    
    access_token = create_access_token(
        identity=str(user_id),
        additional_claims=additional_claims
    )
    
    return jsonify({
        'access_token': access_token,
        'message': 'Login successful'
    })

@app.route("/api/patients", methods=["POST"])
@require_user_type('central_authority')
def add_patient():
    collection = db["patients"]   

    try:
        data = request.json
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        required_fields = ["first_name", "last_name", "personal_id", "date_of_birth", 
                          "gender", "address", "phone", "citizenship","password"]
        
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400

        if collection.find_one({"personal_id": data["personal_id"]}):
            return jsonify({"error": "Patient with this personal_id already exists!"}), 400

        new_patient = Patient(
            first_name=data["first_name"],
            last_name=data["last_name"],
            personal_id=data["personal_id"],
            date_of_birth=data["date_of_birth"],
            gender=data["gender"],
            address=data["address"],
            phone=data["phone"],
            citizenship=data["citizenship"],
            password=generate_password_hash(data["password"])
        )


       
        new_account = {
            "public_key": new_patient.public_key,
            "private_key": new_patient.private_key
        }

        message = {
            "type": "CLIENT_ADD_ACCOUNT",
            "data": new_account
        }

        blockchain_success, blockchain_response = send_to_blockchain_per_request(message)
        
        response_data = {}
        
        response =  blockchain_response

        if blockchain_success:
            response_data["blockchain_response"] = response["message"]
            result = collection.insert_one(new_patient.to_dict())

            if result.inserted_id:
                response_data["message"] = "Patient successfully added"
                response_data["id"] = result.inserted_id
            else:
                return jsonify({"error": "Failed to insert patient!"}), 500
        else:
            response_data["blockchain_error"] = response
            return jsonify(response_data), 500
        
        return jsonify(response_data), 201
       

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route("/api/health-authority", methods=["POST"])
@require_user_type('central_authority')
def add_health_authority():
    collection = db["health_authorities"]
    data = request.json
    
    if not data:
        return jsonify({"error": "No data provided"}), 400
        
    required_fields = ["name", "type", "address", "phone", "password"]
        
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    try:
        
       
        new_health_authority = HealthAuthority(
            name=data.get("name"),
            type=data.get("type"),
            address=data.get("address"),
            phone=data.get("phone"),
            password=generate_password_hash(data["password"])
        )

       
        new_account = {
            "public_key": new_health_authority.public_key,
            "private_key": new_health_authority.private_key
        }

        message = {
            "type": "CLIENT_ADD_ACCOUNT",
            "data": new_account
        }

        blockchain_success, blockchain_response = send_to_blockchain_per_request(message)
        
        response_data = {}
        
        response =  blockchain_response
        if blockchain_success:
            response_data["blockchain_response"] = response["message"]
            result = collection.insert_one(new_health_authority.to_dict())

            if result.inserted_id:
                response_data["message"] = "Health Authority successfully added"
                response_data["id"] = result.inserted_id
            else:
                return jsonify({"error": "Failed to insert health authority!"}), 500
        else:
            response_data["blockchain_error"] = response

            return jsonify(response_data), 500
        
        return jsonify(response_data), 201
      

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500


@app.route("/api/doctors", methods = ["POST"])
@require_user_type('health_authorities')
def add_doctor():
    user, user_type = get_current_user()

    collection = db["doctors"]
    data = request.json

    if not data:
            return jsonify({"error": "No data provided"}), 400
        
    required_fields = ["first_name", "last_name", "password"]
        
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    new_doctor = Doctor(
        first_name=data["first_name"],
        last_name=data["last_name"],
        health_authority_id = user["_id"],
        password=generate_password_hash(data["password"])
    )

    health_authorities_collection = db["health_authorities"]

    result = health_authorities_collection.update_one(
        {"_id": new_doctor.health_authority_id},
        {"$push": {"doctors": new_doctor._id}}
    )

    if result.matched_count == 0:
        return jsonify({"error": "HealthAuthority with this ID not found!"}), 404


    collection.insert_one(new_doctor.to_dict())

    return jsonify({"message": "Doctor successfully added", "id": new_doctor._id}), 201


@app.route("/api/health-records", methods=["POST"])
@require_user_type('doctors')
def add_health_record():
    health_records_collection = db["health_records"]
    patients_collection = db["patients"]
    health_authorities_collection = db["health_authorities"]

    data = request.json

    if not data:
        return jsonify({"error": "No data provided"}), 400

    new_id = uuid.uuid4().hex
    data["_id"] = new_id

    secret_key = generate_secret_key_b64()

    user, user_type = get_current_user()

    data["date"] = datetime.datetime.now().strftime("%d-%m-%Y")
    data["doctor_id"] = user["_id"]
    data["doctor_first_name"] = user["first_name"]
    data["doctor_last_name"] = user["last_name"] 
    data["health_authority_id"] = user["health_authority_id"]
    data["health_authority_name"] = health_authorities_collection.find_one({"_id": user["health_authority_id"]})["name"]

    patient_dict = patients_collection.find_one({"_id": data["patient_id"]})
    if not patient_dict:
        return {"error": "Patient not found"}, 404

    patient_dict = patients_collection.find_one({"_id": data["patient_id"]})
    data["patient_first_name"] = patient_dict["first_name"]
    data["patient_last_name"] = patient_dict["last_name"]

    print(data)
    health_record_string_data = json.dumps(data)


    encrypted_data = encrypt(health_record_string_data, convert_secret_key_to_bytes(secret_key))

    health_record = {
        "_id": new_id,
        "health_authority_id": data["health_authority_id"],
        "data": encrypted_data,
        "key": secret_key,
        "patient_id": data["patient_id"]
    }

    
    patient_dict = patients_collection.find_one({"_id": data["patient_id"]})
    if not patient_dict:
        return {"error": "Patient not found"}, 404
    
    health_authority_dict = health_authorities_collection.find_one({"_id": data["health_authority_id"]})
    if not health_authority_dict:
        return {"error": "Health authority not found"}, 404

    patient = Patient.from_dict(patient_dict)
    health_authority = HealthAuthority.from_dict(health_authority_dict)

   
    transaction_body = TransactionBody(
        health_authority.public_key, 
        patient.public_key, 
        new_id,
        datetime.datetime.now().isoformat(),
        util.hash256(data)
    )
    transaction = Transaction(transaction_body)
    health_authority.sign(transaction)
    
    try:
        
        message = {
            "type": "CLIENT_ADD_TRANSACTION",
            "data": {
                "transaction": transaction.to_dict(),
                "data_for_validation": data
            }
        }

        blockchain_success, blockchain_response = send_to_blockchain_per_request(message)
        
        if blockchain_success:
            
            response_type = blockchain_response.get("type")
            
            if response_type == "TRANSACTION_RESULT":
                transaction_success = blockchain_response.get("success", False)
                blockchain_message = blockchain_response.get("message", "")
                transaction_id = blockchain_response.get("transaction_id")
                
                if transaction_success:
                   
                    result = health_records_collection.insert_one(health_record)
                    update_result = health_authorities_collection.update_one(
                        {
                            "_id": health_authority_dict["_id"],
                            "patients": {"$ne": data["patient_id"]}
                        },
                        {"$push": {"patients": data["patient_id"]}}
                    )

                    return jsonify({
                        "message": "Health record successfully added and confirmed on blockchain",
                        "id": new_id,
                        "transaction_id": transaction_id,
                        "blockchain_status": blockchain_message,
                        "database_id": str(result.inserted_id)
                    }), 201
                    
                else:
                  
                    return jsonify({
                        "error": "Transaction rejected by blockchain network",
                        "blockchain_message": blockchain_message,
                        "transaction_id": transaction_id
                    }), 400
            else:
                
                return jsonify({
                    "error": "Unexpected blockchain response",
                    "response": blockchain_response
                }), 500
        else:
            
            return jsonify({
                "error": "Failed to communicate with blockchain",
                "blockchain_error": blockchain_response.get("error", "Unknown error")
            }), 500

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route("/api/health-records/decrypt/<string:hr_id>", methods=["POST"])
@require_user_type("doctors")
def decrypt_health_record(hr_id):
    
    health_records_collection = db["health_records"]
    health_record_dict = health_records_collection.find_one({"_id": hr_id})


    if not health_record_dict:
        return {"error": "Health record not found"}, 404
    
    user, user_type = get_current_user()


    data = request.json

    if data is None:
        return jsonify({"message":"Secret key not provided!"}), 400
    
    if "secret_key" not in data:
        return jsonify({"message":"Secret key not provided!"}), 400

    if health_record_dict["key"] != data["secret_key"]:
        return jsonify({"message":"Secret key invalid!"}), 400
    
    decrypted_health_record = json.loads(decrypt(health_record_dict["data"],convert_secret_key_to_bytes(health_record_dict["key"])))

    health_record_with_key = {
        "health_record": decrypted_health_record,
        "key": data["secret_key"]
    }

    request_collection = db["requests_for_health_records"]

    request_collection.delete_one({"key":data["secret_key"],"health_record_id":hr_id})

    return jsonify(health_record_with_key), 200


@app.route("/api/health-records/verify/<string:hr_id>", methods=["POST"])
@jwt_required()
def verify_health_record(hr_id):
    health_records_collection = db["health_records"]
    data = request.json

    health_record_dict = health_records_collection.find_one({"_id": hr_id})

    if not health_record_dict:
        return {"error": "Health record not found"}, 404
      
    if health_record_dict["key"] != data["secret_key"]:
        return {"error": "Key is invalid!"}, 403

    try:

        health_record_for_verification = json.loads(decrypt(health_record_dict["data"],convert_secret_key_to_bytes(health_record_dict["key"])))
        message = {
                "type": "CLIENT_VERIFY_TRANSACTION",
                "data": {
                    "health_record_id":hr_id,
                    "health_record" : health_record_for_verification
                }
        }

        blockchain_success, blockchain_response = send_to_blockchain_per_request(message)
        response_data = {}
        response =  blockchain_response

        if blockchain_success:
            response_data["blockchain_response"] = response["message"]
        else:
            response_data["blockchain_error"] = response
            return jsonify(response_data), 500
                
        return jsonify(response_data), 200
       

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route("/api/health-records", methods=["GET"])
@require_user_type("patients")
def get_health_records_by_patient():

    health_records_collection = db['health_records']
    health_records = []
    filter = {}

    user, user_type = get_current_user()

    filter = {'patient_id': user["_id"]}

    health_records_raw = list(health_records_collection.find(filter))

    health_records = []

    for health_record_raw in health_records_raw:
        decrypted_health_record = json.loads(decrypt(health_record_raw["data"], convert_secret_key_to_bytes(health_record_raw["key"])))
        
        health_record_with_key = {
            "health_record": decrypted_health_record,
            "key": health_record_raw["key"]
        }
        
        health_records.append(health_record_with_key)

    return jsonify({"health_records": health_records}), 201

@app.route("/api/health-records/secret_key/<string:hr_id>", methods=["GET"])
@require_user_type("patients")
def get_secret_key(hr_id):
    user, user_type = get_current_user()
    hr_collection = db["health_records"]
    
    hr = hr_collection.find_one({"patient_id":user["_id"],"_id":hr_id})

    if not hr:
        return jsonify({"message":"Health record not found!"})

    return jsonify({"secret_key":hr["key"]}), 200



@app.route("/api/health-records/patient/<string:patient_personal_id>", methods=["GET"])
@require_user_type('doctors')
def get_health_records_of_patient(patient_personal_id):

    patients_collection = db["patients"] 

    patient = patients_collection.find_one({"personal_id":patient_personal_id}) 

    if patient is None:
        return jsonify({"message":"Patinet not found!"}), 400


    health_records_collection =  db['health_records']
    user, user_type  = get_current_user()

    own = request.args.get('own')

    if own == "true":
        
        health_records = []
        
        filter = {'health_authority_id': user["health_authority_id"]}
        
        health_records_raw = list(health_records_collection.find(filter))

        health_records = []

        for health_record_raw in health_records_raw:
            decrypted_health_record = json.loads(decrypt(health_record_raw["data"],convert_secret_key_to_bytes(health_record_raw["key"])))
            health_record_with_key = {
                "health_record": decrypted_health_record,
                "key": health_record_raw["key"]
            }
            health_records.append(health_record_with_key)

        return jsonify({"health_records":health_records}), 201
    
    patient_public_key = patient["public_key"]
    
    try:

        message = {
                    "type": "CLIENT_GET_ALL_TRANSACTIONS_OF_PATIENT",
                    "data": patient_public_key
        }

        blockchain_success, blockchain_response = send_to_blockchain_per_request(message)
        response_data = {}
            
        response =  blockchain_response
        
        if blockchain_success:
            health_authority_collection = db["health_authorities"]
            health_authority = health_authority_collection.find_one({"_id":user["health_authority_id"]})

            health_records_created_by_different_ha  = [hr for hr in response["message"] if hr["creator"] != health_authority["public_key"]]

            requests_collection = db["requests_for_health_records"]

            for health_record in health_records_created_by_different_ha:
                ha = health_authority_collection.find_one({"public_key":health_record["creator"]})
                health_record["health_authority_id"] = ha["_id"]
                health_record["health_authority_name"] = ha["name"]

                health_record["added_at_blockchain"] = health_record["date"]
                health_record["patient_id"] = patients_collection.find_one({"public_key":health_record["patient"]})["_id"]

                request_result =requests_collection.find_one({"health_record_id":health_record["health_record_id"],"health_authority_id":user["health_authority_id"]})

                if request_result:
                    if "key" in request_result:
                        health_record["key"] = request_result["key"]

                del health_record["patient"]
                del health_record["creator"]
                del health_record["date"]


            response_data["blockchain_response"] = health_records_created_by_different_ha

            
        else:
            response_data["blockchain_error"] = response
         
        return jsonify(response_data), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

@app.route("/api/requests", methods=["POST"])
@require_user_type("doctors")
def add_request():
    data = request.json
    user, user_type = get_current_user()
    patients_collection = db["patients"]
    health_records_collection = db["health_records"]
    request_collection = db["requests_for_health_records"]

    if patients_collection.find_one({"_id":data["patient_id"]}) is None:
        return jsonify({"message":"Patient not found!"}), 201
    
    if health_records_collection.find_one({"_id":data["health_record_id"]}) is None:
        return jsonify({"message":"Health record not found!"}), 201
    
    if request_collection.find_one({"patient_id":data["patient_id"],"health_record_id":data["health_record_id"]}) is not None:
        return jsonify({"error": "Request aleady exists!"}), 400

    requests_for_health_records_collection = db["requests_for_health_records"]
    data["health_authority_id"] = user["health_authority_id"]
    data["_id"] = uuid.uuid4().hex
    result = requests_for_health_records_collection.insert_one(data)
    

    if result.inserted_id:
        return jsonify(data), 201
    else:    
        return jsonify({"error": "Failed to insert patient!"}), 500


@app.route("/api/requests/patient", methods=["GET"])
@require_user_type("patients")
def get_patient_requests_by_patient():
    user, user_type = get_current_user()
    requests_collection = db["requests_for_health_records"]
    ha_collection = db["health_authorities"]
    cursor = requests_collection.find({"patient_id":user["_id"]})

    requests = []
    for request in cursor:
        if "key" not in request:
            ha = ha_collection.find_one({'_id':request["health_authority_id"]})
            request["health_authority_name"] = ha["name"]
            requests.append(request)

    return jsonify(requests), 200

@app.route("/api/requests/doctors", methods=["GET"])
@require_user_type("doctors")
def get_patient_requests_by_doctors():
    user, user_type = get_current_user()
    requests_collection = db["requests_for_health_records"]

    cursor = requests_collection.find({"health_authority_id":user["health_authority_id"]})

    requests = []
    for request in cursor:
        requests.append(request)

    return jsonify(requests), 200

@app.route("/api/requests/<string:request_id>", methods=["DELETE"])
@require_user_type("patients","doctors")
def delete_request(request_id):
    user, user_type = get_current_user()
    requests_collection = db["requests_for_health_records"]

    try:
        
        result = requests_collection.delete_one({"_id": request_id})
        
        if result.deleted_count == 1:
            return jsonify({"message": "Request not found!"}), 200
        else:
            return jsonify({"error": "Request not found!"}), 404
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/requests/<string:request_id>", methods=["PATCH"])
@require_user_type("patients")
def accept_request(request_id):

    data = request.json
    print(data)
    if data is None:
        return jsonify({"error": "Secret key not provided!"}), 400

    user, user_type = get_current_user()
    requests_collection = db["requests_for_health_records"]

    try:
        if requests_collection.find_one({"patient_id":user["_id"],"_id":request_id}) is None:
            return jsonify({"error": "Dont have access!"}), 400
        
        result = requests_collection.update_one(
            {"_id": request_id},          
            {"$set": {"key": data["secret_key"]}}  
        )
        
        if result.modified_count > 0:
            return jsonify({"message": "Request accepted!"}), 200
        else:
            return jsonify({"error": "Request not found!"}), 404
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/doctors/<string:doctor_id>", methods = ["GET"])
@jwt_required()
def get_doctor(doctor_id):
    doctors_collection = db["doctors"]
    health_authority_collection = db["health_authorities"]

    doctor = doctors_collection.find_one({"_id":doctor_id})
    if doctor is None:
        return jsonify({"message":"Doctor not found!"}), 400
    
    del doctor["password"]

    ha = health_authority_collection.find_one({"_id": doctor["health_authority_id"]})
    doctor["health_authority_name"] = ha["name"]

    return jsonify(doctor), 200

@app.route("/api/health_authority/<string:ha_id>", methods = ["GET"])
@jwt_required()
def get_health_authority(ha_id):
    ha_collection = db["health_authorities"]

    ha = ha_collection.find_one({"_id":ha_id})
    if ha is None:
        return jsonify({"message":"Health authority not found!"}), 400
    
    del ha["password"]
    del ha["public_key"]
    del ha["private_key"]
    del ha["doctors"]
    del ha["patients"]

    return jsonify(ha), 200

@app.route("/api/patients/<string:patient_id>", methods = ["GET"])
@jwt_required()
def get_patient(patient_id):
    patient_collection = db["patients"]

    patinet = patient_collection.find_one({"_id":patient_id})
    if patinet is None:
        return jsonify({"message":"Patinet not found!"}), 400
    
    del patinet["password"]
    del patinet["public_key"]
    del patinet["private_key"]
    del patinet["health_records"]
    
    return jsonify(patinet), 200

@app.route("/api/patients/personal_id/<string:personal_id>", methods = ["GET"])
@jwt_required()
def get_patient_by_personal_id(personal_id):
    patient_collection = db["patients"]

    patinet = patient_collection.find_one({"personal_id":personal_id})
    if patinet is None:
        return jsonify({"message":"Patinet not found!"}), 400
    
    del patinet["password"]
    del patinet["public_key"]
    del patinet["private_key"]
    del patinet["health_records"]
    
    return jsonify(patinet), 200

@app.route("/api/central-authority/<string:ca_id>", methods = ["GET"])
@jwt_required()
def get_central_authority(ca_id):
    ca_collection = db["central_authority"]

    ca = ca_collection.find_one({"_id":ca_id})
    if ca is None:
        return jsonify({"message":"Central authority not found!"}), 400
    
    del ca["password"]
    return jsonify(ca), 200

if __name__ == "__main__":
    app.run(debug=True)