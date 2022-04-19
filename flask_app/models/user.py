from flask_app.config.mysqlconnection import connectToMySQL
from flask import flash
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') 
class User:
    def __init__( self , data ):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']
    
    @classmethod
    def create(cls , data):
        query = "INSERT INTO users (first_name , last_name , email , password, created_at, updated_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s, NOW(), NOW())"
        return connectToMySQL('user_schema').query_db(query, data)

    @staticmethod
    def validate_user(user):
        is_valid = True
        if len(user['first_name']) < 2:
            flash("First Name must be at least two characters", "register")
            is_valid = False
        if len(user['last_name']) < 2:
            flash("Last Name must be at least two characters", "register")
            is_valid = False
        if not EMAIL_REGEX.match(user['email']):
            flash("Invalid email address", "register")
            is_valid = False
        if len(user['password']) < 8:
            flash("Password must be at least 8 characters", "register")
            is_valid = False
        if user['passwordc'] != user['password']:
            flash("Password confirmation must match password", "register")
            is_valid = False
        return is_valid

    @classmethod
    def get_by_email(cls,data):
        query = "SELECT * FROM users WHERE email = %(email)s;"
        result = connectToMySQL("user_schema").query_db(query,data)
        if len(result) < 1:
            return False
        return cls(result[0])

    @classmethod
    def get_user_by_id(cls,data):
        query = "SELECT * FROM users WHERE id = %(user_id)s"
        result = connectToMySQL("user_schema").query_db(query,data)
        user = cls(result[0])
        return user
