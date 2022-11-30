from flask_app.config.mysqlconnection import connectToMySQL
import re
from flask import render_template, redirect, request, session, flash

NAME_REGEX = re.compile(r'^[a-zA-Z]+$') 
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') 

db_name = 'login_register'
class User:

    def __init__(self, data):
        self.id = data['id']
        self.name = data['first_name']
        self.lname = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']

    @classmethod
    def save(cls,data):
        query = "INSERT INTO users (first_name,last_name, email, password, created_at, updated_at) VALUES (%(name)s, %(lname)s, %(email)s, %(password)s, NOW(), NOW() );"
        return connectToMySQL(db_name).query_db(query, data)

    @classmethod
    def getAllMagazines(cls):
        query= 'select m.id, title, m.user_id, first_name, last_name from magazines m join users u on m.user_id = u.id;'
        results =  connectToMySQL(db_name).query_db(query)
        magazines= []
        for row in results:
            magazines.append(row)
        # print(magazines)
        return magazines

    @classmethod
    def getAllSubscribedMagazines(cls, data):
        query= 'select m.id, title, m.user_id, first_name, last_name from magazines m join users u on m.user_id = u.id where m.user_id = %(id)s;'
        results =  connectToMySQL(db_name).query_db(query, data)
        magazines= []
        for row in results:
            magazines.append(row)
        return magazines

    @classmethod
    def get_by_email(cls,data):
        query = "SELECT * FROM users WHERE email = %(email)s;"
        result = connectToMySQL(db_name).query_db(query,data)
        print(result)
        # Didn't find a matching user
        if len(result) < 1:
            return False
        return cls(result[0])
    
    @classmethod
    def get_user_by_id(cls, data):
        query= 'SELECT * FROM users WHERE users.id = %(user_id)s;'
        results = connectToMySQL(db_name).query_db(query, data)
        return results[0]

    @classmethod
    def get_selectedUser(cls, data):
        query = "SELECT * FROM users WHERE id = %(id)s;"
        result = connectToMySQL(db_name).query_db(query, data)
        return cls(result[0])
    
    @classmethod
    def update(cls, data):
        query = "UPDATE users SET first_name=%(name)s,last_name=%(lname)s,email=%(email)s,updated_at=NOW() WHERE id = %(id)s;"
        return connectToMySQL(db_name).query_db( query, data )
    
    @classmethod
    def get_oneUser(cls, data):
        query = "select * from users order by updated_at desc limit 1;"
        result = connectToMySQL(db_name).query_db(query, data)
        return cls(result[0])

    @classmethod
    def favorited_users(cls,data):
        query = "E magazine_id = %(id)s );"
        users = []
        results = connectToMySQL(db_name).query_db(query,data)
        for row in results:
            users.append(cls(row))
        return users

    @classmethod
    def get_logged_user_liked_magazines(cls, data):
        query = 'SELECT magazine_id as id FROM favorites LEFT JOIN users on favorites.user_id = users.id WHERE user_id = %(user_id)s;'
        results = connectToMySQL(db_name).query_db(query, data)
        postsFavorited = []
        for row in results:
            postsFavorited.append(row['id'])
        print(postsFavorited)
        return postsFavorited

    @classmethod
    def getAllSubscribers(cls, data):
        query= 'SELECT count(*), title FROM magazines JOIN favorites ON magazines.id = favorites.magazine_id LEFT JOIN users ON users.id = favorites.user_id  group by magazine_id ;'
        results =  connectToMySQL(db_name).query_db(query, data)
        subscribers= []
        for row in results:
            subscribers.append(row)
        # print(subscribers)
        return subscribers

    @staticmethod
    def is_valid(user):
        is_valid = True
        if not NAME_REGEX.match(user['name']):
            flash("Name should have only letters!", "fnameletter")
            is_valid = False
        if len(user['name']) < 2:
            flash("Name should be at least 2 characters!", "fnamechar")
            is_valid = False
        is_valid = True
        if not NAME_REGEX.match(user['lname']):
            flash("Last name should be at least 2 characters and should have only letters!", "lnameletter")
            is_valid = False
        if len(user['lname']) < 2:
            flash("Last name should be at least 2 characters and should have only letters!", "lnamechar")
            is_valid = False
        if not EMAIL_REGEX.match(user['email']): 
            flash("Invalid email address!", "email")
            is_valid = False
        query = "select count(email) from users where email = %(email)s;"
        result = connectToMySQL(db_name).query_db(query, user)
        if result[0]['count(email)'] >= 1:
            flash("This email address already exists!", "emailExists")
            is_valid = False
        if len(user['password']) < 8:
            flash("Password should be at least 8 characters!", "password")
            is_valid = False
        if user['confirmPassword'] != user['password']:
            flash("Passwords don't match!", "passwordConfirm")
            is_valid = False
        
        if is_valid == True:
            flash("Success, user created!You can now login!", "userCreated")
        
        return is_valid


    @staticmethod
    def is_valid_update(user):
        is_valid = True
        if not NAME_REGEX.match(user['name']):
            flash("Name should have only letters!", "fnameletter")
            is_valid = False
        if len(user['name']) < 3:
            flash("Name should be at least 3 characters!", "fnamechar")
            is_valid = False
        is_valid = True
        if not NAME_REGEX.match(user['lname']):
            flash("Last name should be at least 3 characters and should have only letters!", "lnameletter")
            is_valid = False
        if len(user['lname']) < 3:
            flash("Last name should be at least 3 characters and should have only letters!", "lnamechar")
            is_valid = False
        if not EMAIL_REGEX.match(user['email']): 
            flash("Invalid email address!", "email")
            is_valid = False
        if is_valid == True:
            flash("Success, user updated!", "userUpdated")
        return is_valid