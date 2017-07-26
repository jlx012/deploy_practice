# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
import bcrypt

class UserManager(models.Manager):
    def validateRegistration(self, form_data):
        errors = []

        if len(form_data['first_name']) == 0:
            errors.append('First Name is required.')
        if len(form_data['last_name']) == 0:
            errors.append('Last Name is required.')
        if len(form_data['email']) == 0:
            errors.append('Email is required.')
        if len(form_data['password']) == 0:
            errors.append('Password is required.')
        if len(form_data['password']) != len(form_data['password_confirmation']):
            errors.append('Password confirmation must match password.')

        return errors

    def validateLogin(self, form_data):
        errors = []

        if len(form_data['email']) == 0:
            errors.append('Email is required.')
        if len(form_data['password']) == 0:
            errors.append('Password is required.')

        return errors

    def createUser(self, form_data):
        password = str(form_data['password'])
        hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt())

        user = User.objects.create(
            first_name = form_data['first_name'],
            last_name = form_data['last_name'],
            email = form_data['email'],
            password = hashed_pw,
        )
        return user

class User(models.Model):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.EmailField()
    password = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        output = 'first_name: {} last_name: {} email: {} password: {}'

        return output.format(
            self.first_name,
            self.last_name,
            self.email,
            self.password,
        )

    objects = UserManager()
