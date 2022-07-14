from rest_framework import serializers, validators

from .models import TestModel, Fish
from django.contrib.auth.models import Group, User, Permission
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.hashers import make_password
from rest_framework.authtoken.models import Token


class UserRegistrationSerializer(serializers.ModelSerializer):

    def create(self, validated_data):
        user = User.objects.create(
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            password=make_password(validated_data['password']),
            username=validated_data['username']
        )

        # user.set_password(validated_data['password'])
        user.save()
        return user

    class Meta:
        model = User
        fields = ['id','first_name','last_name','password','email','username']
        extra_kwargs = {
            'first_name': {
                'required' : True
            },
            'last_name': {
                'required': True
            },
            'email': {
                'required': True
            },
            'password': {
                'write_only': True
            }
        }
    
class UserLoginSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['username','password']

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'username', 'email', 'groups', 'is_superuser']
        extra_kwargs = {
            'is_superuser': {
                'read_only': True
            }
        }

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'username', 'email', 'password']
        extra_kwargs = {
            'username' : {
                'read_only': True,
                'required': True
            },
            'email': {
                'read_only': True
            },
            'password': {
                'write_only': True,
                'required': True,
            },
            'first_name': {
                'required': True
            },
            'last_name': {
                'required': True,
            },
        }

class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ['id', 'name', 'permissions']

class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'name', 'codename', 'content_type_id']

class PermissionUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'name', 'codename', 'content_type_id']
        extra_kwargs = {
            'codename' : {
                'read_only' : True
            }
        }

class TestModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = TestModel
        fields = ['id', 'test_string', 'created_at', 'updated_at']


class FishAddSerializer(serializers.ModelSerializer):
    fishname = serializers.CharField(max_length=20,required=True)
    price = serializers.IntegerField(default=0,required=False)
    fishfamily = serializers.CharField(max_length=200,required=True)
    image = serializers.ImageField(required=False)
    def create(self, validated_data):
        return Fish.objects.create(**validated_data)

        # user.set_password(validated_data['password'])
        #fish.save()
        #return fish
    class Meta:
        model = Fish
        fields = ['id', 'fishname', 'price', 'image','fishfamily']




class FishSerializer(serializers.ModelSerializer):
    class Meta:
        model = Fish
        fields = ['id', 'fishname', 'price', 'image','fishfamily']


class FishUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Fish
        fields = ['id', 'fishname', 'price', 'image','fishfamily']
