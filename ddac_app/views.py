from django import http
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.http import HttpResponse
from django.shortcuts import render, redirect
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication, TokenAuthentication

from django.db.utils import IntegrityError
from django.contrib.auth.models import Permission, User, Group
from django.contrib.contenttypes.models import ContentType
from .models import TestModel, Fish
from .serializers import GroupSerializer, PermissionSerializer, PermissionUpdateSerializer, TestModelSerializer, UserLoginSerializer, UserRegistrationSerializer, UserSerializer, UserUpdateSerializer,FishSerializer,FishAddSerializer,FishUpdateSerializer
# Create your views here.


@api_view(['GET'])
def api_index(request):
    return Response({'index':'/api/'})


"""Start of Permission Routes"""
@api_view(['GET'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def permission_detail(request, pk):
    if not request.user.has_perm('auth.view_permission'):
        return Response({'message':'You are not authorized for this action.'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        permission = Permission.objects.get(pk = pk)
    except Permission.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
    
    serialize = PermissionSerializer(permission, many=False)

    return Response(serialize.data, status=status.HTTP_200_OK)

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def permission_lists(request):
    if not request.user.has_perm('auth.view_permission'):
        return Response({'message' : 'You are not authorized for this action.'}, status=status.HTTP_401_UNAUTHORIZED)

    if request.method == 'GET':
        permissions = Permission.objects.all()
        serialized = PermissionSerializer(permissions, many=True)

        content = {
            'data' : serialized.data
        }

        return Response(content, status=status.HTTP_200_OK)

    if request.method == 'POST':
        try:

            selected_permissions = Permission.objects.filter(id__in=request.data['permissions'])

            permissions = PermissionSerializer(selected_permissions, many=True)

            return Response({'data':permissions.data}, status=status.HTTP_200_OK)
        except KeyError:
            return Response({'message':'error'}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def permission_create(request):
    if not request.user.has_perm('auth.add_permission'):
        return Response({'message': 'You are not authorized for this action.'}, status=status.HTTP_401_UNAUTHORIZED)


    permission = PermissionSerializer(data=request.data)

    if permission.is_valid():
        
        contentType, _ = ContentType.objects.get_or_create(app_label="ddac_app", model="modelless")

        try:
            s = Permission.objects.create(
                codename = permission.data['codename'],
                name = permission.data['name'],
                content_type = contentType
            )
        except IntegrityError:
            return Response({'message':'Permission Codename already exists.'}, status=status.HTTP_400_BAD_REQUEST)

        s = PermissionSerializer(s)

        content = {
            'message' : 'OK',
            'data': s.data
        }

        return Response(content, status=status.HTTP_201_CREATED)

    return Response(permission.error_messages, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def permission_edit(request, pk):
    if not request.user.has_perm('auth.change_permission'):
        return Response({'message' : 'You are not authorized for this action.'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        permission = Permission.objects.get(pk = pk)
    except Permission.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    serialize = PermissionUpdateSerializer(permission, data=request.data, many=False)

    if serialize.is_valid():
        serialize.save()

        return Response({'message': 'Updated Permission.'}, status=status.HTTP_200_OK)

    return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def permission_delete(request, pk):
    if not request.user.has_perm('auth.delete_permission'):
        return Response({'message':'You are not authorized for this action.'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        permission = Permission.objects.get(pk = pk)
    except Permission.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    permission.delete()
    return Response({'message':'Permission Deleted.'}, status=status.HTTP_200_OK)

"""End of Permission Routes"""

"""Start of User Routes"""
@api_view(['GET'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def user_group(request):
    
    content = {
        'username': request.user.username,
        'email': request.user.email,
        'group': None if request.user.groups.first() is None else request.user.groups.first().name,
        'is_admin': request.user.is_superuser
    }

    return Response(content, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def user_detail(request, pk):
    if not request.user.has_perm('auth.view_user'):
        return Response({'message': 'You are not authorized for this action.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        user = User.objects.get(pk=pk)
    except User.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
    
    serialize = UserSerializer(user, many=False)

    return Response(serialize.data, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def staff_create(request):
    if not request.user.has_perm('auth.add_user'):
        return Response({'message': 'You are not authorized for this action.'}, status=status.HTTP_401_UNAUTHORIZED)

    serialize = UserRegistrationSerializer(data=request.data)

    if serialize.is_valid():
        serialize.save()

        user = User.objects.get(pk=serialize.data['id'])
        group, _ = Group.objects.get_or_create(name="staff")

        user.groups.add(group)

        s = UserSerializer(user, many=False)

        return Response(s.data, status=status.HTTP_201_CREATED)

    return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def user_edit(request, pk):
    if not request.user.has_perm('auth.change_user'):
        return Response({'message': 'You are not authorized for this action.'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        user = User.objects.get(pk=pk)
    except User.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)
    
    serialize = UserSerializer(user, data=request.data)

    if serialize.is_valid():
        serialize.save()
        return Response({'message':'Successfully Updated Account.'}, status=status.HTTP_200_OK)

    return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def user_lists(request):
    if not request.user.has_perm('auth.view_user'):
        return Response({'message': 'You are not authorized for this action.'}, status=status.HTTP_401_UNAUTHORIZED)

    users = User.objects.all()
    serialize = UserSerializer(users, many=True)

    content = {
        "data": serialize.data
    }

    return Response(content, status=status.HTTP_200_OK)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def user_delete(request, pk):
    if not request.user.has_perm('auth.delete_user'):
        return Response({'message': 'You are not authorized for this action.'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        user = User.objects.get(pk=pk)
    except User.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    user.delete()

    return Response({'message':'User Deleted.'}, status=status.HTTP_200_OK)
"""End of User Routes"""

"""
Start of Group Routes
"""
@api_view(['GET'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def group_detail(request, pk):
    if not request.user.has_perm('auth.view_group'):
        return Response({'message':'You are not authorized for this action.'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        group = Group.objects.get(pk=pk)
    except Group.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    serialize = GroupSerializer(group, many=False)

    return Response(serialize.data, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def group_edit(request, pk):
    if not request.user.has_perm('auth.change_group'):
        return Response({'message':'You are not authorized for this action.'}, status=status.HTTP_401_UNAUTHORIZED)

    request.data['name'] = request.data['name'].lower()

    try:
        group = Group.objects.get(pk=pk)
    except Group.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    serialize = GroupSerializer(group, data=request.data)

    if serialize.is_valid():
        serialize.save()
        return Response(serialize.data, status=status.HTTP_200_OK)

    return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def group_lists(request):

    if not request.user.has_perm('auth.view_group'):
        return Response({'message':'You are not authorized for this action.'}, status=status.HTTP_401_UNAUTHORIZED)

    group_lists = Group.objects.all()
    serialized = GroupSerializer(group_lists, many=True)

    content = {
        'data' : serialized.data
    }

    return Response(content, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def group_create(request):
    if not request.user.has_perm('auth.create_group'):
        return Response({'message':'You are not authorized for this action.'}, status=status.HTTP_401_UNAUTHORIZED)

    try:

        request.data['name'] = request.data['name'].lower()

        serialize = GroupSerializer(data=request.data, many=False)
    except KeyError:
        request.data['permissions'] = []
        serialize = GroupSerializer(data=request.data, many=False)
    
    if serialize.is_valid():

        serialize.save()

        return Response(serialize.data, status=status.HTTP_201_CREATED)

    return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def group_delete(request, pk):
    if not request.user.has_perm('auth.delete_group'):
        return Response({'message':'You are not authorized for this action.'}, status=status.HTTP_401_UNAUTHORIZED)
    try:
        group = Group.objects.get(pk=pk)
    except Group.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    group.delete()
    return Response({'message':'Group Deleted.'}, status=status.HTTP_200_OK)
"""
End of Group Routes
"""

"""
Start of Profile Route
"""
@api_view(['GET'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def profile(request):
    try:
        user = Token.objects.get(key=request.auth.key).user
    except Token.DoesNotExist:
        return Response(status=status.HTTP_401_UNAUTHORIZED)

    serialized = UserSerializer(user, many=False)
    return Response(serialized.data, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def profile_edit(request):

    try:
        user = Token.objects.get(key = request.auth.key).user
    except Token.DoesNotExist:
        return Response(status=status.HTTP_401_UNAUTHORIZED)

    serialize = UserUpdateSerializer(user, data=request.data, many=False)

    try:
        if request.data['password'] != request.data['confirm_password']:
            return Response({'message':'Password does not match.'}, status=status.HTTP_400_BAD_REQUEST)
    except KeyError:
        return Response({'message':'Please ensure all field has been filled.'}, status=status.HTTP_400_BAD_REQUEST)

    if serialize.is_valid():
        updated = serialize.save()
        updated.set_password(request.data['password'])
        updated.save()
        return Response(serialize.data, status=status.HTTP_200_OK)

    return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)
"""
End of Profile Route
"""

"""
Start of Authentication Routes
"""
@api_view(['POST'])
def login(request):
    try:
        user = User.objects.get(username=request.data['username'])
        try:
            Token.objects.get(user=user).delete()
        except Token.DoesNotExist:
            pass
    except User.DoesNotExist:
        return Response({'message':'Incorrect Username or Password'}, status=status.HTTP_400_BAD_REQUEST)

    if not check_password(request.data['password'], user.password):
        return Response({'message':'Incorrect Username or Password'}, status=status.HTTP_400_BAD_REQUEST)

    serialized = UserSerializer(user, many=False)
    token = Token.objects.create(user=user)

    content = {
        "user": serialized.data,
        "token": token.key
    }

    return Response(content, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def logout(request):
    request.user.auth_token.delete()
    return Response({'message':'Logged out.'}, status=status.HTTP_200_OK)
@api_view(['POST'])
def register_account(request):
    serialize = UserRegistrationSerializer(data=request.data)
    
    if serialize.is_valid():
        serialize.save()
        #generate token here?
        user = User.objects.get(pk=serialize.data['id'])
        token = Token.objects.create(user=user)
        content = {
            "user" : serialize.data,
            "token": token.key,
        }

        return Response(content, status=status.HTTP_201_CREATED)

    return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)
"""
End of Authentication Routes
"""

"""
Start of TestModel Routes/URL
"""
@api_view(['GET'])
@authentication_classes([SessionAuthentication, TokenAuthentication])
@permission_classes([IsAuthenticated])
def test_lists(request):
    test_lists = TestModel.objects.all()
    serialized = TestModelSerializer(test_lists, many=True)

    return Response(serialized.data)
@api_view(['POST'])
def test_create(request):
    serialize = TestModelSerializer(data=request.data)
    
    if serialize.is_valid():
        serialize.save()
        return Response(data=serialize.data, status=status.HTTP_201_CREATED)

    return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def test_detail(request, pk):
    try:
        test_model = TestModel.objects.get(pk = pk)
    except TestModel.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    serialize = TestModelSerializer(test_model, many=False)
    return Response(serialize.data)

@api_view(['DELETE'])
def test_delete(request, pk):
    try:
        test_model = TestModel.objects.get(pk=pk)
    except TestModel.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    test_model.delete()
    return Response(status=status.HTTP_200_OK)

@api_view(['GET', 'PUT'])
def test_edit(request, pk):
    try:
        test_model = TestModel.objects.get(pk = pk)
    except TestModel.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serialize = TestModelSerializer(test_model, many=False)
        return Response(serialize.data, status=status.HTTP_200_OK)

    if request.method == 'PUT':
        serialize = TestModelSerializer(test_model, data=request.data)
        if serialize.is_valid():
            serialize.save()
            return Response(serialize.data, status=status.HTTP_200_OK)
        return Response(request.data, status=status.HTTP_400_BAD_REQUEST)

    pass
"""
End of TestModel Routes/URL
"""

"""Start of Fish Routes"""


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def fish_detail(request, pk):
    if not request.user.has_perm('auth.view_user'):
        return Response({'message': 'You are not authorized for this action.'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        fish = Fish.objects.get(pk=pk)
    except Fish.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    serialize = FishSerializer(fish, many=False)

    return Response(serialize.data, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def fish_create(request):

    serialize = FishAddSerializer(data=request.data)

    if serialize.is_valid():
        serialize.save()
        #print(serialize)

        #fish = Fish.objects.get(pk=serialize.data['fishid'])
        #s = FishSerializer(fish, many = False)
        #print(s)
        return Response(data=serialize.data, status=status.HTTP_201_CREATED)
        #return Response(s.data, status=status.HTTP_201_CREATED)

    return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def fish_edit(request, pk):
    if not request.user.has_perm('auth.change_user'):
        return Response({'message': 'You are not authorized for this action.'}, status=status.HTTP_401_UNAUTHORIZED)
    try:
        fish = Fish.objects.get(pk=pk)
    except Fish.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    serialize = FishSerializer(fish, data=request.data)

    if serialize.is_valid():
        serialize.save()
        return Response({'message': 'Successfully Updated fish.'}, status=status.HTTP_200_OK)

    return Response(serialize.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def fish_lists(request):
    if not request.user.has_perm('auth.view_user'):
        return Response({'message': 'You are not authorized for this action.'}, status=status.HTTP_401_UNAUTHORIZED)

    fishes = Fish.objects.all()
    serialize = FishSerializer(fishes, many=True)

    content = {
        "data": serialize.data
    }

    return Response(content, status=status.HTTP_200_OK)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def fish_delete(request, pk):
    if not request.user.has_perm('auth.delete_user'):
        return Response({'message': 'You are not authorized for this action.'}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        fish = Fish.objects.get(pk=pk)
    except Fish.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    fish.delete()

    return Response({'message': 'Fish Deleted.'}, status=status.HTTP_200_OK)


"""End of User Routes"""


def fish_imageupload(request):
    if request.method == 'POST':
        print(1)
        pic = request.FILES['pic']
        save_path= '%s/images/%S'%(settings.MEDIA_ROOT,pic.name)
        print(save_path)
        with open(save_path,'wb') as f:
            for content in pic.chunks():
                f.write(content)
            return HttpResponse('success')
    else:
        pic = FishUpdateSerializer()
    return render(request, 'fish/create.html', {'form': pic})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@authentication_classes([TokenAuthentication])
def success(request):
    return HttpResponse('successfully uploaded')

