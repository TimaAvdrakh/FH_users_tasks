from django.shortcuts import render
from rest_framework.views import APIView
from .serializers import UserSerializer
from rest_framework.response import Response
from rest_framework import status
from .models import User
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.decorators import api_view, permission_classes
from rest_framework_simplejwt.tokens import RefreshToken
from django.http import JsonResponse
from .permissions import *


class GetUser(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        print('get user')
        print(request.data)
        try:
            id = request.data['id']
        except KeyError:
            user = request.user
            return JsonResponse({'id': user.id, 'email': user.email, 'name': user.name, 'role': user.role, 'pages': user.pages})

        try:
            user = User.objects.get(id=int(request.data['id']))
        except User.DoesNotExist:
            return Response({"error": "DoesNotExist"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        if user.creator == request.user or request.user.is_staff:
            return Response({
                        "id": user.id,
                        "email": user.email,
                        "name": user.name,
                        "role": user.role,
                        "is_active": user.is_active,
                        "pages": user.pages},
                        status=status.HTTP_200_OK)
        else:
            return Response(status=status.HTTP_403_FORBIDDEN)


class GetUserList(APIView):
    permission_classes = [AdditionallyPage | IsAdminUser]

    def get(self, request):
        user = request.user

        user_list = []

        if user.is_staff:
            for user in User.objects.exclude(creator=None):
                user_list.append({
                    'id': user.id,
                    'name': user.name,
                    'email': user.email,
                    'creator': user.creator.email
                })
        else:
            for user in User.objects.filter(creator=user):
                user_list.append({
                    'id': user.id,
                    'name': user.name,
                    'email': user.email,
                    'creator': user.creator.email
                })

        return JsonResponse({"users_list": user_list}, safe=False)


class CreateUserAPIView(APIView):
    permission_classes = [AdditionallyPage | IsAdminUser]

    def post(self, request):
        user = request.data
        if request.user.role == User.ROLE_ADMINISTRATOR:
            if request.data['role'] == User.ROLE_ADMINISTRATOR:
                new_user = User.objects.create_superuser(
                    email=request.data['email'],
                    name=request.data['name'],
                    password=request.data['password'],
                    creator=request.user
                )
            else:
                new_user = User.objects.create_user(
                    email=request.data['email'],
                    name=request.data['name'],
                    pages=request.data['pages'],
                    password=request.data['password'],
                    creator=request.user
                )
            return Response({'email': new_user.email, 'name': new_user.name}, status=status.HTTP_201_CREATED)
        else:
            if int(user['role']) == User.ROLE_ADMINISTRATOR:
                return Response({"error": "admin"}, status=status.HTTP_403_FORBIDDEN)
            else:
                if len(user['pages']) != 0:
                    for page in user['pages']:
                        if page not in request.user.pages:
                            return Response({"error": "pages"}, status=status.HTTP_403_FORBIDDEN)
                        else:
                            new_user = User.objects.create_user(
                                email=request.data['email'],
                                name=request.data['name'],
                                pages=request.data['pages'],
                                password=request.data['password'],
                                creator=request.user
                            )
                    return Response({'email': new_user.email, 'name': new_user.name}, status=status.HTTP_201_CREATED)
                else:
                    new_user = User.objects.create_user(
                        email=request.data['email'],
                        name=request.data['name'],
                        pages=request.data['pages'],
                        password=request.data['password'],
                        creator=request.user
                    )
                    return Response({'email': new_user.email, 'name': new_user.name}, status=status.HTTP_201_CREATED)


class EditUser(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        print(request.data)

        try:
            user = User.objects.get(id=int(request.data['id']))
        except User.DoesNotExist:
            return Response({"error": "DoesNotExist"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        if user.creator != request.user:
            return Response({"error": "Access Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        user.email = request.data['email']
        user.name = request.data['name']

        if request.data['role'] == 0 and request.user.role != User.ROLE_ADMINISTRATOR:
            return Response({'error': 'Access Forbidden Cant Make Admin'}, status=status.HTTP_403_FORBIDDEN)

        for page in request.data['pages']:
            if page in request.user.pages:
                user.pages.append(page)
            else:
                return Response({"error": "Access Forbitten Creator has not" + page + "parmission"},
                                status=status.HTTP_403_FORBIDDEN)

        user.is_active = request.data['isActive']

        if request.data['role'] == User.ROLE_ADMINISTRATOR:
            user.is_staff = True
            user.pages = User.get_pages()
        if request.data['password'] != None:
            user.set_password(request.data['password'])
        user.save()
        return Response(status=status.HTTP_200_OK)


class DeleteUser(APIView):
    permission_classes = [IsAuthenticated | AdditionallyPage]

    def post(self, request):
        try:
            user = User.objects.get(id=int(request.data['id']))
        except User.DoesNotExist:
            return Response({"error": "DoesNotExist"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        if user.creator != request.user:
            return Response({"error": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        user.delete()
        return Response(status=status.HTTP_200_OK)


class TasksPagePermission(APIView):
    permission_classes = [TasksPage | IsAdminUser]

    def get(self, request):
        return Response(status=status.HTTP_200_OK)


class NumbersPagePermission(APIView):
    permission_classes = [NumbersPage | IsAdminUser]

    def get(self, request):
        return Response(status=status.HTTP_200_OK)


class ReportsPagePermission(APIView):
    permission_classes = [ReportsPage | IsAdminUser]

    def get(self, request):
        return Response(status=status.HTTP_200_OK)


class AdditionallyPagePermission(APIView):
    permission_classes = [AdditionallyPage | IsAdminUser]

    def get(self, request):
        return Response(status=status.HTTP_200_OK)


class GetRoles(APIView):
    permission_classes = (IsAdminUser,)

    def get(self, request):
        roles = User.ROLE_CHOICES
        return JsonResponse(roles, safe=False)