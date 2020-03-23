from django.shortcuts import render
from .views import (
    CreateUserAPIView,
    GetRoles,
    TasksPagePermission,
    NumbersPagePermission,
    ReportsPagePermission,
    AdditionallyPagePermission,
    GetUser,
    EditUser,
    GetUserList,
    DeleteUser
)
from django.urls import path
# Create your views here.
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView
)

urlpatterns = [
    path('create/', CreateUserAPIView.as_view(), name='create_user'), ##done
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'), # Done_test
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'), # Done_test
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'), # Done_test
    path('get_roles/', GetRoles.as_view(), name='get_roles'), # Done_test
    path('tasks/', TasksPagePermission.as_view(), name='tasks_permission'), # Done
    path('numbers/', NumbersPagePermission.as_view(), name='numbers_permission'), # DONE_test
    path('reports/', ReportsPagePermission.as_view(), name='reports_permission'), # done
    path('additionally/', AdditionallyPagePermission.as_view(), name='additionally_permission'), #done
    path('get_user/', GetUser.as_view(), name='get_user'), # Done_test
    path('edit_user/', EditUser.as_view(), name='edit_user'), # Done_test
    path('delete_user/', DeleteUser.as_view(), name='delete_user'), # Dont
    path('get_user_list/', GetUserList.as_view(), name='get_users_list'),  # Done
]