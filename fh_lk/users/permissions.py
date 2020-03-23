from rest_framework.permissions import BasePermission

from .models import User

class TaskPermission(BasePermission):
    def has_permission(self, request, view):
        print(request.user)
        return User.PAGES_TASKS in request.user.pages

class NumberPermission(BasePermission):
    def has_permission(self, request, view):
        print(request.user)
        return User.PAGE_NUMBER in request.user.pages

class ReportsPermission(BasePermission):
    def has_permission(self, request, view):
        print(request.user)
        return User.PAGE_REPORTS in request.user.pages

class AdditionallyPage(BasePermission):
    def has_permission(self, request, view):
        print(request.user)
        return User.PAGE_ADDITIONALLY in request.user.pages
