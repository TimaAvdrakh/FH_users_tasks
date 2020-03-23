from __future__ import unicode_literals
from django.db import models
from django.contrib.postgres.fields import ArrayField
from django.utils import timezone
from django.contrib.auth.models import (
    AbstractBaseUser, PermissionsMixin, BaseUserManager
)


class UserManager(BaseUserManager):
    def _create_user(self, email, name, password=None, **extra_fields):
        if not email:
            raise ValueError("Email Should Be Provided")
        email = self.normalize_email(email)
        user = self.model(email=email, name=name, **extra_field)
        user.set_password(password)
        user.save()
        return user

    def create_user(self, email, name, pages, creator, password=None, **extra_fields):
        extra_fields.setdefault('is_superuser', False)
        extra_fields.setdefault('is_active', Tru)
        extra_fields.setdefault('role', )
        extra_fields.setdefault('pages', pages)
        extra_fields.setdefault('creator', creator )
        return self._create_user(email=email, name=name, password=password, **extra_fields)

    def create_superuser(self, email, name, password, **extra_fields):
        pages = [i[0] for i in User.PAGES]
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', User.ROLE_ADMINISTRATOR),
        extra_fields.setdefault('pages', pages)
        # extra_fields.setdefault('pages', User.get_pages(self.request.user))



        return self._create_user(email, name, password=password, **extra_fields)




class User(AbstractBaseUser, PermissionsMixin):
    ROLE_ADMINISTRATOR = 0
    ROLE_CLIENT = 1
    ROLE_CHOICES = (
        (ROLE_ADMINISTRATOR,'Админ'),
        (ROLE_CLIENT, 'Клиент')
    )

    PAGES_TASKS = 'TASKS'
    PAGE_NUMBER = 'NUMBERS'
    PAGE_REPORTS = 'REPORTS'
    PAGE_ADDITIONALLY = 'ADDITIONALLY'
    PAGES = (
        (PAGES_TASKS,'Задачи'),
        (PAGE_NUMBER,'Номера'),
        (PAGE_REPORTS,'Отчеты'),
        (PAGE_ADDITIONALLY,'Дополнительно'),
    )

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']

    object = UserManager()

    name = models.CharField(max_length=30)
    email = models.EmailField(unique=True)
    creator = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, related_name='user_creator')
    role = models.SmallIntegerField(choices=ROLE_CHOICES)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    pages = ArrayField(models.CharField(max_length=22, choices=PAGES), size=4, default=None)

    def get_pages(self):
        arr=[]
        for page in User.PAGES:
            arr.append(page[0])
        return arr