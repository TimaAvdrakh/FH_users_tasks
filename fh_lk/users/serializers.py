from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):

    pages = serializers.ListField(child=serializers.CharField)
    creator = serializers.RelatedField(read_only=True)

    def create(self, validated_data):

        user = User.objects.crete_user(
            name=validated_data['name'],
            email=validated_data['email'],
            creator=validated_data['creator'],
            role=validated_data['role'],
            pages=validated_data['pages']
        )

        user.set_password(validated_data['password'])
        user.save()

        return user


    class Meta:
        model = User
        fields = ['id', 'email', 'creator', 'name', 'password', 'role', 'pages']
        extra_kwargs = {'password': {'write_only': True}}