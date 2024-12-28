from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'is_staff','first_name','last_name','client_id']
        extra_kwargs = {
            'password': {'write_only': True}  # Ensure password is write-only
        }

    def create(self, validated_data):
        
        if User.objects.filter(email=validated_data['email']).exists():
            raise ValidationError("A user with this email already exists.")
        
        is_staff = validated_data.get('is_staff', True)
        is_superuser = validated_data.get('is_superuser', True)

        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            is_staff=is_staff,
            is_superuser=is_superuser
        )
        return user
