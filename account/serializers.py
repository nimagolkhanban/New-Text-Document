from rest_framework import serializers
from .models import MyUser

class MyUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = MyUser
        fields = ['first_name', 'last_name', 'email', 'password']
        extra_kwargs = {'password':{'write_only': True}}
        
    def create(self, validated_data):
        user = MyUser(
            phone = validated_data["phone"],
            first_name = validated_data["first_name"],
            last_name = validated_data["last_name"],
            email = validated_data["email"],
        )
        user.set_password(validated_data["password"])
        user.save()
        return user
    
    def validate_email(self, value):
        if MyUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("email already exist")  
        return value
    