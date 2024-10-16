"""
Serializers for the User API
"""


from django.contrib.auth import get_user_model, authenticate

from rest_framework import serializers



class UserSerializer(serializers.ModelSerializer):
    """Serializer for the user model"""

    class Meta:
        model = get_user_model()
        fields = ('email', 'password', 'name')
        extra_kwargs = {
            'password': {
                'write_only': True,
                'min_length': 5
            }
        }

    def create(self, validated_data):
        """ Creates and returns a new user with encrypted password"""
        return get_user_model().objects.create_user(**validated_data)

    def update(self, instance, validated_data):
        """Updates a user, including handling password changes"""

        # Pop the password field if it exists in validated_data
        password = validated_data.pop('password', None)

        # Update the other fields from the validated data
        user = super().update(instance, validated_data)

        # If a password is provided, hash it and save it
        if password:
            user.set_password(password)
            user.save()  # Save the updated user instance with the new password

        return user

    # def update(self, instance, validated_data):
    #     """Updates a user"""
    #
    #     password = validated_data.pop('password', None)
    #     user = super().update(instance, validated_data)
    #
    #     if password:
    #         user.set_password(password)
    #         user.save()
    #
    #     return user

    # def update(self, instance, validated_data):
    #     """Update and return the user with an encrypted password."""
    #     # Pop the password field from validated data if it exists
    #     password = validated_data.pop('password', None)
    #
    #     # Update the user's other fields first
    #     user = super().update(instance, validated_data)
    #
    #     # If the password is being updated, hash and save it
    #     if password:
    #         user.set_password(password)  # Hash the password
    #         user.save()  # Save the user with the new password


class AuthTokenSerializer(serializers.Serializer):

    email = serializers.EmailField()
    password = serializers.CharField(
        style= {'input_type': 'password'},
        trim_whitespace=False
    )

    def validate(self, attrs):
        """Validate and authenticate the credentials and the user"""

        email = attrs.get('email')
        password = attrs.get('password')

        user = authenticate(
            username=email,
            password=password
        )

        if not user:
            msg = 'Unable to Authenticate User with Provided Credentials'
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs





