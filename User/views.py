"""
Views for the user API
"""

from rest_framework import generics, authentication, permissions
from rest_framework.authtoken.views import ObtainAuthToken

from rest_framework.settings import api_settings
from User.serializers import UserSerializer,AuthTokenSerializer
from django.contrib.auth import get_user_model, authenticate
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from .serializers import UserSerializer



from BankAccount import models

class CreateUserView(generics.CreateAPIView):
    """ Endpoint for creating a new user in our system"""
    serializer_class = UserSerializer




class UserList(generics.ListAPIView):
    queryset = get_user_model().objects.all()
    serializer_class = UserSerializer
    #permission_classes = [IsAuthenticated]


class UserUpdate(generics.UpdateAPIView):
    queryset = get_user_model().objects.all()  # Query all users (we'll restrict it later)
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]  # Ensure that only authenticated users can update

    def get_object(self):
        """Override to return the current authenticated user"""
        return self.request.user  # Return the authenticated user


class CreateTokenView(ObtainAuthToken):
    """Create a new token for the user"""
    serializer_class = AuthTokenSerializer
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES




class ManageUserView(generics.RetrieveUpdateAPIView):
    """Manage the authenticated user"""
    serializer_class = UserSerializer
    authentication_classes = (authentication.TokenAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def get_object(self):
        """Retrieve and return the authenticated user"""
        return self.request.user























































