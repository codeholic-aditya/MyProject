from django.http import JsonResponse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import UserSerializer
from rest_framework_simplejwt.tokens import RefreshToken,AccessToken
from django.contrib.auth import authenticate,get_user_model,logout
from django.contrib.auth.models import Permission
from rest_framework.permissions import IsAuthenticated,IsAdminUser
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.permissions import BasePermission
from rest_framework.exceptions import ValidationError
import hashlib
from rest_framework_simplejwt.exceptions import InvalidToken
import json
from django.shortcuts import render
import os
from django.conf import settings

# Create your views here.
User = get_user_model()

class IsSuperuser(BasePermission):
    """
    Custom permission to only allow superusers to access the view.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_superuser

class CanCreateUserPermission(BasePermission):
    def has_permission(self, request, view):
        # First, check if the user is an admin
        if not request.user.is_staff:
            return False
        # Check if the user has the specific permission
        return request.user.has_perm('auth.add_user')

class Generator:
    def generate_hashed_string(username, email):
    # Concatenate the username and email
        combined = username + email
        
        # Create a SHA-256 hash object
        sha256_hash = hashlib.sha256()
        
        # Update the hash object with the combined string (encoded to bytes)
        sha256_hash.update(combined.encode('utf-8'))
        
        # Generate the hexadecimal representation of the hash
        hashed_value = sha256_hash.hexdigest()
        
        return hashed_value

class BackEndRegister(APIView):
    permission_classes = [IsAdminUser]
    def post(self, request):
        adminuser=request.user
        # print("Hello")

        if not adminuser.has_perm('app.add_user'):
            return Response({"error": "You do not have permission to create a user."}, status=status.HTTP_403_FORBIDDEN)

        username= request.data.get('username')
        firstname= request.data.get('firstname')
        lastname= request.data.get('lastname')
        email= request.data.get('email')
        password= request.data.get('password')
        permission= request.data.get('permission',[])

        

        if not all([username, firstname, lastname, email, password]):
            return Response({"error": "All fields are required."}, status=status.HTTP_400_BAD_REQUEST)
        
        if User.objects.filter(username=username).exists():
            return Response({"error": f"Username '{username}' is already exist."}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({"error": f"Email '{email}' is already exist."}, status=status.HTTP_400_BAD_REQUEST)
        
        perms=[]

        try:
            
            if permission:
                if not adminuser.has_perm('auth.add_permission'):
                    return Response({"error": "You do not have permission to assign permission to any user."}, status=status.HTTP_403_FORBIDDEN)

                try:
                    # Get the permission by codename
                    # for perms in permission:
                    #     perm = Permission.objects.get(codename=perms)
                    #     user.user_permissions.add(perm)  # Add the permission to the user
                    perms = [Permission.objects.get(codename=perm) for perm in permission]

                except Permission.DoesNotExist as e:
                    return Response({"error": f"Permission that you give does not exist."}, status=status.HTTP_400_BAD_REQUEST)
            
            user = User.objects.create_user(
                username=username,
                first_name=firstname,
                last_name=lastname, 
                email=email, 
                password=password,
                is_staff=True if permission else False,
                client_id=Generator.generate_hashed_string(username,email)
            )
            if permission:
                user.user_permissions.set(perms)

            user.save()
            return Response({
                "message": "User created successfully!",
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                },
                "status": "Active" if user.is_active else "Inactive",
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class Login(APIView):
    def post(self, request):
        
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response({
                'message': 'Username and password are required'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Authenticate user
        user = authenticate(username=username, password=password)

        if user is not None:
            # If user is authenticated, generate JWT token
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            
            return Response({
                'message': 'Login successful',
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "firstname": user.first_name,
                    "lastname": user.last_name,
                    "email": user.email,
                },
                'access_token': access_token,
                'refresh_token': str(refresh),
                "expires_in": 18000,
                
            }, status=status.HTTP_200_OK)
        else:
            # If authentication fails, return error response
            return Response({
                'message': 'Invalid username or password'
            }, status=status.HTTP_401_UNAUTHORIZED)

class Logout(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Check if the user is authenticated at the beginning
        if not request.user.is_authenticated:
            return Response({"message": "You are already logged out."}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the refresh_token is provided in the request
        refresh_token = request.data.get('refresh_token')

        if not refresh_token:
            return Response({"error": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create a RefreshToken object using the provided refresh token
            token = RefreshToken(refresh_token)
            # Blacklist the refresh token to invalidate it
            token.blacklist()

        except InvalidToken:
            return Response({"error": "Invalid refresh token."}, status=status.HTTP_400_BAD_REQUEST)

        # Log the user out (clear the session in case of session-based auth)
        logout(request)
        
        return Response({"message": "Logged out successfully."}, status=status.HTTP_200_OK)

class BackendUpdateUser(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request):

        user_id = request.data.get('user_id')
        username = request.data.get('username')
        firstname = request.data.get('firstname')
        lastname = request.data.get('lastname')
        email = request.data.get('email')

        if not user_id:
            return Response({"error": "user_id is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Fetch the user object by ID
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise NotFound(detail="User not found.")

        backend_user = request.user
        
        if backend_user.has_perm('app.change_user'):
            if username:
                user.username = username
            if firstname:
                user.first_name = firstname
            if lastname:
                user.last_name = lastname
            if email:
                user.email = email
                user.save()
        else:
            return Response({"message": "You don't have permission to update the user"}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message": "User updated successfully"}, status=status.HTTP_200_OK)

class GetAllBackendUser(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        
        users = User.objects.all()

        user_data=[]

        for user in users:
            user_data.append({
                'id': user.id,
                'is_staff': user.is_staff,
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'joined_date': user.date_joined,
                'client_id':user.client_id
            })
        return Response({"users": user_data}, status=status.HTTP_200_OK)

class GetBackendUser(APIView):
    permission_classes = [IsAdminUser]
    
    def get(self, request):
        user=request.user
        if user:
            user_data = {
            'id': user.id,
                'is_staff': user.is_staff,
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'joined_date': user.date_joined,
                'client_id':user.client_id
            }
        else:
            return Response({"error":"User not found"}, status=status.HTTP_400_BAD_REQUEST)    
        # Return the user details in the response
        return Response({"user": user_data}, status=status.HTTP_200_OK)

class ReadJSONData(APIView):

    def load_json_data(self, file_path):
        """Helper function to load JSON data from a file."""
        try:
            with open(file_path, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            return None
        except json.JSONDecodeError:
            return None

    def get(self, request):
        """
        Handles GET requests to merge and filter the 'changelog_latest.json' and 'changelog_previous.json' files.

        Query Parameters:
            - version (str): A specific version to filter data.
            - category (str): A specific category to filter data within a version.
            - feature_type (str): A specific feature type to filter features.

        Returns:
            - A JSON response with the filtered changelog data.
            - HTTP 404 if one of the files is not found.
            - HTTP 400 if the JSON format is invalid in any of the files.
            - HTTP 200 with merged data or filtered data if the query matches.
        """
        file_path1 = os.path.join(settings.CHANGELOG_DATA_DIR_PATH, settings.CHANGELOG_LATEST_FILE_NAME)
        file_path2 = os.path.join(settings.CHANGELOG_DATA_DIR_PATH, settings.CHANGELOG_PREVIOUS_FILE_NAME)

        # Get query parameters
        version_query = request.query_params.get('version')
        category_query = request.query_params.get('category')
        feature_type_query = request.query_params.get('type')

        json_data_1 = self.load_json_data(file_path1)
        json_data_2 = self.load_json_data(file_path2)

        if not json_data_1 or not json_data_2:
            missing_file = file_path1 if not json_data_1 else file_path2
            return Response({"error": f"File not found or invalid JSON format: {missing_file}"}, status=404)

        # Merge versions from both files
        merged_versions = json_data_1.get('versions', []) + json_data_2.get('versions', [])

        def filter_versions(data, key, query):
            """
            Filters a list of dictionaries by a specified key and value.

            Args:
                data (list): List of dictionaries to filter.
                key (str): Key to filter by.
                query (str or any): Value to match for the specified key.

            Returns:
                list: Filtered list of dictionaries where the key matches the query.
            """
            return [item for item in data if str(item.get(key, '')).lower() == str(query).lower()]

        def clean_empty(data, key):
                """
                Removes dictionaries where the specified key is missing or has a falsy value.

                Args:
                    data (list): List of dictionaries to filter.
                    key (str): The key to check for emptiness.
                Returns:
                    list: Filtered list with dictionaries that have a truthy value for the key.
                """
                return [item for item in data if item.get(key)]

        # Apply filtering based on query parameters
        # Filter by version
        if version_query:
            merged_versions = filter_versions(merged_versions, 'version', version_query)
            if not merged_versions:
                return Response({"status": False, "message": f"No data found for version: {version_query}. Showing all versions.", "versions": []}, status=200)

        #Filter by category
        if category_query:
            for version in merged_versions:
                version['categories'] = filter_versions(version.get('categories', []), 'category', category_query)
            merged_versions = clean_empty(merged_versions, 'categories')
            if not merged_versions:
                return Response({"status": False, "message": f"No data found for category: {category_query}.", "versions": []}, status=200)

        #Filter by feature type
        if feature_type_query:
            for version in merged_versions:
                for category in version.get('categories', []):
                    category['features'] = filter_versions(category.get('features', []), 'type', feature_type_query)
                version['categories'] = clean_empty(version.get('categories', []), 'features')
            merged_versions = clean_empty(merged_versions, 'categories')
            if not merged_versions:
                return Response({"status": False, "message": f"No data found for feature type: {feature_type_query}.", "versions": []}, status=200)

        # Return merged data if no filters are applied
        return Response({
            "status": True,
            "message": "Filtered data",
            "versions": merged_versions
        }, status=200)

    def patch(self, request):
        """
        Handles PATCH requests to update the 'like' or 'dislike' count for a specific feature 
        within a particular version and category in the changelog JSON file.

        The API expects the following parameters in the request body:
            - version (str): The version number of the changelog.
            - category (str): The category under which the feature is listed.
            - feature-index (int): The index of the feature to be updated.
            - like (bool): If True, increment the 'like' count by 1. If False, decrement the 'like' count by 1.
            - dislike (bool): If True, increment the 'dislike' count by 1. If False, decrement the 'dislike' count by 1.

        Response:
            - A JSON response with a message indicating the success or failure of the operation.
            - HTTP 200 (OK) if the update is successful.
            - HTTP 400 (Bad Request) if the index is out of range or if required fields are missing.
            - HTTP 404 (Not Found) if the specified version or category is not found.
            - HTTP 404 (Not Found) if the JSON file does not exist.
            - HTTP 400 (Bad Request) if the JSON format is invalid.
        """
        version_number = request.data.get('version')
        category_name = request.data.get('category')
        index = request.data.get('feature-index')
        like = request.data.get('like')
        dislike = request.data.get('dislike')

        # Ensure all required fields are provided
        if not all([version_number, category_name, index is not None]):
            return Response({"error": "Missing required fields"}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure index is an integer
        try:
            index = int(index)
        except ValueError:
            return Response({"error": "Invalid feature-index. Must be an integer."}, status=status.HTTP_400_BAD_REQUEST)

        # Define the file path to the changelog JSON file
        file_path = os.path.join(settings.CHANGELOG_DATA_DIR_PATH, settings.CHANGELOG_LATEST_FILE_NAME)

        # Load the JSON data
        data = self.load_json_data(file_path)
        if not data:
            return Response({"error": "File not found or invalid JSON format."}, status=status.HTTP_404_NOT_FOUND)

        for version in data.get('versions', []):
            if version.get('version') == version_number:
                for category in version.get('categories', []):
                    # if category.get('category') == category_name:
                    if str(category.get('category', '')).lower() == str(category_name).lower():
                        features = category.get('features', [])
                        if 0 <= index < len(features):
                            feature = features[index]

                            # Update 'like' count: increment or decrement based on 'like' value, ensuring it doesn't go below 0.
                            if like is not None:
                                feature['like'] = max(0, feature.get('like', 0) + (1 if like else -1))

                            # Update 'dislike' count: increment or decrement based on 'dislike' value, ensuring it doesn't go below 0.
                            if dislike is not None:
                                feature['dislike'] = max(0, feature.get('dislike', 0) + (1 if dislike else -1))

                            # Save changes back to json file
                            with open(file_path, 'w') as json_file:
                                json.dump(data, json_file, indent=4)

                            return Response({"status": True, "message": "Updated successfully"}, status=status.HTTP_200_OK)

                        return Response({"error": "Invalid index for features."}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"error": "Version or category not found."}, status=status.HTTP_404_NOT_FOUND)
    
class AssignBackendUserPermission(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request):
        admin_user = request.user
        user_id = request.data.get('user_id')
        permissions = request.data.get('permission',[])
        
        if user_id==admin_user.id:
            return Response({"error": "You can not assign permission to yourself."}, status=status.HTTP_400_BAD_REQUEST)
        
        if not user_id:
            return Response({"error": "User ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        if not permissions:
            return Response({"error": "At least one permission is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        
        if not admin_user.has_perm('auth.change_user'):
            return Response({"error": "You do not have permission to assign permissions to users."}, status=status.HTTP_403_FORBIDDEN)

        permission_objects = []
        for perm_codename in permissions:
            try:
                perm = Permission.objects.get(codename=perm_codename)
                permission_objects.append(perm)
            except Permission.DoesNotExist:
                return Response({"error": f"Permission '{perm_codename}' does not exist."}, status=status.HTTP_400_BAD_REQUEST)

        user.user_permissions.set(permission_objects)

        user.save()

        return Response({"message": "Permissions assigned successfully!"}, status=status.HTTP_200_OK)

    def delete(self, request):

        admin_user = request.user

        user_id = request.data.get("user_id")
        permissions = request.data.get("permissions", [])

        if user_id==admin_user.id:
            return Response({"error": "You can not assign permission to yourself."}, status=status.HTTP_400_BAD_REQUEST)

        if not user_id:
            return Response({"error":"User ID required"},status=status.HTTP_400_BAD_REQUEST)
        if not permissions:
            return Response({"error":"Atleast one permission is required"},status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        
        if not admin_user.has_perm('app.change_user'):
            return Response({"error": "You do not have permission to delete permissions from users."}, status=status.HTTP_403_FORBIDDEN)

        permission_objects = []
        for perm_codename in permissions:
            try:
                perm = Permission.objects.get(codename=perm_codename)
                permission_objects.append(perm)
            except Permission.DoesNotExist:
                return Response({"error": f"Permission '{perm_codename}' does not exist."}, status=status.HTTP_400_BAD_REQUEST)

        user.user_permissions.remove(*permission_objects)
        print(permission_objects)
        user.save()

        return Response({
            "message": "Permissions deleted successfully!",
            "permissions": permissions
            }, status=status.HTTP_200_OK)
        
    def get(self, request):
        admin_user = request.user

        user_id = request.data.get('user_id')
        
        # if user_id==admin_user.id:
        #     return Response({"error": "You can not assign permission to yourself."}, status=status.HTTP_400_BAD_REQUEST)

        if not user_id:
            return Response({"error":"User ID required"},status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        
        if not admin_user.has_perm('app.view_user'):
            return Response({"error": "You do not have permission to view user's permissions."}, status=status.HTTP_403_FORBIDDEN)
        
        permission_list=user.user_permissions.all()

        permission_data = [{"id": perm.id, "name": perm.codename} for perm in permission_list]
        print(permission_data)

        return Response({
            "message": "Permissions deleted successfully!",
            "permissions": permission_data
            }, status=status.HTTP_200_OK)

class DeleteBackendUser(APIView):
    permission_classes = [IsAdminUser]

    def delete(self, request):

        admin_user = request.user

        user_id = request.data.get('user_id')

        if not user_id:
            return Response({"error":"User id required"},status=status.HTTP_400_BAD_REQUEST)

        if not admin_user.has_perm('app.delete_user'):
            return Response({"error":"You do not have permission to delete user."},status=status.HTTP_400_BAD_REQUEST)
        
        try:
            delete_user = User.objects.get(id=user_id)
            delete_user.delete()
            return Response({
                "message": "User deleted successfully.",
                "user": delete_user.username
                }, status=status.HTTP_200_OK)
    
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

class DeactivateUser(APIView):
    permission_classes = [IsAdminUser]

    def delete(self, request):

        admin_user = request.user

        user_id = request.data.get('user_id')

        if not user_id:
            return Response({"error":"User id required"},status=status.HTTP_400_BAD_REQUEST)

        if not admin_user.has_perm('app.delete_user'):
            return Response({"error":"You do not have permission to deactivate user."},status=status.HTTP_400_BAD_REQUEST)
            
        try:
            deactivate_user = User.objects.get(id=user_id)
            deactivate_user.is_active=False

            deactivate_user.save()

            return Response({
                "message": "User deactivated successfully.",
                "user": deactivate_user.username
                }, status=status.HTTP_200_OK)
    
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)



# frontend APIs

class FrontEndRegister(APIView):
    def post(self, request):

        username= request.data.get('username')
        firstname= request.data.get('firstname')
        lastname= request.data.get('lastname')
        email= request.data.get('email')
        password= request.data.get('password')

        if not all([username, firstname, lastname, email, password]):
            return Response({"error": "All fields are required."}, status=status.HTTP_400_BAD_REQUEST)
        
        if User.objects.filter(username=username).exists():
            return Response({"error": f"Username '{username}' is already exist."}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({"error": f"Email '{email}' is already exist."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.create_user(
                username=username,
                first_name=firstname,
                last_name=lastname, 
                email=email, 
                password=password,
                client_id=Generator.generate_hashed_string(username,email)
            )
            user.save()
            return Response({
                "message": "Registration successful!",
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                },
                "status": "Active" if user.is_active else "Inactive",
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class FrontendUserLogin(APIView):
    def post(self, request):

        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response({
                'message': 'Username and password are required'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Authenticate user
        user = authenticate(username=username, password=password)

        if user is not None:
            # If user is authenticated, generate JWT token
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            
            return Response({
                'message': 'Login successful',
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "firstname": user.first_name,
                    "lastname": user.last_name,
                    "email": user.email,
                },
                'access_token': access_token,
                'refresh_token': str(refresh),
                "expires_in": 18000,
                
            }, status=status.HTTP_200_OK)
        else:
            # If authentication fails, return error response
            return Response({
                'message': 'Invalid username or password'
            }, status=status.HTTP_401_UNAUTHORIZED)

class FrontendUserLogout(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Check if the user is authenticated at the beginning
        if not request.user.is_authenticated:
            return Response({"message": "You are already logged out."}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the refresh_token is provided in the request
        refresh_token = request.data.get('refresh_token')

        if not refresh_token:
            return Response({"error": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create a RefreshToken object using the provided refresh token
            token = RefreshToken(refresh_token)
            # Blacklist the refresh token to invalidate it
            token.blacklist()

        except InvalidToken:
            return Response({"error": "Invalid refresh token."}, status=status.HTTP_400_BAD_REQUEST)

        # Log the user out (clear the session in case of session-based auth)
        logout(request)
        
        return Response({"message": "Logged out successfully."}, status=status.HTTP_200_OK)






