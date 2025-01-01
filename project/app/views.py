import re
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken,TokenError
from django.contrib.auth import get_user_model,logout
from django.contrib.auth.models import Permission
from rest_framework.permissions import IsAuthenticated,IsAdminUser
from rest_framework.exceptions import NotFound
from rest_framework.permissions import BasePermission
from rest_framework.exceptions import ValidationError
import hashlib
from rest_framework_simplejwt.exceptions import InvalidToken

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

class Validation:
    def validate_username(username):
        # Regex pattern to check for allowed characters (_,-,.)
        username_pattern = r'^[A-Za-z0-9._-]+$'
        if not re.match(username_pattern, username):
            return False
        return True

    def validate_email(email):
        # Regex pattern to check for a valid email format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return False
        return True
    def validate_phone_number(self, phone_number):
        # Regex pattern to check for a valid phone number format
        phone_number_pattern = r'^\+?[0-9]{1,4}?[-.\s]?[0-9]{1,15}$'
        if not re.match(phone_number_pattern, phone_number):
            return False
        return True
    
    def validate_strong_password(password):
        # Check if the password is at least 8 characters long
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long.")
        if not re.search(r'[A-Z]', password):
            raise ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'[0-9]', password):
            raise ValidationError("Password must contain at least one digit.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError("Password must contain at least one special character.")
        return password

class BackEndRegister(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request):
        adminuser = request.user

        if not adminuser.has_perm('app.add_user'):
            return Response({
                "status": False,
                "error": "You do not have permission to create a user."
            }, status=status.HTTP_403_FORBIDDEN)

        username= request.data.get('username')
        firstname= request.data.get('firstname')
        lastname= request.data.get('lastname')
        email= request.data.get('email')
        password= request.data.get('password')
        is_staff= request.data.get('is_staff',False)
        permission= request.data.get('permission',[])
        
        if not username:
            return Response({
                "status": False,
                "error": "Username is required."
            }, status=status.HTTP_400_BAD_REQUEST)
        if not firstname:
            return Response({
                "status": False,
                "error": "First name is required."
            }, status=status.HTTP_400_BAD_REQUEST)
        if not lastname:
            return Response({
                "status": False,
                "error": "Last name is required."
            }, status=status.HTTP_400_BAD_REQUEST)
        if not email:
            return Response({
                "status": False,
                "error": "Email is required."
            }, status=status.HTTP_400_BAD_REQUEST)
        if not password:
            return Response({
                "status": False,
                "error": "Password is required."
            }, status=status.HTTP_400_BAD_REQUEST)

        username_pattern = Validation.validate_username(username)
        if not username_pattern:
            return Response({
                "status": False,
                "error": "Username can only contain letters, numbers, underscores (_), hyphens (-), and periods (.)"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # phone_number_pattern = r'^\+?[0-9]{1,4}?[-.\s]?[0-9]{1,15}$'
        # if not re.match(phone_number_pattern, username):
        #     return Response({"error": "Invalid phone number format."}, status=status.HTTP_400_BAD_REQUEST)
        
        email_pattern = Validation.validate_email(email)
        if not email_pattern:
            return Response({
                "status": False,
                "error": "Invalid email format. Please provide a valid email address."
            }, status=status.HTTP_400_BAD_REQUEST)

        password = Validation.validate_strong_password(password)

        if User.objects.filter(username=username).exists():
            return Response({
                "status": False,
                "error": f"Username '{username}' is already exist."
            }, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({
                "status": False,
                "error": f"Email '{email}' is already exist."
            }, status=status.HTTP_400_BAD_REQUEST)

        permission_objects=[]

        try:
            
            if permission:
                if not adminuser.has_perm('auth.add_permission'):
                    return Response({
                        "status": False,
                        "error": "You do not have permission to assign permission to any user."
                    }, status=status.HTTP_403_FORBIDDEN)
                
                for perm_codename in permission:
                    try:
                        perm = Permission.objects.get(codename=perm_codename)
                        permission_objects.append(perm)
                    except Permission.DoesNotExist:
                        return Response({
                            "status": False,
                            "error": f"Permission '{perm_codename}' does not exist."
                        }, status=status.HTTP_400_BAD_REQUEST)

            user = User.objects.create_user(
                username=username,
                first_name=firstname,
                last_name=lastname,
                email=email,
                password=password,
                is_staff=is_staff,
                client_id=Generator.generate_hashed_string(username,email)
            )

            if is_staff:
                user_view_permission = Permission.objects.get(codename="view_user")
                user.user_permissions.add(user_view_permission)

            if permission and is_staff:
                user.user_permissions.set(permission_objects)
                print(permission_objects)

            user.save()
            return Response({
                "status": True,
                "message": "User created successfully!",
                "user": {
                    "is_active": user.is_active,
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "verify_email": user.email_verified,
                    "created_at": user.date_joined,
                },
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({
                "status": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class Login(APIView):
    def post(self, request):
        
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response({
                "status": False,
                'message': 'Username and password are required'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Authenticate user
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({
                "status": False,
                "error": "The username you entered does not match any account."
            }, status=status.HTTP_404_NOT_FOUND)
   
        
        if user.is_active is False:
            return Response({
                "status": False,
                "error": "User is deactivated"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not user.check_password(password):
            return Response({
                "status": False,
                "error": "The password you entered is incorrect."
            }, status=status.HTTP_401_UNAUTHORIZED)

        # If user is authenticated, generate JWT token
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        
        return Response({
            "status": True,
            'message': 'Login successful',
            "user": {
                "id": user.id,
                "username": user.username,
                "firstname": user.first_name,
                "lastname": user.last_name,
                "email": user.email,
                "is_active": user.is_active,
                "is_staff": user.is_staff, 
            },
                'access_token': access_token,
                'refresh_token': str(refresh)
        }, status=status.HTTP_200_OK)

class Logout(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Check if the user is authenticated at the beginning
        if not request.user.is_authenticated:
            return Response({
                "status": False,
                "message": "You are already logged out."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if the refresh_token is provided in the request
        refresh_token = request.data.get('refresh_token')

        if not refresh_token:
            return Response({
                "status": False,
                "error": "Refresh token is required."
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create a RefreshToken object using the provided refresh token
            token = RefreshToken(refresh_token)
            # Blacklist the refresh token to invalidate it
            token.blacklist()

        except TokenError as e:
            return Response({
                "status": False,
                "error":f"Token error: {str(e)}"
            }, status=status.HTTP_400_BAD_REQUEST)
        except InvalidToken:
            return Response({
                "status": False,
                "error": "Invalid refresh token."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Log the user out (clear the session in case of session-based auth)
        logout(request)
        
        return Response({
            "status": True,
            "message": "Logged out successfully."
        }, status=status.HTTP_200_OK)

class BackendUpdateUser(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request):

        user_id = request.data.get('user_id')
        username = request.data.get('username')
        firstname = request.data.get('firstname')
        lastname = request.data.get('lastname')
        email = request.data.get('email')

        if not user_id:
            return Response({
                "status": False,
                "error": "user_id is required."
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Fetch the user object by ID
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise NotFound(detail="User not found.")

        backend_user = request.user

        if user.is_superuser and not backend_user.is_superuser:
            return Response({
                "status": False,
                "error": "You can not update superuser."
            }, status=status.HTTP_400_BAD_REQUEST)

        if backend_user.has_perm('app.change_user'):
            if user_id==backend_user.id or not user.is_staff or backend_user.is_superuser:
                if username:
                    if User.objects.filter(username=username).exists():
                        return Response({
                            "status": False,
                            "error": f"Username '{username}' is already exist."
                        }, status=status.HTTP_400_BAD_REQUEST)
                    user.username = username
                if firstname:
                    user.first_name = firstname
                if lastname:
                    user.last_name = lastname
                if email:
                    if User.objects.filter(email=email).exists():
                        return Response({
                            "status": False,
                            "error": f"Email '{email}' is already exist."
                        }, status=status.HTTP_400_BAD_REQUEST)
                    user.email = email
                user.save()
            else:
                return Response({
                    "status": False,
                    "message": "You can't update the admin user"
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({
                "status": False,
                "message": "You don't have permission to update the user"
            }, status=status.HTTP_400_BAD_REQUEST)
        return Response({
            "status": True,
            "message": "User updated successfully"
        }, status=status.HTTP_200_OK)

class GetAllUser(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        
        users = User.objects.all()

        user_data=[]

        for user in users:
            user_data.append({
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'joined_date': user.date_joined,
                'client_id':user.client_id
            })
        return Response({
            "status": True,
            "users": user_data
        }, status=status.HTTP_200_OK)

class GetUser(APIView):
    permission_classes = [IsAdminUser]
    
    def get(self, request):
        user=request.user
        if user:
            user_data = {
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'joined_date': user.date_joined,
                'client_id':user.client_id
            }
        else:
            return Response({
                "status": False,
                "error":"User not found"
            }, status=status.HTTP_400_BAD_REQUEST)    
        # Return the user details in the response
        return Response({
            "status": True,
            "user": user_data
        }, status=status.HTTP_200_OK)

class AssignBackendUserPermission(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request):
        admin_user = request.user

        user_id = request.data.get('user_id')
        permissions = request.data.get('permission',[])

        
        if user_id==admin_user.id:
            return Response({
                "status": False,
                "error": "You can not assign permission to yourself."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not user_id:
            return Response({
                "status": False,
                "error": "User ID is required."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not permissions:
            return Response({
                "status": False,
                "error": "At least one permission is required."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(id=user_id)
            if user.is_superuser:
                return Response({
                    "status": False,
                    "error": "You can not assign permission to superuser."
                }, status=status.HTTP_400_BAD_REQUEST)
        
        except User.DoesNotExist:
            return Response({
                "status": False,
                "error": "User not found."
            }, status=status.HTTP_404_NOT_FOUND)
        
        if not admin_user.has_perm('app.change_user'):
            return Response({
                "status": False,
                "error": "You do not have permission to assign permissions to users."
            }, status=status.HTTP_403_FORBIDDEN)

        permission_objects = []

        for perm_codename in permissions:
            try:
                perm = Permission.objects.get(codename=perm_codename)
                permission_objects.append(perm)
            except Permission.DoesNotExist:
                return Response({
                    "status": False,
                    "error": f"Permission '{perm_codename}' does not exist."
                }, status=status.HTTP_400_BAD_REQUEST)

        user.user_permissions.add(*permission_objects)

        user.save()

        return Response({
            "status": True,
            "message": "Permissions assigned successfully!"
        }, status=status.HTTP_200_OK)

    def delete(self, request):

        admin_user = request.user

        user_id = request.data.get("user_id")
        permissions = request.data.get("permissions", [])

        if not admin_user.has_perm('auth.delete_permission'):
            return Response({
                "status": False,
                "error": "You do not have permission to delete permissions from users."
            }, status=status.HTTP_403_FORBIDDEN)
        
        if user_id==admin_user.id:
            return Response({
                "status": False,
                "error": "You can not delete permission to yourself."
            }, status=status.HTTP_400_BAD_REQUEST)

        if not user_id:
            return Response({
                "status": False,
                "error":"User ID required"
            },status=status.HTTP_400_BAD_REQUEST)
        if not permissions:
            return Response({
                "status": False,
                "error":"Atleast one permission is required"
            },status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({
                "status": False,
                "error": "User not found."
            }, status=status.HTTP_404_NOT_FOUND)
        
        if user.is_superuser:
            return Response({
                "status": False,
                "error": "You can not delete permission from superuser."
            }, status=status.HTTP_400_BAD_REQUEST)

        permission_objects = []
        for perm_codename in permissions:
            try:
                perm = Permission.objects.get(codename=perm_codename)
                permission_objects.append(perm)
            except Permission.DoesNotExist:
                return Response({
                    "status": False,
                    "error": f"Permission '{perm_codename}' does not exist."
                }, status=status.HTTP_400_BAD_REQUEST)

        user.user_permissions.remove(*permission_objects)
        print(permission_objects)
        user.save()

        return Response({
            "status": True,
            "message": "Permissions deleted successfully!",
            "permissions": permissions
            }, status=status.HTTP_200_OK)
        
    def get(self, request):
        admin_user = request.user

        user_id = request.data.get('user_id')
        
        # if user_id==admin_user.id:
        #     return Response({"error": "You can not assign permission to yourself."}, status=status.HTTP_400_BAD_REQUEST)

        if not user_id:
            return Response({
                "status": False,
                "error":"User ID required"
            },status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({
                "status": False,
                "error": "User not found."
            }, status=status.HTTP_404_NOT_FOUND)
        
        if not admin_user.has_perm('app.view_user'):
            return Response({
                "status": False,
                "error": "You do not have permission to view user's permissions."
            }, status=status.HTTP_403_FORBIDDEN)
        
        permission_list=user.user_permissions.all()

        permission_data = [{"id": perm.id, "name": perm.codename} for perm in permission_list]
        print(permission_data)

        return Response({
            "status": True,
            "message": f"Permissions of {user.username}'s",
            "user": {
                "username": user.username,
                "permissions": permission_data
            }
        }, status=status.HTTP_200_OK)

class DeleteBackendUser(APIView):
    permission_classes = [IsAdminUser]

    def delete(self, request):

        admin_user = request.user

        user_id = request.data.get('user_id')

        if not user_id:
            return Response({
                "status": False,
                "error":"User id required"
            },status=status.HTTP_400_BAD_REQUEST)

        if not admin_user.has_perm('app.delete_user'):
            return Response({
                "status": False,
                "error":"You do not have permission to delete user."
            },status=status.HTTP_400_BAD_REQUEST)
        
        if user_id==admin_user.id:
            return Response({
                "status": False,
                "error": "You can not delete yourself."
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            delete_user = User.objects.get(id=user_id)

            if delete_user.is_superuser:
                return Response({
                "status": False,
                "error": "You can not delete superuser."
            }, status=status.HTTP_400_BAD_REQUEST)

            delete_user.delete()
            return Response({
                "status": True,
                "message": "User deleted successfully.",
                "user": delete_user.username
                }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({
                "status": False,
                "error": "User not found."
            }, status=status.HTTP_404_NOT_FOUND)

class DeactivateUser(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request):

        admin_user = request.user

        user_id = request.data.get('user_id')

        if not user_id:
            return Response({
                    "status": False,
                    "error":"User id required"
                },status=status.HTTP_400_BAD_REQUEST)

        if not admin_user.has_perm('app.delete_user'):
            return Response({
                    "status": False,
                    "error":"You do not have permission to deactivate user."
                },status=status.HTTP_400_BAD_REQUEST)
            
        try:
            deactivate_user = User.objects.get(id=user_id)

            if deactivate_user.is_active is False:
                return Response({
                    "status": False,
                    "error": "User is already deactivated."
                }, status=status.HTTP_400_BAD_REQUEST)

            if deactivate_user.is_superuser:
                return Response({
                    "status": False,
                    "error": "You can not deactivate superuser."
                }, status=status.HTTP_400_BAD_REQUEST)

            deactivate_user.is_active=False

            deactivate_user.save()

            return Response({
                "status": True,
                "message": "User deactivated successfully.",
                "user": deactivate_user.username
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({
                    "status": False,
                    "error": "User not found."
                }, status=status.HTTP_404_NOT_FOUND)

class CreatePermission(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request):
        admin_user = request.user
        permission_name = request.data.get('permission_name')
        permission_codename = request.data.get('permission_codename')

        if not permission_name:
            return Response({
                "status": False,
                "error": "Permission name is required."
            }, status=status.HTTP_400_BAD_REQUEST)
        if not permission_codename:
            return Response({
                "status": False,
                "error": "Permission codename is required."
            }, status=status.HTTP_400_BAD_REQUEST)

        if not admin_user.has_perm('auth.create_permission'):
            return Response({
                "status": False,
                "error": "You do not have permission to create permission."
            }, status=status.HTTP_403_FORBIDDEN)

        try:
            permission = Permission.objects.create(name=permission_name, codename=permission_codename)
            return Response({
                "status": True,
                "message": "Permission created successfully.",
                "permission": {
                    "id": permission.id,
                    "name": permission.name,
                    "codename": permission.codename
                }
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({
                "status": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class BackendPorfile(APIView):
    permission_classes = [IsAdminUser]
    def get(self, request):
        current_user = request.user
        user_data = {
            'username': current_user.username,
            'first_name': current_user.first_name,
            'last_name': current_user.last_name,
            'email': current_user.email,
            'joined_date': current_user.date_joined,
            'client_id':current_user.client_id,
        }
        return Response({
            "status": True,
            "user": user_data
        }, status=status.HTTP_200_OK)

class CreateBackendUserPassword(APIView):
    permission_classes = [IsAdminUser]

    def post(self,request):
        current_user = request.user
        password = request.data.get('password')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')

        if not password:
            return Response({
                "status": False,
                "error": "Current password is required."
            }, status=status.HTTP_400_BAD_REQUEST)
        if not new_password:
            return Response({
                "status": False,
                "error": "New password is required."
            }, status=status.HTTP_400_BAD_REQUEST)
        if not confirm_password:
            return Response({
                "status": False,
                "error": "Confirmed password is required."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        user = User.objects.get(username=current_user.username)

        if not user.check_password(password):
            return Response({
                "status": False,
                "error": "Current password is incorrect."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if new_password != confirm_password:
            return Response({
                "status": False,
                "error": "New password and confirm password does not match."
            }, status=status.HTTP_400_BAD_REQUEST)

        current_user.set_password(new_password)
        current_user.save()

        return Response({
                "status": True,
                "message": "Password updated successfully."
            }, status=status.HTTP_200_OK)
 
class BackendUpdatePorfile(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request):
        current_user = request.user

        username = request.data.get('username')
        firstname = request.data.get('firstname')
        lastname = request.data.get('lastname')
        email = request.data.get('email')

        try:
            # Fetch the user object by ID
            user = User.objects.get(username=current_user.username)
        except User.DoesNotExist:
            raise NotFound(detail="User not found.")

        if email:
            emailvalide=Validation.validate_email(email)

            if emailvalide is False:
                return Response({
                    "status": False,
                    "error": "Invalid email format"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check if the email is already taken by another user
            if User.objects.filter(email=email).exclude(id=user.id).exists():
                raise ValidationError("Email is already in use.")

        # Check if the new username is unique (if provided)
        if username:
            if User.objects.filter(username=username).exclude(id=user.id).exists():
                return Response({
                    "status": False,
                    "error": "Username is already taken."
                }, status=status.HTTP_400_BAD_REQUEST)
            user.username = username

        if firstname:
            user.first_name = firstname
        if lastname:
            user.last_name = lastname
        if email:
            user.email = email

        user.save()

        return Response({
            "status": True,
            "message": "Profile updated successfully"
        }, status=status.HTTP_200_OK)

# frontend APIs

class FrontEndRegister(APIView):
    def post(self, request):

        username= request.data.get('username')
        firstname= request.data.get('firstname')
        lastname= request.data.get('lastname')
        email= request.data.get('email')
        password= request.data.get('password')

        if not username:
            return Response({
                "status": False,
                "error": "Username is required."
            }, status=status.HTTP_400_BAD_REQUEST)
        if not firstname:
            return Response({
                "status": False,
                "error": "First name is required."
            }, status=status.HTTP_400_BAD_REQUEST)
        if not lastname:
            return Response({
                "status": False,
                "error": "Last name is required."
            }, status=status.HTTP_400_BAD_REQUEST)
        if not email:
            return Response({
                "status": False,
                "error": "Email is required."
            }, status=status.HTTP_400_BAD_REQUEST)
        if not password:
            return Response({
                "status": False,
                "error": "Password is required."
            }, status=status.HTTP_400_BAD_REQUEST)

        username_pattern = Validation.validate_username(username)
        if not username_pattern:
            return Response({
                "status": False,
                "error": "Username can only contain letters, numbers, underscores (_), hyphens (-), and periods (.)"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        
        email_pattern = Validation.validate_email(email)
        if not email_pattern:
            return Response({
                "status": False,
                "error": "Invalid email format. Please provide a valid email address."
            }, status=status.HTTP_400_BAD_REQUEST)

        password = Validation.validate_strong_password(password)

        if User.objects.filter(username=username).exists():
            return Response({
                "status": False,
                "error": f"Username '{username}' is already exist."
            }, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({
                "status": False,
                "error": f"Email '{email}' is already exist."
            }, status=status.HTTP_400_BAD_REQUEST)
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
                "status": True,
                "message": "Registration successful !",
                "user": {
                    "is_active": user.is_active,
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "verify_email": user.email_verified,
                    "created_at": user.date_joined,
                }
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({
                "status": False,
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class FrontendUserLogin(APIView):
    def post(self, request):
        
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response({
                "status": False,
                'message': 'Username and password are required'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Authenticate user
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({
                "status": False,
                "error": "User not found."
            }, status=status.HTTP_404_NOT_FOUND)
        
        if user.is_active is False:
            return Response({
                "status": False,
                "error": "User is deactivated"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not user.check_password(password):
            return Response({
                "status": False,     
                'message': 'Wrong password'
            }, status=status.HTTP_401_UNAUTHORIZED)

        # If user is authenticated, generate JWT token
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        
        return Response({
            "status": True,
            'message': 'Login successful',
            "user": {
                "id": user.id,
                "username": user.username,
                "firstname": user.first_name,
                "lastname": user.last_name,
                "email": user.email,
                "is_active": user.is_active,
                "is_staff": user.is_staff,
            },
                'access_token': access_token,
                'refresh_token': str(refresh)
                
            }, status=status.HTTP_200_OK)

class FrontendUserLogout(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Check if the user is authenticated at the beginning
        if not request.user.is_authenticated:
            return Response({
                "status": False,
                "message": "You are already logged out."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if the refresh_token is provided in the request
        refresh_token = request.data.get('refresh_token')

        if not refresh_token:
            return Response({
                "status": False,
                "error": "Refresh token is required."
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create a RefreshToken object using the provided refresh token
            token = RefreshToken(refresh_token)
            # Blacklist the refresh token to invalidate it
            token.blacklist()
            
        except TokenError as e:
            return Response({
                "status": False,
                "error":f"Token error: {str(e)}"
            }, status=status.HTTP_400_BAD_REQUEST)
        except InvalidToken:
            return Response({
                "status": False,
                "error": "Invalid refresh token."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Log the user out (clear the session in case of session-based auth)
        logout(request)
        
        return Response({
            "status": True,
            "message": "Logged out successfully."
        }, status=status.HTTP_200_OK)

class FrontendPorfile(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        current_user = request.user
        user_data = {
            'username': current_user.username,
            'first_name': current_user.first_name,
            'last_name': current_user.last_name,
            'email': current_user.email,
            'joined_date': current_user.date_joined,
            'client_id':current_user.client_id,
        }
        return Response({
            "status": False,
            "user": user_data
        }, status=status.HTTP_200_OK)

class FrontendUpdatePorfile(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        current_user = request.user

        username = request.data.get('username')
        firstname = request.data.get('firstname')
        lastname = request.data.get('lastname')
        email = request.data.get('email')

        try:
            # Fetch the user object by ID
            user = User.objects.get(username=current_user.username)
        except User.DoesNotExist:
            raise NotFound(detail="User not found.")

        if email:
            emailvalide=Validation.validate_email(email)

            if emailvalide is False:
                return Response({
                    "status": False,
                    "error": "Invalid email format"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check if the email is already taken by another user
            if User.objects.filter(email=email).exclude(id=user.id).exists():
                raise ValidationError("Email is already in use.")

        # Check if the new username is unique (if provided)
        if username:
            if User.objects.filter(username=username).exclude(id=user.id).exists():
                return Response({
                    "status": False,
                    "error": "Username is already taken."
                }, status=status.HTTP_400_BAD_REQUEST)
            user.username = username

        if firstname:
            user.first_name = firstname
        if lastname:
            user.last_name = lastname
        if email:
            user.email = email

        user.save()

        return Response({
            "status": True,
            "message": "Profile updated successfully"
        }, status=status.HTTP_200_OK)

class CreateFrontendUserPassword(APIView):
    permission_classes = [IsAuthenticated]

    def post(self,request):
        current_user = request.user
        password = request.data.get('password')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')

        if not password:
            return Response({
                "status": False,
                "error": "Current password is required."
            }, status=status.HTTP_400_BAD_REQUEST)
        if not new_password:
            return Response({
                "status": False,
                "error": "New password is required."
            }, status=status.HTTP_400_BAD_REQUEST)
        if not confirm_password:
            return Response({
                "status": False,
                "error": "Confirmed password is required."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        user = User.objects.get(username=current_user.username)

        if not user.check_password(password):
            return Response({
                "status": False,
                "error": "Current password is incorrect."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if new_password != confirm_password:
            return Response({
                "status": False,
                "error": "New password and confirm password does not match."
            }, status=status.HTTP_400_BAD_REQUEST)

        current_user.set_password(new_password)
        current_user.save()

        return Response({
            "status": True,
            "message": "Password updated successfully."
        }, status=status.HTTP_200_OK)
    



