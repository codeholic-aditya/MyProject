from django.urls import path
from .views import FrontEndRegister,BackEndRegister,Login,Logout,BackendUpdateUser, GetAllUser, GetUser,AssignBackendUserPermission, DeleteBackendUser, DeactivateUser, BackendPorfile, BackendUpdatePorfile, CreateBackendUserPassword, FrontendUserLogin, FrontendUserLogout, FrontendUpdatePorfile, FrontendPorfile, CreateFrontendUserPassword
# from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    # Backenduser APIs
    path('backend-user/register/', BackEndRegister.as_view(), name='backend-register'),
    path('backend-user/login/', Login.as_view(), name='login'),
    path('backend-user/logout/',Logout.as_view(),name='logout'),
    path('backend-user/update-user/', BackendUpdateUser.as_view(), name='backenduser-update-user'),
    path('backend-user/get-all/', GetAllUser.as_view(), name='backenduser-get-all'),
    path('backend-user/get/', GetUser.as_view(), name='backenduser-get'),
    path('backend-user/assign-permission/', AssignBackendUserPermission.as_view(), name='assign-permission'),   # method post
    path('backend-user/get-permission/', AssignBackendUserPermission.as_view(), name='change-permission'),   # method get
    path('backend-user/delete-permission/', AssignBackendUserPermission.as_view(), name='delete-permission'),   # method delete
    path('delete-user/', DeleteBackendUser.as_view(), name='delete-user'),
    path('deactivate-user/', DeactivateUser.as_view(), name='deactivate-user'),
    path('backend-user/profile/', BackendPorfile.as_view(), name='backenduser-profile'),
    path('backend-user/profile-update/',BackendUpdatePorfile.as_view(),name='backenduser-profile-update'),
    path('backend-user/create-password/',CreateBackendUserPassword.as_view(),name='backenduser-create-password'),
    
    # Frontenduser APIs
    path('frontend-user/register/', FrontEndRegister.as_view(), name='frontend-register'),
    path('frontend-user/login/', FrontendUserLogin.as_view(), name='login'),
    path('frontend-user/logout/',FrontendUserLogout.as_view(),name='logout'),
    path('frontend-user/profile/', FrontendPorfile.as_view(), name='frontenduser-profile'),
    path('frontend-user/profile-update/',FrontendUpdatePorfile.as_view(),name='frontenduser-profile-update'),
    path('frontend-user/create-password/',CreateFrontendUserPassword.as_view(),name='frontenduser-create-password'),
    
]


# backend-user/register/
# backend-user/login/
# backend-user/logout
# backend-user/update-user/
# backend-user/get-all/
# backend-user/get/
# assign-permission/
# delete-user/
# deactivate-user/
