from django.urls import path
from .views import FrontEndRegister,BackEndRegister,Login,Logout,BackendUpdateUser,ReadJSONData, GetAllBackendUser, GetBackendUser, AssignBackendUserPermission, DeleteBackendUser, DeactivateUser, FrontendUserLogin, FrontendUserLogout
# from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    # Backenduser APIs
    path('backend-user/register/', BackEndRegister.as_view(), name='backend-register'),
    path('backend-user/login/', Login.as_view(), name='login'),
    path('backend-user/logout/',Logout.as_view(),name='logout'),
    path('backend-user/update-user/', BackendUpdateUser.as_view(), name='backenduser-update-user'),
    path('backend-user/get-all/', GetAllBackendUser.as_view(), name='backenduser-get-all'),
    path('backend-user/get/', GetBackendUser.as_view(), name='backenduser-get'),
    path('assign-permission/', AssignBackendUserPermission.as_view(), name='assign-permission'),
    path('delete-user/', DeleteBackendUser.as_view(), name='delete-user'),
    path('deactivate-user/', DeactivateUser.as_view(), name='deactivate-user'),
    path('read-json/', ReadJSONData.as_view(), name='read-json'),
    # Frontenduser APIs
    path('frontend-user/register/', FrontEndRegister.as_view(), name='frontend-register'),
    path('frontend-user/login/', FrontendUserLogin.as_view(), name='login'),
    path('frontend-user/logout/',FrontendUserLogout.as_view(),name='logout'),
    
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
