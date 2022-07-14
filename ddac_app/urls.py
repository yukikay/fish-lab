from collections import namedtuple

from django.conf import settings
from django.conf.urls.static import static
from django.urls import path


from . import views

app_name="ddac_app"
urlpatterns = [
    path('', views.api_index, name="index"),
    path('test-lists/', views.test_lists, name="test-lists"),
    path('test-create/', views.test_create, name="test-create"),
    path('test-detail/<int:pk>', views.test_detail, name="test-detail"),
    path('test-delete/<int:pk>', views.test_delete, name="test-delete"),
    path('test-edit/<int:pk>', views.test_edit, name="test-edit"),

    path('users/', views.user_lists, name="user-lists"),
    path('user-group/', views.user_group, name="user-group"),
    path('user/delete/<int:pk>', views.user_delete, name="user-delete"),
    path('user/<int:pk>', views.user_detail, name="user-detail"),
    path('user/<int:pk>/edit', views.user_edit, name="user-edit"),
    path('staff/create/', views.staff_create, name="staff-create"),

    path('fishes/', views.fish_lists, name="fish-lists"),
    path('fish/<int:pk>', views.fish_detail, name="fish-detail"),
    path('fish/<int:pk>/edit', views.fish_edit, name="fish-edit"),
    path('fish/create/', views.fish_create, name="fish-create"),
    path('fish/delete/<int:pk>', views.fish_delete, name="fish-delete"),
    path('fishes/upload/', views.fish_imageupload, name = 'fish_imageupload'),
    path('fishes/', views.success, name = 'success'),

    path('groups/', views.group_lists, name="group-lists"),
    path('group/create/', views.group_create, name="group-create"),
    path('group/delete/<int:pk>', views.group_delete, name="group-delete"),
    path('group/<int:pk>', views.group_detail, name="group-detail"),
    path('group/<int:pk>/edit', views.group_edit, name="group-edit"),

    path('permissions/', views.permission_lists, name="permission-lists"),
    path('permission/create/', views.permission_create, name="permission-create"),
    path('permission/delete/<int:pk>/', views.permission_delete, name="permission-delete"),
    path('permission/<int:pk>/', views.permission_detail, name="permission-detail"),
    path('permission/<int:pk>/edit/', views.permission_edit, name="permission-edit"),

    path('register/', views.register_account, name="register-account"),
    path('logout/', views.logout, name="logout"),
    path('login/', views.login, name="login"),

    path('profile/', views.profile, name="profile"),
    path('profile/edit/', views.profile_edit, name="profile-edit")

]
if settings.DEBUG:
        urlpatterns += static(settings.MEDIA_URL,
                              document_root=settings.MEDIA_ROOT)