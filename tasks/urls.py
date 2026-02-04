from rest_framework.routers import DefaultRouter
from .views import TaskViewSet

router = DefaultRouter()

router.register(r"tasks", TaskViewSet, basename="task")

urlpatterns = router.urls

# from django.urls import path
# from .views import task_list_api

# urlpatterns = [
#     # This means: if someone hits /tasks/, run the task_list_api function
#     path('tasks/', task_list_api, name='task-list'),
