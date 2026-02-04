from django.http import JsonResponse
from .models import Task

def task_list_api(request):
    # 1. Fetch all task objects from the DB
    # .values() converts the database objects into a Python Dictionary (like a JS Object)
    tasks = Task.objects.all().values('id', 'title', 'description', 'is_completed', 'created_at')
    
    # 2. Convert that 'QuerySet' into a standard Python List
    data = list(tasks)
    
    # 3. Return it as JSON
    return JsonResponse(data, safe=False)