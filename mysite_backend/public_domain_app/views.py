import json
from functools import wraps
import traceback
import logging

from django.http import JsonResponse
from django.shortcuts import render
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from rest_framework.decorators import api_view
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authtoken.models import Token


logger = logging.getLogger(__name__)


def handle_uncaught_exceptions(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.info(e)
            return JsonResponse({'error': f"There was an unexpected error - {e}"}, status=500)
    return wrapper


@handle_uncaught_exceptions
@csrf_exempt
def signup(request):
    """API endpoint for user signup."""
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')    
        if username is None or password is None:
            return JsonResponse({'error': 'Please provide both username and password'}, status=400)
        if User.objects.filter(username=username).exists():
            return JsonResponse({'error': 'Username already exists'}, status=400)
        user = User.objects.create_user(username=username, password=password, is_active=False)
        print(f"{user.is_active=}")
        login(request, user)
        return JsonResponse({'message': 'User has signed up successfully'})
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    