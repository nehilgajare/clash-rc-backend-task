from django.db import models
from django.db.models.deletion import CASCADE
from django.contrib.auth.models import User
# Create your models here.
class login_user(models.Model):
    first_name=models.CharField(max_length=64)
    last_name=models.CharField(max_length=64)
    email=models.EmailField()
    phone_number=models.CharField(max_length=10)
    user=models.OneToOneField(User,on_delete=models.CASCADE)
