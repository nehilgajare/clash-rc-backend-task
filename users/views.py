from django.db.models.query_utils import Q
from django.http import request
from django.http.response import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.contrib.auth.models import User
from django.contrib import auth
from .models import login_user
from django.contrib import messages
import re
# Create your views here.
def signup(request):
    if request.method == "POST":
        
        if request.POST['password'] == request.POST['cpassword']:
            try:
                user = User.objects.get(username=request.POST['username'])
                return render(request,'users/signup.html',{'error':"Username Has already been taken"})
            except User.DoesNotExist:
                user = User.objects.create_user(username=request.POST['username'],password=request.POST['password'],email=request.POST['email'])
                phone_number=request.POST['phone']
                first_name=request.POST['fname']
                last_name=request.POST['lname']
                email=request.POST['email']
            if (len(request.POST['password'])<8):
                return render(request,'users/signup.html',{'error':"Password too Short, Should Contain ATLEAST 1 Uppercase,1 lowercase,1 special Character and 1 Numeric Value"})

            elif not re.search(r"[\d]+",request.POST['password']):
                return render(request,'users/signup.html',{'error':"Your Password must contain Atleast 1 Numeric "})
            elif not re.findall('[A-Z]', request.POST['password']):   
                return render(request,'users/signup.html',{'error':"Your Password must contain Atleast 1 UpperCase Letter "})

            elif not re.findall('[a-z]',request.POST['password']):
                return render(request,'users/signup.html',{'error':"Your Password must contain Atleast 1 lowercase Letter "})
            elif not re.findall('[()[\]{}|\\`~!@#$%^&*_\-+=;:\'",<>./?]', request.POST['password']):   
                return render(request,'users/signup.html',{'error':"Your Password must contain Atleast 1 Special character "})
            else:
                if login_user.objects.filter(email=email).exists():
                    return render(request,'users/signup.html',{'error':"This Email Already Exists"})
                elif login_user.objects.filter(phone_number=phone_number).exists():
                    return render(request,'users/signup.html',{'error':"This Phone number Already Exists"})
                else:
                    newlogin_user= login_user(phone_number=phone_number,user=user,first_name=first_name,last_name=last_name,email=email)
                    newlogin_user.save()
                    auth.login(request,user)
                    return HttpResponse('<h1>You have been successfully signed in!<h1>')
        else:
            return render(request,'users/signup.html',{'error':"You Entered Wrong Password"})
            
        
    else:
        return render(request,'users/signup.html')

def login(request):
    if request.method == "POST":
        user = auth.authenticate(username=request.POST['username'],password=request.POST['password'])
        if user is not None:
            auth.login(request,user)
            matching=login_user.objects.filter(user=request.user)
            return render(request,'users/homepage.html',{'match':matching})
        else:
            return render(request,'users/login.html')
    else:
        return render(request,'users/login.html')

def homepage(request):
    if request.method=="POST":

        inputstr = str(request.POST.get('Input'))
        func = str(request.POST.get('Filter'))
        context=dict()
        lst=[]

        if not inputstr:
            messages.error(request, f'Enter valid input string according to the option choosed above')

        else:
            if func=="number":
                regex_pattern = re.compile(r'[1-9][0-9][0-9]+')
                match = regex_pattern.finditer(inputstr)
                for m in match:
                    lst.append(m.group(0))
                return render(request, 'users/homepage.html', {'result': lst})

            if func=="date":
                regex_pattern = re.compile(r'([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])')
                match = regex_pattern.finditer(inputstr)
                for m in match:
                    lst.append(m.group(0))
                return render(request, 'users/homepage.html', {'result': lst})

            if func=="string":
                regex_pattern = re.compile(r".*'([^']*)'.*")
                match = regex_pattern.finditer(inputstr)
                for m in match:
                    lst.append(m.group(1))
                return render(request, 'users/homepage.html', {'result': lst})

            
            if func=="ipaddress":
                # rega_1 = re.compile(r'\.[0-255]\.[0-255]\.[0-255]')
                rega_1 = re.compile(r"(([0-9]|[1-9][0-9]|1[0-9][0-9]|"\
                "2[0-4][0-9]|25[0-5])\\.){3}"\
                "([0-9]|[1-9][0-9]|1[0-9][0-9]|"\
                "2[0-4][0-9]|25[0-5])")
                
                if(re.search(rega_1,inputstr)):
                    lst=''
                
                    reg=re.compile(rega_1)
                    matches=reg.finditer(inputstr)
                    for i in matches:
                        if(int(i.group(2))>=0 and int(i.group(2))<=127):
                            lst+="This is valid IP address \n Class A"
                        elif(int(i.group(2))>=128 and int(i.group(2))<=191):
                            lst+="This is valid IP address \n Class B"
                        elif(int(i.group(2))>=192 and int(i.group(2))<=223):
                            lst+="This is valid IP address \n Class C"
                        elif(int(i.group(2))>=224 and int(i.group(2))<=239):
                            lst+="This is valid IP address \n Class D"
                        elif(int(i.group(2))>=240 and int(i.group(2))<=255):
                            lst+="This is valid IP address \n Class E"
                        
                    return render(request, 'users/homepage.html', {'result': lst})    

            if func=="macaddress":
                regex_pattern = ("^([0-9A-Fa-f]{2}[:-])" + "{5}([0-9A-Fa-f]{2})|" + "([0-9a-fA-F]{4}\\." + "[0-9a-fA-F]{4}\\." + "[0-9a-fA-F]{4})$")

                if(re.fullmatch(regex_pattern, inputstr)):
                    lst = " This is valid MAC address"
                    

                else:
                    lst = "This is invalid MAC address"
                    
                return render(request, 'users/homepage.html', {'result': lst})


            if func=="camelcasetosnake":
                regex_pattern = re.sub(r'(.)([A-Z][a-z]+)', r'\1_\2', inputstr)
                lst = re.sub('([a-z0-9])([A-Z])', r'\1_\2', regex_pattern).lower()
                return render(request, 'users/homepage.html', {'result': lst})

            if func=="email_valid":
                regex_pattern = re.compile(r"^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$")
                if(re.fullmatch(regex_pattern, inputstr)):
                    lst = " This is valid Email address"

                else:
                    lst = "This is invalid Email address"
                return render(request,'users/homepage.html',{'result': lst})
    return render(request, 'users/homepage.html')