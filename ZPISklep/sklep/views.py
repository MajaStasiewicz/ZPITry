
from django.shortcuts import redirect, render
from django.core.mail import send_mail
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib import messages
from sklep.forms import RegisterUserForm
from django.contrib.auth.forms import UserCreationForm, PasswordChangeForm
from django.contrib.auth.models import User
from django.contrib.auth.views import PasswordChangeView
from django.urls import reverse_lazy
from .tokens import account_activation_token
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import EmailMessage

from sklep.models import *

class PasswordsChangeView(PasswordChangeView):
    form_class = PasswordChangeForm
    success_url = reverse_lazy('password_success')

def password_success(request):
    return render(request, 'zmianaSuccess.html', {})

def index(request):
    return render(request, 'home.html')

def oNas(request):
    return render(request, 'oNas.html')

def kontakt(request):
    return render(request, 'kontakt.html')

def produkt(request):
    return render(request, 'produkt.html')

def regulamin(request):
    return render(request, 'regulamin.html')

def platnosc(request):
    return render(request, 'platnosc.html')

def zwroty(request):
    return render(request, 'zwroty.html')

def newsletter(request):
    if request.method == 'POST':
        emailCheck = request.POST.get('email')
        if ZapisNewsletter.objects.filter(email=emailCheck).exists():
            return redirect('/zapisbrak/')
        else:
            dane=ZapisNewsletter(email = emailCheck)
            dane.save() 
            subject = 'Potwierdzenie subskrypcji'
            message = 'Dziękujemy za zapisanie się do naszego newslettera.'
            from_email = 'your@email.com'
            recipient_list = [emailCheck]

            send_mail(subject, message, from_email, recipient_list, fail_silently=False)
        emailCheck = None
    return render(request, 'newsletter.html')

def zapisbrak(request):
    return render(request, 'zapisbrak.html')

def logowanie(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('/home/')
        else:
            messages.success(request, ("There Was An Error!"))
            return redirect('/logowanie/')

    return render(request, 'logowanie.html')

def wylogowanie(request):
    logout(request)
    messages.success(request, ("You were logged out!"))
    return redirect('/logowanie/')

def rejestracja(request):
    if request.method == 'POST':
        form = RegisterUserForm(request.POST)
        emailCheck = request.POST.get('email')
        nameCheck = request.POST.get('username')
        if User.objects.filter(email=emailCheck).exists():
            messages.success(request, ("Email istnieje!"))
            return redirect('/rejestracja/')
        elif User.objects.filter(username=nameCheck).exists(): 
            messages.success(request, ("Username istnieje!"))
            return redirect('/rejestracja/')
        else:
            if form.is_valid():
                user = form.save(commit=False)
                user.is_active = False
                user.save()
                #username = form.cleaned_data['username']
                #password = form.cleaned_data['password1']
                #user = authenticate(username=username, password=password)
                activateEmail(request, user, form.cleaned_data.get('email'))
                return redirect('/logowanie/')
    else:
        form = RegisterUserForm()
    return render(request, 'rejestracja.html', {
       'form':form,
    })

def activateEmail(request, user, to_email):
    subject = 'Potwierdzenie subskrypcji'
    message = render_to_string("activate_account.html", {
        'user': user.username,
        'domain': get_current_site(request).domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': account_activation_token.make_token(user),
        "protocol": 'https' if request.is_secure() else 'http'
        })

    from_email = 'your@email.com'
    recipient_list = [to_email]
    send_mail(subject, message, from_email, recipient_list, fail_silently=False)
   
    messages.success(request, "Sprawdz maila i potwierdz, aby sie zalogowac!")

def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except:
        user = None
    
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()

        messages.success(request, "Thank you for email confirmation!")
        return redirect('/logowanie/')
    else:
        messages.error(request, "Activation link is invalid!")

    return redirect('/home/')

def zmianaHasla(request):
    return render(request, 'zmiana.html')

def konto(request):
    return render(request, 'konto.html')
