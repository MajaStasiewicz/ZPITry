from django.db import models

# Create your models here.

class ZapisNewsletter(models.Model):
    email = models.CharField(max_length=200)

    def __str__(self):
        return self.email
    
class ZapisVerification(models.Model):
    email = models.CharField(max_length=200)

    def __str__(self):
        return self.email
    
    