from django.db import models

# Create your models here.


class TestModel(models.Model):
    test_string = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Fish(models.Model):
    id = models.AutoField(primary_key=True)
    fishname = models.CharField(max_length=255)
    fishfamily = models.CharField(max_length=255,default='')
    price = models.DecimalField(max_digits=5,decimal_places=2)
    image = models.ImageField(upload_to='images',default='')
    class Meta:
        db_table = 'auth_fish'  # 对应数据表
