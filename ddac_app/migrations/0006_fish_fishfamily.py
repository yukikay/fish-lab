# Generated by Django 3.2.8 on 2021-11-03 14:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ddac_app', '0005_fish_image'),
    ]

    operations = [
        migrations.AddField(
            model_name='fish',
            name='fishfamily',
            field=models.CharField(default='', max_length=255),
        ),
    ]