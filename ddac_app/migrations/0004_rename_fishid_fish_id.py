# Generated by Django 3.2.8 on 2021-11-03 07:24

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ddac_app', '0003_fish'),
    ]

    operations = [
        migrations.RenameField(
            model_name='fish',
            old_name='fishid',
            new_name='id',
        ),
    ]
