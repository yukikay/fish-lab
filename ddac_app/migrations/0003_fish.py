# Generated by Django 3.2.8 on 2021-11-03 02:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ddac_app', '0002_auto_20211017_2059'),
    ]

    operations = [
        migrations.CreateModel(
            name='Fish',
            fields=[
                ('fishid', models.AutoField(primary_key=True, serialize=False)),
                ('fishname', models.CharField(max_length=255)),
                ('price', models.IntegerField()),
            ],
            options={
                'db_table': 'auth_fish',
            },
        ),
    ]
