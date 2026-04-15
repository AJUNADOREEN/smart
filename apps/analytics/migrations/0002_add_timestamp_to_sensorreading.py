from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('analytics', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='sensorreading',
            name='timestamp',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterModelOptions(
            name='sensorreading',
            options={'ordering': ['timestamp', 'date']},
        ),
    ]
